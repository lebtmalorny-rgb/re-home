from dataclasses import asdict, dataclass, field
from pathlib import Path
import re
from typing import Any, Dict, Mapping, Optional, Sequence, Set, Tuple


CLASSIFICATIONS = {
    "COMMON_COMPATIBLE",
    "NORMALIZATION_REQUIRED",
    "SOURCE_ONLY_IGNORED",
    "TARGET_DEFAULT",
    "TARGET_VALUE_REQUIRED",
    "SEMANTIC_MISMATCH",
    "BLOCKED",
}

_BUILTIN_NORMALIZATION_NAMES = {
    "cell_id",
    "compute_id",
    "service_uuid",
    "volume_type_id",
}
_INTEGER_WITH_DISPLAY_WIDTH = re.compile(
    r"\b(tinyint|smallint|mediumint|int|integer|bigint)\(\d+\)",
    flags=re.IGNORECASE,
)
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_INDEX_TYPE = re.compile(r"^[A-Z][A-Z0-9_ ]{0,31}$")
_FK_ACTIONS = {"CASCADE", "NO ACTION", "RESTRICT", "SET DEFAULT", "SET NULL"}


@dataclass(frozen=True)
class SchemaColumn:
    name: str
    ordinal: int
    column_type: str
    nullable: bool
    default: Optional[str]
    extra: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SchemaIndex:
    name: str
    unique: bool
    columns: Tuple[str, ...]
    index_type: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "unique": self.unique,
            "columns": list(self.columns),
            "index_type": self.index_type,
        }


@dataclass(frozen=True)
class SchemaForeignKey:
    name: str
    columns: Tuple[str, ...]
    referenced_table: str
    referenced_columns: Tuple[str, ...]
    update_rule: str
    delete_rule: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "columns": list(self.columns),
            "referenced_table": self.referenced_table,
            "referenced_columns": list(self.referenced_columns),
            "update_rule": self.update_rule,
            "delete_rule": self.delete_rule,
        }


@dataclass(frozen=True)
class SchemaSnapshot:
    tables: Dict[str, Dict[str, SchemaColumn]]
    indexes: Dict[str, Dict[str, SchemaIndex]] = field(default_factory=dict)
    foreign_keys: Dict[str, Dict[str, SchemaForeignKey]] = field(default_factory=dict)
    metadata_complete: bool = False


def _identifier(value: str, label: str) -> str:
    if _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"invalid {label}")
    return value


def _positive_ordinal(value: str, line_number: int, label: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise ValueError(f"invalid {label} at line {line_number}: {value!r}") from error
    if parsed < 1 or parsed > 100_000:
        raise ValueError(f"invalid {label} at line {line_number}: {value!r}")
    return parsed


def parse_information_schema(path: Path) -> SchemaSnapshot:
    tables: Dict[str, Dict[str, SchemaColumn]] = {}
    index_rows: Dict[Tuple[str, str], list] = {}
    foreign_key_rows: Dict[Tuple[str, str], list] = {}
    section = None
    sections = set()
    for line_number, raw_line in enumerate(
        Path(path).read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not raw_line:
            continue
        if raw_line.startswith("SERVICE:"):
            service = raw_line.removeprefix("SERVICE:")
            if not service or len(service) > 64 or re.fullmatch(r"[a-z][a-z0-9_-]*", service) is None:
                raise ValueError(f"invalid information_schema service at line {line_number}")
            section = None
            continue
        if raw_line.startswith("SECTION:"):
            section = raw_line.removeprefix("SECTION:")
            if section not in {"COLUMNS", "STATISTICS", "FOREIGN_KEYS"}:
                raise ValueError(f"unknown information_schema section at line {line_number}")
            sections.add(section)
            continue
        if section is None:
            continue

        parts = raw_line.split("\t")
        if section == "COLUMNS":
            if len(parts) != 8:
                raise ValueError(f"malformed information_schema row at line {line_number}")
            schema, table, ordinal, name, column_type, nullable, default, extra = parts
            _identifier(schema, "schema identifier")
            _identifier(table, "table identifier")
            _identifier(name, "column identifier")
            ordinal_value = _positive_ordinal(ordinal, line_number, "column ordinal")
            if nullable not in {"YES", "NO"}:
                raise ValueError(
                    f"invalid nullable value at line {line_number}: {nullable!r}"
                )
            if not column_type or any(character in column_type for character in "\x00\r\n"):
                raise ValueError(f"invalid column type at line {line_number}")
            full_table = f"{schema}.{table}"
            columns = tables.setdefault(full_table, {})
            if name in columns or any(item.ordinal == ordinal_value for item in columns.values()):
                raise ValueError(f"duplicate column {full_table}.{name}")
            columns[name] = SchemaColumn(
                name=name,
                ordinal=ordinal_value,
                column_type=column_type,
                nullable=nullable == "YES",
                default=None if default in {"NULL", r"\N"} else default,
                extra="" if extra == r"\N" else extra,
            )
        elif section == "STATISTICS":
            if len(parts) != 7:
                raise ValueError(f"malformed index row at line {line_number}")
            schema, table, name, non_unique, ordinal, column, index_type = parts
            for value, label in ((schema, "schema"), (table, "table"), (name, "index"), (column, "column")):
                _identifier(value, f"{label} identifier")
            if non_unique not in {"0", "1"} or _INDEX_TYPE.fullmatch(index_type) is None:
                raise ValueError(f"invalid index metadata at line {line_number}")
            row = (_positive_ordinal(ordinal, line_number, "index ordinal"), column, non_unique == "0", index_type)
            index_rows.setdefault((f"{schema}.{table}", name), []).append(row)
        else:
            if len(parts) != 10:
                raise ValueError(f"malformed foreign key row at line {line_number}")
            schema, table, name, ordinal, column, ref_schema, ref_table, ref_column, update_rule, delete_rule = parts
            for value, label in (
                (schema, "schema"), (table, "table"), (name, "constraint"),
                (column, "column"), (ref_schema, "referenced schema"),
                (ref_table, "referenced table"), (ref_column, "referenced column"),
            ):
                _identifier(value, f"{label} identifier")
            if update_rule not in _FK_ACTIONS or delete_rule not in _FK_ACTIONS:
                raise ValueError(f"invalid foreign key action at line {line_number}")
            row = (
                _positive_ordinal(ordinal, line_number, "foreign key ordinal"),
                column, f"{ref_schema}.{ref_table}", ref_column, update_rule, delete_rule,
            )
            foreign_key_rows.setdefault((f"{schema}.{table}", name), []).append(row)

    indexes: Dict[str, Dict[str, SchemaIndex]] = {}
    for (full_table, name), rows in sorted(index_rows.items()):
        ordered = sorted(rows)
        if [row[0] for row in ordered] != list(range(1, len(ordered) + 1)):
            raise ValueError(f"non-contiguous index ordinal for {full_table}.{name}")
        if full_table not in tables or any(row[1] not in tables[full_table] for row in ordered):
            raise ValueError(f"index column is missing for {full_table}.{name}")
        if len({(row[2], row[3]) for row in ordered}) != 1:
            raise ValueError(f"inconsistent index metadata for {full_table}.{name}")
        indexes.setdefault(full_table, {})[name] = SchemaIndex(
            name=name,
            unique=ordered[0][2],
            columns=tuple(row[1] for row in ordered),
            index_type=ordered[0][3],
        )

    foreign_keys: Dict[str, Dict[str, SchemaForeignKey]] = {}
    for (full_table, name), rows in sorted(foreign_key_rows.items()):
        ordered = sorted(rows)
        if [row[0] for row in ordered] != list(range(1, len(ordered) + 1)):
            raise ValueError(f"non-contiguous foreign key ordinal for {full_table}.{name}")
        if full_table not in tables or any(row[1] not in tables[full_table] for row in ordered):
            raise ValueError(f"foreign key column is missing for {full_table}.{name}")
        identity = {(row[2], row[4], row[5]) for row in ordered}
        if len(identity) != 1:
            raise ValueError(f"inconsistent foreign key metadata for {full_table}.{name}")
        referenced_table = ordered[0][2]
        if referenced_table in tables and any(row[3] not in tables[referenced_table] for row in ordered):
            raise ValueError(f"referenced column is missing for {full_table}.{name}")
        foreign_keys.setdefault(full_table, {})[name] = SchemaForeignKey(
            name=name,
            columns=tuple(row[1] for row in ordered),
            referenced_table=referenced_table,
            referenced_columns=tuple(row[3] for row in ordered),
            update_rule=ordered[0][4],
            delete_rule=ordered[0][5],
        )
    return SchemaSnapshot(
        tables=tables,
        indexes=indexes,
        foreign_keys=foreign_keys,
        metadata_complete={"COLUMNS", "STATISTICS", "FOREIGN_KEYS"}.issubset(sections),
    )


def schema_capability(
    snapshot: SchemaSnapshot,
    used_columns: Mapping[str, Sequence[str]],
) -> Dict[str, Any]:
    """Serialize the strict directional schema capability contract."""
    if not isinstance(snapshot, SchemaSnapshot) or not snapshot.metadata_complete:
        raise ValueError("constraint metadata is incomplete")
    payload = {
        "tables": {
            table: {
                column: definition.to_dict()
                for column, definition in sorted(columns.items())
            }
            for table, columns in sorted(snapshot.tables.items())
        },
        "indexes": {
            table: {
                name: definition.to_dict()
                for name, definition in sorted(definitions.items())
            }
            for table, definitions in sorted(snapshot.indexes.items())
        },
        "foreign_keys": {
            table: {
                name: definition.to_dict()
                for name, definition in sorted(definitions.items())
            }
            for table, definitions in sorted(snapshot.foreign_keys.items())
        },
        "used_columns": {
            table: sorted(dict.fromkeys(columns))
            for table, columns in sorted(used_columns.items())
        },
    }
    parse_schema_capability(payload)
    return payload


def parse_schema_capability(
    payload: object,
) -> Tuple[SchemaSnapshot, Dict[str, Sequence[str]]]:
    """Validate and reconstruct one side of the directional capability."""
    if not isinstance(payload, dict) or set(payload) != {
        "tables", "indexes", "foreign_keys", "used_columns",
    }:
        raise ValueError("live information_schema capability is invalid")
    if not all(isinstance(payload[key], dict) for key in payload):
        raise ValueError("live information_schema capability is invalid")

    tables: Dict[str, Dict[str, SchemaColumn]] = {}
    for full_table, columns in payload["tables"].items():
        if (
            not isinstance(full_table, str)
            or full_table.count(".") != 1
            or not isinstance(columns, dict)
            or not columns
        ):
            raise ValueError("live information_schema table is invalid")
        schema, table = full_table.split(".")
        _identifier(schema, "schema identifier")
        _identifier(table, "table identifier")
        parsed_columns = {}
        ordinals = set()
        for name, definition in columns.items():
            if (
                not isinstance(name, str)
                or not isinstance(definition, dict)
                or set(definition) != {
                    "name", "ordinal", "column_type", "nullable", "default", "extra",
                }
                or definition.get("name") != name
            ):
                raise ValueError("live SchemaColumn is invalid")
            _identifier(name, "column identifier")
            ordinal = definition.get("ordinal")
            if (
                not isinstance(ordinal, int)
                or isinstance(ordinal, bool)
                or not 1 <= ordinal <= 100_000
                or ordinal in ordinals
                or not isinstance(definition.get("column_type"), str)
                or not definition["column_type"]
                or not isinstance(definition.get("nullable"), bool)
                or (definition.get("default") is not None and not isinstance(definition["default"], str))
                or not isinstance(definition.get("extra"), str)
            ):
                raise ValueError("live SchemaColumn is invalid")
            ordinals.add(ordinal)
            parsed_columns[name] = SchemaColumn(**definition)
        tables[full_table] = parsed_columns

    indexes: Dict[str, Dict[str, SchemaIndex]] = {}
    for full_table, definitions in payload["indexes"].items():
        if full_table not in tables or not isinstance(definitions, dict) or not definitions:
            raise ValueError("live index table is invalid")
        parsed_indexes = {}
        for name, definition in definitions.items():
            if (
                not isinstance(name, str)
                or not isinstance(definition, dict)
                or set(definition) != {"name", "unique", "columns", "index_type"}
                or definition.get("name") != name
                or not isinstance(definition.get("unique"), bool)
                or not isinstance(definition.get("columns"), list)
                or not definition["columns"]
                or len(definition["columns"]) != len(set(definition["columns"]))
                or not all(
                    isinstance(column, str) and column in tables[full_table]
                    for column in definition["columns"]
                )
                or not isinstance(definition.get("index_type"), str)
                or _INDEX_TYPE.fullmatch(definition["index_type"]) is None
            ):
                raise ValueError("live SchemaIndex is invalid")
            _identifier(name, "index identifier")
            parsed_indexes[name] = SchemaIndex(
                name=name,
                unique=definition["unique"],
                columns=tuple(definition["columns"]),
                index_type=definition["index_type"],
            )
        indexes[full_table] = parsed_indexes

    foreign_keys: Dict[str, Dict[str, SchemaForeignKey]] = {}
    for full_table, definitions in payload["foreign_keys"].items():
        if full_table not in tables or not isinstance(definitions, dict) or not definitions:
            raise ValueError("live foreign key table is invalid")
        parsed_foreign_keys = {}
        for name, definition in definitions.items():
            if (
                not isinstance(name, str)
                or not isinstance(definition, dict)
                or set(definition) != {
                    "name", "columns", "referenced_table", "referenced_columns",
                    "update_rule", "delete_rule",
                }
                or definition.get("name") != name
            ):
                raise ValueError("live SchemaForeignKey is invalid")
            _identifier(name, "constraint identifier")
            columns = definition.get("columns")
            referenced = definition.get("referenced_columns")
            referenced_table = definition.get("referenced_table")
            if (
                not isinstance(columns, list)
                or not columns
                or not isinstance(referenced, list)
                or len(columns) != len(referenced)
            ):
                raise ValueError("live SchemaForeignKey is invalid")
            if (
                len(columns) != len(set(columns))
                or not all(isinstance(column, str) and column in tables[full_table] for column in columns)
                or not isinstance(referenced_table, str)
                or referenced_table.count(".") != 1
                or not all(isinstance(column, str) and _IDENTIFIER.fullmatch(column) for column in referenced)
                or definition.get("update_rule") not in _FK_ACTIONS
                or definition.get("delete_rule") not in _FK_ACTIONS
            ):
                raise ValueError("live SchemaForeignKey is invalid")
            ref_schema, ref_table = referenced_table.split(".")
            _identifier(ref_schema, "referenced schema identifier")
            _identifier(ref_table, "referenced table identifier")
            if referenced_table in tables and any(column not in tables[referenced_table] for column in referenced):
                raise ValueError("live SchemaForeignKey reference is invalid")
            parsed_foreign_keys[name] = SchemaForeignKey(
                name=name,
                columns=tuple(columns),
                referenced_table=referenced_table,
                referenced_columns=tuple(referenced),
                update_rule=definition["update_rule"],
                delete_rule=definition["delete_rule"],
            )
        foreign_keys[full_table] = parsed_foreign_keys

    used_columns: Dict[str, Sequence[str]] = {}
    for full_table, columns in payload["used_columns"].items():
        if (
            full_table not in tables
            or not isinstance(columns, list)
            or not columns
            or len(columns) != len(set(columns))
            or not all(isinstance(column, str) and column in tables[full_table] for column in columns)
        ):
            raise ValueError("used schema columns are invalid")
        used_columns[full_table] = list(columns)
    if not used_columns:
        raise ValueError("used schema columns are missing")
    return SchemaSnapshot(
        tables=tables,
        indexes=indexes,
        foreign_keys=foreign_keys,
        metadata_complete=True,
    ), used_columns


def _normalized_type(column_type: str) -> str:
    normalized = " ".join(column_type.lower().split())
    normalized = _INTEGER_WITH_DISPLAY_WIDTH.sub(
        lambda match: "int" if match.group(1).lower() == "integer" else match.group(1).lower(),
        normalized,
    )
    normalized = re.sub(r"\binteger\b", "int", normalized)
    return normalized


def _normalized_extra(extra: str) -> str:
    return " ".join(extra.lower().split())


def _compatible(source: SchemaColumn, target: SchemaColumn) -> bool:
    return (
        _normalized_type(source.column_type) == _normalized_type(target.column_type)
        and source.nullable == target.nullable
        and source.default == target.default
        and _normalized_extra(source.extra) == _normalized_extra(target.extra)
    )


def _column_item(
    column: str,
    classification: str,
    source: Optional[SchemaColumn],
    target: Optional[SchemaColumn],
) -> Dict[str, Any]:
    if classification not in CLASSIFICATIONS:
        raise ValueError(f"unknown classification: {classification}")
    return {
        "column": column,
        "classification": classification,
        "source": source.to_dict() if source is not None else None,
        "target": target.to_dict() if target is not None else None,
    }


def _normalization_columns(policy: Mapping[str, Any]) -> Set[str]:
    configured = policy.get("normalization_columns", [])
    if not isinstance(configured, list) or not all(
        isinstance(value, str) for value in configured
    ):
        raise ValueError("normalization_columns must be a list of strings")
    return set(configured)


def _source_only_allowlist(policy: Mapping[str, Any]) -> Set[str]:
    configured = policy.get("source_only_allowlist", [])
    if not isinstance(configured, list) or not all(
        isinstance(value, str) for value in configured
    ):
        raise ValueError("source_only_allowlist must be a list of strings")
    return set(configured)


def build_directional_mapping(
    source: SchemaSnapshot,
    target: SchemaSnapshot,
    used_columns: Mapping[str, Sequence[str]],
    policy: Mapping[str, Any],
) -> Dict[str, Any]:
    allowlist = _source_only_allowlist(policy)
    normalization = _normalization_columns(policy)
    tables: Dict[str, Any] = {}
    blockers = []

    for table in sorted(used_columns):
        source_columns = source.tables.get(table, {})
        target_columns = target.tables.get(table, {})
        items = []
        used = list(dict.fromkeys(used_columns[table]))

        for column_name in used:
            key = f"{table}.{column_name}"
            source_column = source_columns.get(column_name)
            target_column = target_columns.get(column_name)
            if source_column is None:
                classification = "BLOCKED"
                blockers.append(key)
            elif target_column is None:
                classification = (
                    "SOURCE_ONLY_IGNORED" if key in allowlist else "BLOCKED"
                )
                if classification == "BLOCKED":
                    blockers.append(key)
            elif key in normalization or column_name in _BUILTIN_NORMALIZATION_NAMES:
                classification = "NORMALIZATION_REQUIRED"
            elif _compatible(source_column, target_column):
                classification = "COMMON_COMPATIBLE"
            else:
                classification = "SEMANTIC_MISMATCH"
                blockers.append(key)
            items.append(
                _column_item(
                    column_name,
                    classification,
                    source_column,
                    target_column,
                )
            )

        used_set = set(used)
        for column_name, target_column in sorted(
            target_columns.items(), key=lambda item: item[1].ordinal
        ):
            if column_name in used_set or column_name in source_columns:
                continue
            key = f"{table}.{column_name}"
            has_default = (
                target_column.nullable
                or target_column.default is not None
                or "auto_increment" in _normalized_extra(target_column.extra).split()
            )
            classification = "TARGET_DEFAULT" if has_default else "TARGET_VALUE_REQUIRED"
            if classification == "TARGET_VALUE_REQUIRED":
                blockers.append(key)
            items.append(_column_item(column_name, classification, None, target_column))

        def canonical_order(item: Mapping[str, Any]) -> Any:
            if item["target"] is not None:
                return (0, item["target"]["ordinal"])
            if item["source"] is not None:
                return (1, item["source"]["ordinal"])
            return (2, item["column"])

        tables[table] = sorted(items, key=canonical_order)

    return {
        "schema_version": "openstack-rehome-directional-schema-mapping/v1alpha1",
        "source_profile": policy.get("source_profile"),
        "target_profile": policy.get("target_profile"),
        "tables": tables,
        "blockers": list(dict.fromkeys(blockers)),
    }
