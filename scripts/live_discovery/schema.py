from dataclasses import asdict, dataclass
from pathlib import Path
import re
from typing import Any, Dict, Mapping, Optional, Sequence, Set


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
class SchemaSnapshot:
    tables: Dict[str, Dict[str, SchemaColumn]]


def parse_information_schema(path: Path) -> SchemaSnapshot:
    tables: Dict[str, Dict[str, SchemaColumn]] = {}
    in_columns = False
    for line_number, raw_line in enumerate(
        Path(path).read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not raw_line:
            continue
        if raw_line.startswith("SERVICE:"):
            in_columns = False
            continue
        if raw_line == "SECTION:COLUMNS":
            in_columns = True
            continue
        if raw_line.startswith("SECTION:"):
            in_columns = False
            continue
        if not in_columns:
            continue

        parts = raw_line.split("\t")
        if len(parts) < 8:
            raise ValueError(f"malformed information_schema row at line {line_number}")
        schema, table, ordinal, name, column_type, nullable, default, extra = parts[:8]
        try:
            ordinal_value = int(ordinal)
        except ValueError as error:
            raise ValueError(
                f"invalid column ordinal at line {line_number}: {ordinal!r}"
            ) from error
        if nullable not in {"YES", "NO"}:
            raise ValueError(
                f"invalid nullable value at line {line_number}: {nullable!r}"
            )
        full_table = f"{schema}.{table}"
        columns = tables.setdefault(full_table, {})
        if name in columns:
            raise ValueError(f"duplicate column {full_table}.{name}")
        columns[name] = SchemaColumn(
            name=name,
            ordinal=ordinal_value,
            column_type=column_type,
            nullable=nullable == "YES",
            default=None if default in {"NULL", r"\N"} else default,
            extra="" if extra == r"\N" else extra,
        )
    return SchemaSnapshot(tables=tables)


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
