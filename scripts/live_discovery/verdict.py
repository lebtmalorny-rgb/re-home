"""Fail-closed readiness verdict aggregation."""

from collections import defaultdict
import hashlib
import re
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Sequence

from .contract import CheckResult
from .graph import _canonical, _safe_reason, validate_graph


VERDICT_VERSION = "openstack-rehome-readiness-verdict/v1alpha1"
MAPPING_VERSION = "openstack-rehome-directional-schema-mapping/v1alpha1"
SOURCE_PROFILE = "keystack-2025.1"
TARGET_PROFILE = "vanilla-openstack-2025.1-epoxy"

EXIT_CODES = {
    "READY": 0,
    "READY_WITH_WARNINGS": 0,
    "UNKNOWN": 2,
    "BLOCKED": 3,
}
PRECEDENCE = ("BLOCKED", "UNKNOWN", "WARN", "PASS")

_STATUSES = frozenset(PRECEDENCE)
_MAPPING_CLASSES = frozenset({
    "COMMON_COMPATIBLE",
    "NORMALIZATION_REQUIRED",
    "SOURCE_ONLY_IGNORED",
    "TARGET_DEFAULT",
    "TARGET_VALUE_REQUIRED",
    "SEMANTIC_MISMATCH",
    "BLOCKED",
})
_BLOCKING_MAPPING_CLASSES = frozenset({
    "TARGET_VALUE_REQUIRED", "SEMANTIC_MISMATCH", "BLOCKED"
})
_SAFE_TEXT = re.compile(r"^[^\x00-\x1f\x7f]{1,512}$")
_SENSITIVE_VALUE = re.compile(
    r"\bsecret[-_]?token\b|\b(?:password|passwd|credential)\b|"
    r"(?:password|passwd|token|secret|credential|connection[_-]?(?:info|data))\s*[:=]\s*\S+|"
    r"(?:(?:authorization\s*:\s*)?(?:bearer|basic)\s+\S+)|"
    r"\bsk-[A-Za-z0-9_-]{8,}\b|"
    r"(?:[a-z][a-z0-9+.-]*://[^/@:\s]+:[^/@\s]+@)",
    flags=re.IGNORECASE,
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_CHECKS = 100_000
_MAX_MAPPING_TABLES = 4096
_MAX_MAPPING_COLUMNS = 100_000
_MAPPING_KEYS = frozenset({
    "schema_version", "source_profile", "target_profile", "tables", "blockers",
})
_MAPPING_COLUMN_KEYS = frozenset({
    "column", "classification", "source", "target",
})
_SCHEMA_COLUMN_KEYS = frozenset({
    "name", "ordinal", "column_type", "nullable", "default", "extra",
})
_TABLE_NAME = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")
_COLUMN_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_INTEGER_WITH_DISPLAY_WIDTH = re.compile(
    r"\b(tinyint|smallint|mediumint|int|integer|bigint)\(\d+\)",
    flags=re.IGNORECASE,
)


def _id(prefix: str, label: str) -> str:
    digest = hashlib.sha256(f"{prefix}\0{label}".encode("utf-8")).hexdigest()[:16]
    return f"verdict.{prefix}.{digest}"


def _synthetic(prefix: str, status: str, reason: str, label: str = "") -> CheckResult:
    return CheckResult(_id(prefix, label), status, reason)


def _normalize_string_list(value: object) -> List[str]:
    if not isinstance(value, list) or len(value) > 4096:
        raise ValueError("invalid list")
    normalized = []
    for item in value:
        if not isinstance(item, str) or _SAFE_TEXT.fullmatch(item) is None:
            raise ValueError("invalid string")
        if _SENSITIVE_VALUE.search(item):
            raise ValueError("sensitive string")
        normalized.append(item)
    if len(normalized) != len(set(normalized)):
        raise ValueError("duplicate string")
    return sorted(normalized)


def _normalize_check(value: object) -> CheckResult:
    if not isinstance(value, CheckResult):
        raise ValueError("invalid check")
    if (
        not isinstance(value.check_id, str)
        or _SAFE_TEXT.fullmatch(value.check_id) is None
        or _SENSITIVE_VALUE.search(value.check_id) is not None
        or not isinstance(value.status, str)
        or value.status not in _STATUSES
    ):
        raise ValueError("invalid check identity")
    return CheckResult(
        value.check_id,
        value.status,
        _safe_reason(value.reason, "readiness check reason is malformed"),
        _normalize_string_list(value.resource_ids),
        _normalize_string_list(value.evidence_ids),
    )


def _mapping_text(
    value: object,
    pattern: re.Pattern = _SAFE_TEXT,
    *,
    allow_empty: bool = False,
) -> str:
    if (
        not isinstance(value, str)
        or (not value and not allow_empty)
        or len(value) > 512
        or (value and pattern.fullmatch(value) is None)
        or any(character in value for character in ("\x00", "\n", "\r"))
        or _SENSITIVE_VALUE.search(value)
    ):
        raise ValueError("invalid mapping text")
    return value


def _schema_column(value: object, column_name: str) -> Dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _SCHEMA_COLUMN_KEYS:
        raise ValueError("invalid schema column")
    name = _mapping_text(value.get("name"), _COLUMN_NAME)
    ordinal = value.get("ordinal")
    column_type = _mapping_text(value.get("column_type"))
    nullable = value.get("nullable")
    default = value.get("default")
    extra = value.get("extra")
    if (
        name != column_name
        or not isinstance(ordinal, int)
        or isinstance(ordinal, bool)
        or not 1 <= ordinal <= _MAX_MAPPING_COLUMNS
        or not isinstance(nullable, bool)
        or (default is not None and not isinstance(default, str))
        or not isinstance(extra, str)
        or len(extra) > 2048
    ):
        raise ValueError("invalid schema column")
    if default is not None:
        _mapping_text(default, allow_empty=True)
    if extra and (_SAFE_TEXT.fullmatch(extra) is None or _SENSITIVE_VALUE.search(extra)):
        raise ValueError("invalid schema column")
    return {
        "name": name,
        "ordinal": ordinal,
        "column_type": column_type,
        "nullable": nullable,
        "default": default,
        "extra": extra,
    }


def _normalized_column_type(value: str) -> str:
    normalized = " ".join(value.lower().split())
    normalized = _INTEGER_WITH_DISPLAY_WIDTH.sub(
        lambda match: "int" if match.group(1).lower() == "integer" else match.group(1).lower(),
        normalized,
    )
    return re.sub(r"\binteger\b", "int", normalized)


def _columns_compatible(source: Mapping[str, Any], target: Mapping[str, Any]) -> bool:
    return (
        _normalized_column_type(source["column_type"])
        == _normalized_column_type(target["column_type"])
        and source["nullable"] == target["nullable"]
        and source["default"] == target["default"]
        and " ".join(source["extra"].lower().split())
        == " ".join(target["extra"].lower().split())
    )


def _has_target_default(target: Mapping[str, Any]) -> bool:
    return (
        target["nullable"]
        or target["default"] is not None
        or "auto_increment" in target["extra"].lower().split()
    )


def _classification_consistent(
    classification: str,
    source: object,
    target: object,
) -> bool:
    if classification == "COMMON_COMPATIBLE":
        return source is not None and target is not None and _columns_compatible(source, target)
    if classification == "NORMALIZATION_REQUIRED":
        return source is not None and target is not None
    if classification == "SOURCE_ONLY_IGNORED":
        return source is not None and target is None
    if classification == "TARGET_DEFAULT":
        return source is None and target is not None and _has_target_default(target)
    if classification == "TARGET_VALUE_REQUIRED":
        return source is None and target is not None and not _has_target_default(target)
    if classification == "SEMANTIC_MISMATCH":
        return source is not None and target is not None and not _columns_compatible(source, target)
    if classification == "BLOCKED":
        return source is None or target is None
    return False


def _mapping_checks(mapping: object) -> List[CheckResult]:
    if mapping is None or (isinstance(mapping, Mapping) and not mapping):
        return [_synthetic(
            "mapping-missing", "UNKNOWN", "directional schema mapping is missing"
        )]
    if not isinstance(mapping, Mapping):
        return [_synthetic(
            "mapping-malformed", "BLOCKED", "directional schema mapping is malformed"
        )]
    if set(mapping) != _MAPPING_KEYS:
        return [_synthetic(
            "mapping-fields", "BLOCKED",
            "directional schema mapping has unknown or missing fields",
        )]
    if mapping.get("schema_version") != MAPPING_VERSION:
        return [_synthetic(
            "mapping-schema", "BLOCKED", "directional schema mapping version is invalid"
        )]

    checks: List[CheckResult] = []
    if mapping.get("source_profile") != SOURCE_PROFILE:
        checks.append(_synthetic(
            "mapping-source-profile", "BLOCKED",
            "directional schema mapping source profile is not approved Keystack 2025.1",
        ))
    if mapping.get("target_profile") != TARGET_PROFILE:
        checks.append(_synthetic(
            "mapping-target-profile", "BLOCKED",
            "directional schema mapping target profile is not vanilla OpenStack 2025.1 Epoxy",
        ))
    blockers = mapping.get("blockers")
    if not isinstance(blockers, list) or len(blockers) > _MAX_MAPPING_COLUMNS:
        checks.append(_synthetic(
            "mapping-blockers-malformed", "BLOCKED",
            "directional schema mapping blockers are malformed",
        ))
    else:
        seen_blockers = set()
        for blocker in blockers:
            try:
                safe = _mapping_text(blocker)
            except ValueError:
                checks.append(_synthetic(
                    "mapping-blocker-malformed", "BLOCKED",
                    "directional schema mapping blocker is malformed",
                ))
                continue
            if safe in seen_blockers:
                checks.append(_synthetic(
                    "mapping-blocker-duplicate", "BLOCKED",
                    "directional schema mapping blocker is duplicated", safe,
                ))
            seen_blockers.add(safe)
        for safe in sorted(seen_blockers):
            checks.append(_synthetic(
                "mapping-blocker", "BLOCKED",
                f"schema mapping blocker: {safe}", safe,
            ))

    tables = mapping.get("tables")
    if not isinstance(tables, Mapping) or len(tables) > _MAX_MAPPING_TABLES:
        checks.append(_synthetic(
            "mapping-tables-malformed", "BLOCKED",
            "directional schema mapping tables are malformed",
        ))
        return checks
    if not tables:
        checks.append(_synthetic(
            "mapping-evidence-empty", "UNKNOWN",
            "directional schema mapping table evidence is empty",
        ))
        return checks

    column_count = 0
    expected_blockers = set()
    mapping_structure_valid = True
    if not all(
        isinstance(key, str)
        and _TABLE_NAME.fullmatch(key) is not None
        and _SENSITIVE_VALUE.search(key) is None
        for key in tables
    ):
        checks.append(_synthetic(
            "mapping-table-name-malformed", "BLOCKED",
            "directional schema mapping table name is malformed",
        ))
        return checks
    for table_name in sorted(tables):
        items = tables[table_name]
        if not isinstance(items, list):
            checks.append(_synthetic(
                "mapping-table-malformed", "BLOCKED",
                "directional schema mapping table is malformed",
                table_name,
            ))
            mapping_structure_valid = False
            continue
        if not items:
            checks.append(_synthetic(
                "mapping-table-empty", "UNKNOWN",
                "directional schema mapping required table evidence is empty",
                table_name,
            ))
            continue
        column_count += len(items)
        if column_count > _MAX_MAPPING_COLUMNS:
            checks.append(_synthetic(
                "mapping-columns-bounds", "BLOCKED",
                "directional schema mapping exceeds safety bounds",
            ))
            break
        seen_columns = set()
        source_ordinals = set()
        target_ordinals = set()
        previous_order = None
        for item in items:
            if not isinstance(item, Mapping) or set(item) != _MAPPING_COLUMN_KEYS:
                checks.append(_synthetic(
                    "mapping-column-malformed", "BLOCKED",
                    "directional schema mapping column is malformed",
                    table_name,
                ))
                mapping_structure_valid = False
                continue
            column = item.get("column")
            classification = item.get("classification")
            if (
                not isinstance(column, str)
                or _COLUMN_NAME.fullmatch(column) is None
                or _SENSITIVE_VALUE.search(column) is not None
                or not isinstance(classification, str)
                or classification not in _MAPPING_CLASSES
            ):
                checks.append(_synthetic(
                    "mapping-column-malformed", "BLOCKED",
                    "directional schema mapping column is malformed",
                    table_name,
                ))
                mapping_structure_valid = False
                continue
            label = f"{table_name}.{column}"
            if column in seen_columns:
                checks.append(_synthetic(
                    "mapping-column-duplicate", "BLOCKED",
                    f"schema mapping column is duplicated: {label}", label,
                ))
                mapping_structure_valid = False
                continue
            seen_columns.add(column)
            try:
                source = (
                    None if item.get("source") is None
                    else _schema_column(item.get("source"), column)
                )
                target = (
                    None if item.get("target") is None
                    else _schema_column(item.get("target"), column)
                )
            except ValueError:
                checks.append(_synthetic(
                    "mapping-schema-column-malformed", "BLOCKED",
                    "directional schema mapping SchemaColumn is malformed", label,
                ))
                mapping_structure_valid = False
                continue
            for value, ordinals in ((source, source_ordinals), (target, target_ordinals)):
                if value is not None:
                    if value["ordinal"] in ordinals:
                        checks.append(_synthetic(
                            "mapping-ordinal-duplicate", "BLOCKED",
                            "directional schema mapping ordinal is duplicated", table_name,
                        ))
                        mapping_structure_valid = False
                    ordinals.add(value["ordinal"])
            if not _classification_consistent(classification, source, target):
                checks.append(_synthetic(
                    "mapping-classification-inconsistent", "BLOCKED",
                    "directional schema mapping classification is inconsistent", label,
                ))
                mapping_structure_valid = False
                continue
            canonical_order = (
                (0, target["ordinal"])
                if target is not None
                else (1, source["ordinal"])
                if source is not None
                else (2, column)
            )
            if previous_order is not None and canonical_order <= previous_order:
                checks.append(_synthetic(
                    "mapping-column-order", "BLOCKED",
                    "directional schema mapping column order is not canonical",
                    table_name,
                ))
                mapping_structure_valid = False
            previous_order = canonical_order
            if classification in _BLOCKING_MAPPING_CLASSES:
                expected_blockers.add(label)
                checks.append(_synthetic(
                    "mapping-classification", "BLOCKED",
                    f"schema mapping classification blocks re-home: {label}", label,
                ))
            elif classification == "SOURCE_ONLY_IGNORED":
                checks.append(_synthetic(
                    "mapping-source-only", "WARN",
                    f"reviewed source-only schema field is ignored: {label}", label,
                ))
    if mapping_structure_valid and seen_blockers != expected_blockers:
        checks.append(_synthetic(
            "mapping-blockers-inconsistent", "BLOCKED",
            "directional schema mapping blockers are inconsistent",
        ))
    return checks


def _graph_has_instance(graph: object) -> bool:
    if not isinstance(graph, Mapping) or not isinstance(graph.get("nodes"), list):
        return False
    for node in graph["nodes"]:
        provenance = node.get("provenance") if isinstance(node, Mapping) else None
        if (
            isinstance(node, Mapping)
            and node.get("side") == "source"
            and node.get("kind") == "instance"
            and isinstance(provenance, Mapping)
            and provenance.get("service") == "nova"
            and provenance.get("side") == "source"
        ):
            return True
    return False


def _graph_has_collector_checks(graph: object) -> bool:
    return (
        isinstance(graph, Mapping)
        and isinstance(graph.get("checks"), list)
        and bool(graph["checks"])
    )


def _merge_checks(values: Iterable[CheckResult]) -> List[CheckResult]:
    groups: MutableMapping[str, List[CheckResult]] = defaultdict(list)
    malformed = 0
    for value in values:
        try:
            normalized = _normalize_check(value)
        except ValueError:
            malformed += 1
            continue
        groups[normalized.check_id].append(normalized)

    merged: List[CheckResult] = []
    for check_id in sorted(groups):
        variants = groups[check_id]
        signatures = {_canonical(item.to_dict()) for item in variants}
        if len(signatures) == 1:
            merged.append(variants[0])
        else:
            merged.append(_synthetic(
                "check-conflict", "BLOCKED", "conflicting check definition",
                check_id,
            ))
    for index in range(malformed):
        merged.append(_synthetic(
            "check-malformed", "BLOCKED", "readiness check is malformed", str(index)
        ))
    return sorted(merged, key=lambda item: item.check_id)


def compute_verdict(
    graph: Mapping[str, Any],
    checks: Sequence[CheckResult],
    mapping: Mapping[str, Any],
) -> Dict[str, Any]:
    """Compute a deterministic aggregate verdict with exact fail-closed precedence."""
    supplied: List[CheckResult] = []
    malformed_check_set = False
    if isinstance(checks, (list, tuple)) and len(checks) <= _MAX_CHECKS:
        supplied.extend(checks)
    else:
        malformed_check_set = True

    combined: List[CheckResult] = []
    combined.extend(validate_graph(graph))
    combined.extend(supplied)
    combined.extend(_mapping_checks(mapping))
    if malformed_check_set:
        combined.append(_synthetic(
            "checks-malformed", "BLOCKED", "readiness check set is malformed"
        ))
    if not _graph_has_instance(graph):
        combined.append(_synthetic(
            "instances-missing", "UNKNOWN", "no source instances were discovered"
        ))
    if not supplied and not _graph_has_collector_checks(graph):
        combined.append(_synthetic(
            "checks-missing", "UNKNOWN", "no readiness checks were produced"
        ))

    merged = _merge_checks(combined)
    counts = {status: 0 for status in ("PASS", "WARN", "UNKNOWN", "BLOCKED")}
    reasons = {status: [] for status in ("PASS", "WARN", "UNKNOWN", "BLOCKED")}
    for check in merged:
        counts[check.status] += 1
        reasons[check.status].append(check.reason)
    for status in reasons:
        reasons[status] = sorted(dict.fromkeys(reasons[status]))

    winning_status = next(status for status in PRECEDENCE if counts[status])
    verdict = {
        "BLOCKED": "BLOCKED",
        "UNKNOWN": "UNKNOWN",
        "WARN": "READY_WITH_WARNINGS",
        "PASS": "READY",
    }[winning_status]
    graph_sha256 = None
    if isinstance(graph, Mapping):
        candidate = graph.get("graph_sha256")
        if isinstance(candidate, str) and _SHA256.fullmatch(candidate):
            graph_sha256 = candidate
    return {
        "schema_version": VERDICT_VERSION,
        "graph_sha256": graph_sha256,
        "verdict": verdict,
        "exit_code": EXIT_CODES[verdict],
        "counts": counts,
        "reasons": reasons,
        "checks": [item.to_dict() for item in merged],
    }
