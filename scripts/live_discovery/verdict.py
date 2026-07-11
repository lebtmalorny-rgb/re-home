"""Fail-closed readiness verdict aggregation."""

from collections import defaultdict
import hashlib
import re
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Sequence

from .contract import CheckResult
from .graph import _canonical, _safe_reason, validate_graph


VERDICT_VERSION = "openstack-rehome-readiness-verdict/v1alpha1"
MAPPING_VERSION = "openstack-rehome-directional-schema-mapping/v1alpha1"
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
    r"(?:password|passwd|token|credential|connection[_-]?(?:info|data))\s*[:=]\s*\S+|"
    r"(?:authorization\s*:\s*(?:bearer|basic)\s+\S+)|"
    r"(?:[a-z][a-z0-9+.-]*://[^/@:\s]+:[^/@\s]+@)",
    flags=re.IGNORECASE,
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_CHECKS = 100_000
_MAX_MAPPING_TABLES = 4096
_MAX_MAPPING_COLUMNS = 100_000


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


def _mapping_checks(mapping: object) -> List[CheckResult]:
    if mapping is None:
        return [_synthetic(
            "mapping-missing", "UNKNOWN", "directional schema mapping is missing"
        )]
    if not isinstance(mapping, Mapping):
        return [_synthetic(
            "mapping-malformed", "BLOCKED", "directional schema mapping is malformed"
        )]
    if mapping.get("schema_version") != MAPPING_VERSION:
        return [_synthetic(
            "mapping-schema", "BLOCKED", "directional schema mapping version is invalid"
        )]

    checks: List[CheckResult] = []
    if mapping.get("target_profile") != TARGET_PROFILE:
        checks.append(_synthetic(
            "mapping-target-profile", "BLOCKED",
            "directional schema mapping target profile is not vanilla OpenStack 2025.1 Epoxy",
        ))
    source_profile = mapping.get("source_profile")
    if not isinstance(source_profile, str) or _SAFE_TEXT.fullmatch(source_profile) is None:
        checks.append(_synthetic(
            "mapping-source-profile", "UNKNOWN",
            "directional schema mapping source profile is unavailable",
        ))

    blockers = mapping.get("blockers")
    if not isinstance(blockers, list) or len(blockers) > _MAX_MAPPING_COLUMNS:
        checks.append(_synthetic(
            "mapping-blockers-malformed", "BLOCKED",
            "directional schema mapping blockers are malformed",
        ))
    else:
        seen = set()
        for index, blocker in enumerate(blockers):
            if not isinstance(blocker, str) or _SAFE_TEXT.fullmatch(blocker) is None:
                checks.append(_synthetic(
                    "mapping-blocker-malformed", "BLOCKED",
                    "directional schema mapping blocker is malformed", str(index),
                ))
                continue
            safe = _safe_reason(blocker, "mapping field is malformed")
            if safe in seen:
                continue
            seen.add(safe)
            checks.append(_synthetic(
                "mapping-blocker", "BLOCKED", f"schema mapping blocker: {safe}", safe
            ))

    tables = mapping.get("tables")
    if not isinstance(tables, Mapping) or len(tables) > _MAX_MAPPING_TABLES:
        checks.append(_synthetic(
            "mapping-tables-malformed", "BLOCKED",
            "directional schema mapping tables are malformed",
        ))
        return checks

    column_count = 0
    for table_name in sorted(tables) if all(isinstance(key, str) for key in tables) else []:
        items = tables[table_name]
        if _SAFE_TEXT.fullmatch(table_name) is None or not isinstance(items, list):
            checks.append(_synthetic(
                "mapping-table-malformed", "BLOCKED",
                "directional schema mapping table is malformed",
                table_name if isinstance(table_name, str) else "invalid",
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
        for index, item in enumerate(items):
            if not isinstance(item, Mapping):
                checks.append(_synthetic(
                    "mapping-column-malformed", "BLOCKED",
                    "directional schema mapping column is malformed",
                    f"{table_name}:{index}",
                ))
                continue
            column = item.get("column")
            classification = item.get("classification")
            if (
                not isinstance(column, str)
                or _SAFE_TEXT.fullmatch(column) is None
                or classification not in _MAPPING_CLASSES
            ):
                checks.append(_synthetic(
                    "mapping-column-malformed", "BLOCKED",
                    "directional schema mapping column is malformed",
                    f"{table_name}:{index}",
                ))
                continue
            label = f"{table_name}.{column}"
            if column in seen_columns:
                checks.append(_synthetic(
                    "mapping-column-duplicate", "BLOCKED",
                    f"schema mapping column is duplicated: {label}", label,
                ))
                continue
            seen_columns.add(column)
            if classification in _BLOCKING_MAPPING_CLASSES:
                checks.append(_synthetic(
                    "mapping-classification", "BLOCKED",
                    f"schema mapping classification blocks re-home: {label}", label,
                ))
            elif classification == "SOURCE_ONLY_IGNORED":
                checks.append(_synthetic(
                    "mapping-source-only", "WARN",
                    f"reviewed source-only schema field is ignored: {label}", label,
                ))
    if tables and not all(isinstance(key, str) for key in tables):
        checks.append(_synthetic(
            "mapping-table-name-malformed", "BLOCKED",
            "directional schema mapping table name is malformed",
        ))
    return checks


def _graph_has_instance(graph: object) -> bool:
    if not isinstance(graph, Mapping) or not isinstance(graph.get("nodes"), list):
        return False
    for node in graph["nodes"]:
        if isinstance(node, Mapping) and node.get("kind") == "instance":
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
