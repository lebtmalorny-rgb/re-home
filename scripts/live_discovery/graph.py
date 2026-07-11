"""Deterministic, fail-closed assembly of live-discovery collector results."""

from collections import Counter, defaultdict
import hashlib
from itertools import islice
import json
import re
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Sequence, Tuple

from .contract import CheckResult, CollectorResult, DependencyEdge, ResourceNode


GRAPH_VERSION = "openstack-rehome-resource-graph/v1alpha1"

# A reference outside the assembled graph is valid only when both its explicit
# type and the edge relation are reviewed here.  Current collectors materialize
# all required OpenStack objects, so this policy is intentionally narrow.
EXTERNAL_REFERENCE_POLICY = {
    "keystone_secret": frozenset({"uses_external_secret"}),
}

REQUIRED_COLLECTORS = (
    ("source", "nova"),
    ("source", "runtime"),
    ("target", "runtime-capabilities"),
    ("target", "target-profile"),
    ("source", "neutron"),
    ("target", "neutron"),
    ("source", "cinder"),
    ("target", "cinder"),
    ("source", "glance"),
    ("target", "glance"),
)

_STATUSES = frozenset({"PASS", "WARN", "UNKNOWN", "BLOCKED"})
_SIDES = frozenset({"source", "target"})
_EXCLUDED_SERVICES = frozenset({"masakari", "drs"})
_SAFE_IDENTIFIER = re.compile(r"^[^\x00-\x1f\x7f]{1,512}$")
_SENSITIVE_KEY = re.compile(
    r"password|passwd|(?:^|[_-])pwd(?:$|[_-])|token|chap|credential|"
    r"connector|connection[_-]?(?:info|data)",
    flags=re.IGNORECASE,
)
_SENSITIVE_VALUE = re.compile(
    r"(?:password|passwd|token|credential|connection[_-]?(?:info|data))\s*[:=]\s*\S+|"
    r"(?:authorization\s*:\s*(?:bearer|basic)\s+\S+)|"
    r"(?:[a-z][a-z0-9+.-]*://[^/@:\s]+:[^/@\s]+@)",
    flags=re.IGNORECASE,
)
_MAX_RESULTS = 128
_MAX_ITEMS = 100_000
_MAX_TREE_DEPTH = 16
_MAX_TREE_NODES = 20_000
_MAX_STRING = 16_384


class _Malformed(ValueError):
    pass


def _identifier(value: object) -> str:
    if not isinstance(value, str) or _SAFE_IDENTIFIER.fullmatch(value) is None:
        raise _Malformed("identifier")
    return value


def _safe_reason(value: object, fallback: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 2048:
        return fallback
    if _SAFE_IDENTIFIER.fullmatch(value) is None:
        return fallback
    return _SENSITIVE_VALUE.sub("[REDACTED]", value)


def _normalize_tree(value: object) -> object:
    remaining = [_MAX_TREE_NODES]

    def walk(item: object, depth: int) -> object:
        remaining[0] -= 1
        if remaining[0] < 0 or depth > _MAX_TREE_DEPTH:
            raise _Malformed("tree bounds")
        if item is None or isinstance(item, bool) or isinstance(item, int):
            return item
        if isinstance(item, float):
            if item != item or item in {float("inf"), float("-inf")}:
                raise _Malformed("non-finite number")
            return item
        if isinstance(item, str):
            if len(item) > _MAX_STRING or "\x00" in item or _SENSITIVE_VALUE.search(item):
                raise _Malformed("unsafe string")
            return item
        if isinstance(item, list):
            return [walk(child, depth + 1) for child in item]
        if isinstance(item, Mapping):
            normalized: Dict[str, object] = {}
            for key, child in item.items():
                if not isinstance(key, str) or not key or len(key) > 512:
                    raise _Malformed("mapping key")
                if _SENSITIVE_KEY.search(key):
                    if child != "[REDACTED]":
                        raise _Malformed("sensitive mapping key")
                    normalized[key] = "[REDACTED]"
                else:
                    normalized[key] = walk(child, depth + 1)
            return {key: normalized[key] for key in sorted(normalized)}
        raise _Malformed("unsupported value")

    return walk(value, 0)


def _string_list(value: object, *, max_items: int = 4096) -> List[str]:
    if not isinstance(value, list) or len(value) > max_items:
        raise _Malformed("string list")
    normalized = [_identifier(item) for item in value]
    if any(_SENSITIVE_VALUE.search(item) for item in normalized):
        raise _Malformed("sensitive string")
    if len(normalized) != len(set(normalized)):
        raise _Malformed("duplicate string")
    return sorted(normalized)


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _issue(code: str, status: str, reason: str, label: str = "") -> Dict[str, Any]:
    digest = hashlib.sha256(f"{code}\0{label}".encode("utf-8")).hexdigest()[:16]
    return CheckResult(f"graph.{code}.{digest}", status, reason).to_dict()


def _safe_sequence(value: object) -> Sequence[object]:
    if isinstance(value, list) and len(value) <= _MAX_ITEMS:
        return value
    raise _Malformed("sequence")


def _evidence_ids(value: object) -> List[str]:
    return _string_list(value, max_items=4096)


def _provenance(value: object, side: str) -> Dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {"service", "side"}:
        raise _Malformed("provenance")
    service = _identifier(value.get("service"))
    provenance_side = _identifier(value.get("side"))
    if provenance_side != side:
        raise _Malformed("provenance side")
    return {"service": service, "side": provenance_side}


def _node_candidate(
    node: object, service: str, collector_side: str
) -> Tuple[Tuple[str, str, str], Dict[str, Any]]:
    if not isinstance(node, ResourceNode):
        raise _Malformed("node type")
    side = _identifier(node.side)
    kind = _identifier(node.kind)
    identifier = _identifier(node.id)
    if side not in _SIDES or side != collector_side:
        raise _Malformed("node side")
    facts = _normalize_tree(node.facts)
    if not isinstance(facts, dict):
        raise _Malformed("node facts")
    evidence_ids = _evidence_ids(node.evidence_ids)
    payload = {
        "side": side,
        "kind": kind,
        "id": identifier,
        "key": f"{kind}:{identifier}",
        "facts": facts,
        "evidence_ids": evidence_ids,
        "provenance": {"service": service, "side": collector_side},
    }
    return (side, kind, identifier), payload


def _edge_candidate(
    edge: object, service: str, side: str
) -> Tuple[Tuple[str, str, str, str], Dict[str, Any]]:
    if not isinstance(edge, DependencyEdge) or not isinstance(edge.required, bool):
        raise _Malformed("edge type")
    source = _identifier(edge.source)
    target = _identifier(edge.target)
    relation = _identifier(edge.relation)
    _parse_reference(source)
    _parse_reference(target)
    payload = {
        "side": side,
        "source": source,
        "target": target,
        "relation": relation,
        "required": edge.required,
        "provenance": {"service": service, "side": side},
    }
    return (side, source, target, relation), payload


def _check_candidate(
    check: object, service: str, side: str
) -> Tuple[str, Dict[str, Any]]:
    if not isinstance(check, CheckResult):
        raise _Malformed("check type")
    check_id = _identifier(check.check_id)
    if _SENSITIVE_VALUE.search(check_id):
        raise _Malformed("sensitive check identity")
    if check.status not in _STATUSES:
        raise _Malformed("check status")
    reason = _safe_reason(check.reason, "collector check reason is malformed")
    resource_ids = _string_list(check.resource_ids)
    evidence_ids = _evidence_ids(check.evidence_ids)
    return check_id, {
        "check_id": check_id,
        "status": check.status,
        "reason": reason,
        "resource_ids": resource_ids,
        "evidence_ids": evidence_ids,
        "provenance": {"service": service, "side": side},
    }


def _parse_reference(value: str) -> Tuple[str, str]:
    if ":" not in value:
        raise _Malformed("reference")
    kind, identifier = value.split(":", 1)
    return _identifier(kind), _identifier(identifier)


def _collector_record(result: CollectorResult, service: str, side: str) -> Dict[str, Any]:
    return {
        "service": service,
        "side": side,
        "node_count": len(result.nodes) if isinstance(result.nodes, list) else 0,
        "edge_count": len(result.edges) if isinstance(result.edges, list) else 0,
        "check_count": len(result.checks) if isinstance(result.checks, list) else 0,
        "blocker_count": len(result.blockers) if isinstance(result.blockers, list) else 0,
        "unknown_count": len(result.unknowns) if isinstance(result.unknowns, list) else 0,
    }


def assemble_graph(results: Iterable[CollectorResult]) -> Dict[str, Any]:
    """Merge collectors without mutating them or trusting their payload types."""
    assembly_checks: List[Dict[str, Any]] = []
    collectors: List[Dict[str, Any]] = []
    node_groups: MutableMapping[Tuple[str, str, str], List[Dict[str, Any]]] = defaultdict(list)
    edge_groups: MutableMapping[Tuple[str, str, str, str], List[Dict[str, Any]]] = defaultdict(list)
    check_groups: MutableMapping[str, List[Dict[str, Any]]] = defaultdict(list)

    try:
        materialized_results = list(islice(iter(results), _MAX_RESULTS + 1))
    except (TypeError, RuntimeError):
        materialized_results = []
        assembly_checks.append(_issue(
            "collectors-malformed", "BLOCKED", "collector result set is malformed"
        ))
    if len(materialized_results) > _MAX_RESULTS:
        materialized_results = []
        assembly_checks.append(_issue(
            "collectors-malformed", "BLOCKED", "collector result set is malformed"
        ))

    for result in materialized_results:
        label = "collector"
        if not isinstance(result, CollectorResult):
            assembly_checks.append(_issue(
                "collector-malformed", "BLOCKED", "collector payload is malformed", label
            ))
            continue
        try:
            service = _identifier(result.service)
            side = _identifier(result.side)
            if side not in _SIDES:
                raise _Malformed("collector side")
            if service.lower() in _EXCLUDED_SERVICES:
                assembly_checks.append(_issue(
                    "collector-out-of-scope", "BLOCKED",
                    "collector is outside discovery scope", f"{side}:{service.lower()}",
                ))
                continue
            nodes = _safe_sequence(result.nodes)
            edges = _safe_sequence(result.edges)
            checks = _safe_sequence(result.checks)
            blockers = _safe_sequence(result.blockers)
            unknowns = _safe_sequence(result.unknowns)
        except _Malformed:
            assembly_checks.append(_issue(
                "collector-malformed", "BLOCKED", "collector payload is malformed", label
            ))
            continue

        collectors.append(_collector_record(result, service, side))
        collector_label = f"{side}:{service}"
        for node in nodes:
            try:
                identity, payload = _node_candidate(node, service, side)
            except _Malformed:
                assembly_checks.append(_issue(
                    "node-malformed", "BLOCKED", "node payload is malformed",
                    collector_label,
                ))
                continue
            node_groups[identity].append(payload)
        for edge in edges:
            try:
                identity, payload = _edge_candidate(edge, service, side)
            except _Malformed:
                assembly_checks.append(_issue(
                    "edge-malformed", "BLOCKED", "edge payload is malformed",
                    collector_label,
                ))
                continue
            edge_groups[identity].append(payload)
        for check in checks:
            try:
                identity, payload = _check_candidate(check, service, side)
            except _Malformed:
                assembly_checks.append(_issue(
                    "check-malformed", "BLOCKED", "check payload is malformed",
                    collector_label,
                ))
                continue
            check_groups[identity].append(payload)
        for status, reasons in (("BLOCKED", blockers), ("UNKNOWN", unknowns)):
            normalized_reasons = sorted({
                _safe_reason(reason, "collector failure reason is malformed")
                for reason in reasons
            })
            for index, safe in enumerate(normalized_reasons):
                identity = f"collector.{side}.{service}.{status.lower()}.{index}"
                check_groups[identity].append({
                    "check_id": identity,
                    "status": status,
                    "reason": safe,
                    "resource_ids": [],
                    "evidence_ids": [],
                    "provenance": {"service": service, "side": side},
                })

    nodes: List[Dict[str, Any]] = []
    for identity in sorted(node_groups):
        variants = node_groups[identity]
        facts = {_canonical(item["facts"]) for item in variants}
        evidence = {_canonical(item["evidence_ids"]) for item in variants}
        provenance = {_canonical(item["provenance"]) for item in variants}
        label = ":".join(identity)
        if len(facts) > 1:
            assembly_checks.append(_issue(
                "node-facts-conflict", "BLOCKED", "node has conflicting facts", label
            ))
            continue
        if len(evidence) > 1 or len(provenance) > 1:
            assembly_checks.append(_issue(
                "node-provenance-conflict", "BLOCKED",
                "node has conflicting provenance", label,
            ))
            continue
        nodes.append(variants[0])

    edges: List[Dict[str, Any]] = []
    for identity in sorted(edge_groups):
        variants = edge_groups[identity]
        requiredness = {item["required"] for item in variants}
        provenance = {_canonical(item["provenance"]) for item in variants}
        label = "|".join(identity)
        if len(requiredness) > 1:
            assembly_checks.append(_issue(
                "edge-requiredness-conflict", "BLOCKED",
                "edge has conflicting requiredness", label,
            ))
            continue
        if len(provenance) > 1:
            assembly_checks.append(_issue(
                "edge-provenance-conflict", "BLOCKED",
                "edge has conflicting provenance", label,
            ))
            continue
        edges.append(variants[0])

    checks: List[Dict[str, Any]] = []
    for check_id in sorted(check_groups):
        variants = check_groups[check_id]
        signatures = {_canonical(item) for item in variants}
        if len(signatures) > 1:
            assembly_checks.append(_issue(
                "check-definition-conflict", "BLOCKED",
                "check has conflicting definition", check_id,
            ))
            continue
        checks.append(variants[0])

    collectors.sort(key=lambda item: _canonical(item))
    assembly_checks = sorted(
        {_canonical(item): item for item in assembly_checks}.values(),
        key=lambda item: item["check_id"],
    )
    graph: Dict[str, Any] = {
        "schema_version": GRAPH_VERSION,
        "collectors": collectors,
        "nodes": nodes,
        "edges": edges,
        "checks": checks,
        "assembly_checks": assembly_checks,
    }
    graph["graph_sha256"] = hashlib.sha256(
        _canonical(graph).encode("utf-8")
    ).hexdigest()
    return graph


def _dict_check(value: Mapping[str, Any]) -> CheckResult:
    check_id = _identifier(value.get("check_id"))
    status = value.get("status")
    if status not in _STATUSES:
        raise _Malformed("check status")
    reason = _safe_reason(value.get("reason"), "graph check reason is malformed")
    return CheckResult(
        check_id,
        status,
        reason,
        _string_list(value.get("resource_ids", [])),
        _evidence_ids(value.get("evidence_ids", [])),
    )


def _validation_issue(code: str, status: str, reason: str, label: str = "") -> CheckResult:
    return _dict_check(_issue(code, status, reason, label))


def _external_reference_resolves(reference: str, relation: str) -> bool:
    try:
        kind, identifier = _parse_reference(reference)
    except _Malformed:
        return False
    if kind != "external_ref" or "/" not in identifier:
        return False
    reference_type, external_id = identifier.split("/", 1)
    return (
        bool(external_id)
        and reference_type in EXTERNAL_REFERENCE_POLICY
        and relation in EXTERNAL_REFERENCE_POLICY[reference_type]
    )


def validate_graph(graph: Mapping[str, Any]) -> List[CheckResult]:
    """Validate a graph defensively and return deterministic integrity checks."""
    issues: List[CheckResult] = []
    check_provenances: List[Tuple[int, Tuple[str, str]]] = []
    if not isinstance(graph, Mapping):
        return [_validation_issue(
            "schema-malformed", "BLOCKED", "resource graph payload is malformed"
        )]

    try:
        if graph.get("schema_version") != GRAPH_VERSION:
            raise _Malformed("schema version")
        collectors = _safe_sequence(graph.get("collectors"))
        nodes = _safe_sequence(graph.get("nodes"))
        edges = _safe_sequence(graph.get("edges"))
        checks = _safe_sequence(graph.get("checks"))
        assembly_checks = _safe_sequence(graph.get("assembly_checks"))
    except _Malformed:
        # Direct callers may supply an unversioned graph.  Inspect each section
        # below where possible, but always fail closed.
        issues.append(_validation_issue(
            "schema-malformed", "BLOCKED", "resource graph payload is malformed"
        ))
        collectors = graph.get("collectors") if isinstance(graph.get("collectors"), list) else []
        nodes = graph.get("nodes") if isinstance(graph.get("nodes"), list) else []
        edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
        checks = graph.get("checks") if isinstance(graph.get("checks"), list) else []
        assembly_checks = graph.get("assembly_checks") if isinstance(graph.get("assembly_checks"), list) else []

    for index, payload in enumerate(assembly_checks):
        try:
            if not isinstance(payload, Mapping):
                raise _Malformed("check mapping")
            issues.append(_dict_check(payload))
        except _Malformed:
            issues.append(_validation_issue(
                "stored-check-malformed", "BLOCKED", "stored graph check is malformed",
                str(index),
            ))
    for index, payload in enumerate(checks):
        try:
            if not isinstance(payload, Mapping):
                raise _Malformed("check mapping")
            provenance = payload.get("provenance")
            if not isinstance(provenance, Mapping):
                raise _Malformed("check provenance")
            side = _identifier(provenance.get("side"))
            if side not in _SIDES:
                raise _Malformed("check side")
            normalized_provenance = _provenance(provenance, side)
            check_provenances.append(
                (index, (side, normalized_provenance["service"]))
            )
            issues.append(_dict_check(payload))
        except _Malformed:
            issues.append(_validation_issue(
                "stored-check-malformed", "BLOCKED", "stored graph check is malformed",
                str(index),
            ))

    node_keys = set()
    for index, node in enumerate(nodes):
        try:
            if not isinstance(node, Mapping):
                raise _Malformed("node mapping")
            side = _identifier(node.get("side"))
            kind = _identifier(node.get("kind"))
            identifier = _identifier(node.get("id"))
            if side not in _SIDES or node.get("key") not in {None, f"{kind}:{identifier}"}:
                raise _Malformed("node identity")
            _normalize_tree(node.get("facts", {}))
            _evidence_ids(node.get("evidence_ids", []))
            _provenance(node.get("provenance"), side)
            key = (side, kind, identifier)
            if key in node_keys:
                issues.append(_validation_issue(
                    "duplicate-node", "BLOCKED", "graph node identity is duplicated",
                    f"{side}:{kind}:{identifier}",
                ))
            node_keys.add(key)
        except _Malformed:
            issues.append(_validation_issue(
                "stored-node-malformed", "BLOCKED", "stored graph node is malformed",
                str(index),
            ))

    for index, edge in enumerate(edges):
        try:
            if not isinstance(edge, Mapping) or not isinstance(edge.get("required"), bool):
                raise _Malformed("edge mapping")
            side = _identifier(edge.get("side"))
            source = _identifier(edge.get("source"))
            target = _identifier(edge.get("target"))
            relation = _identifier(edge.get("relation"))
            if side not in _SIDES:
                raise _Malformed("edge side")
            _provenance(edge.get("provenance"), side)
            source_kind, source_id = _parse_reference(source)
            target_kind, target_id = _parse_reference(target)
            endpoints = (
                ("source", source, (side, source_kind, source_id)),
                ("target", target, (side, target_kind, target_id)),
            )
            for endpoint_name, reference, identity in endpoints:
                if identity in node_keys or _external_reference_resolves(reference, relation):
                    continue
                required = edge["required"]
                issues.append(CheckResult(
                    _issue(
                        f"edge-{endpoint_name}-unresolved", "UNKNOWN" if required else "WARN",
                        ("required edge " if required else "optional edge ")
                        + f"{endpoint_name} is unresolved",
                        f"{side}|{source}|{target}|{relation}",
                    )["check_id"],
                    "UNKNOWN" if required else "WARN",
                    ("required edge " if required else "optional edge ")
                    + f"{endpoint_name} is unresolved",
                    [f"{side}:{reference}"],
                ))
        except _Malformed:
            issues.append(_validation_issue(
                "stored-edge-malformed", "BLOCKED", "stored graph edge is malformed",
                str(index),
            ))

    collector_keys: List[Tuple[str, str]] = []
    empty_collectors = set()
    for index, record in enumerate(collectors):
        try:
            if not isinstance(record, Mapping):
                raise _Malformed("collector record")
            side = _identifier(record.get("side"))
            service = _identifier(record.get("service"))
            if side not in _SIDES:
                raise _Malformed("collector side")
            counts = []
            for name in ("node_count", "edge_count", "check_count", "blocker_count", "unknown_count"):
                count = record.get(name)
                if not isinstance(count, int) or isinstance(count, bool) or count < 0 or count > _MAX_ITEMS:
                    raise _Malformed("collector count")
                counts.append(count)
            collector_keys.append((side, service))
            if sum(counts) == 0:
                empty_collectors.add((side, service))
        except _Malformed:
            issues.append(_validation_issue(
                "stored-collector-malformed", "BLOCKED",
                "stored collector provenance is malformed", str(index),
            ))

    counts = Counter(collector_keys)
    for index, provenance_key in check_provenances:
        if provenance_key not in counts:
            issues.append(_validation_issue(
                "stored-check-malformed", "BLOCKED", "stored graph check is malformed",
                str(index),
            ))
    for side, service in REQUIRED_COLLECTORS:
        count = counts[(side, service)]
        label = f"{side}:{service}"
        if count == 0:
            issues.append(_validation_issue(
                "collector-missing", "UNKNOWN", "required collector is missing", label
            ))
        elif count > 1:
            issues.append(_validation_issue(
                "collector-duplicate", "UNKNOWN", "required collector is duplicated", label
            ))
        elif (side, service) in empty_collectors:
            issues.append(_validation_issue(
                "collector-empty", "UNKNOWN", "required collector returned no evidence", label
            ))

    candidate_hash = graph.get("graph_sha256")
    hash_payload = {
        "schema_version": graph.get("schema_version"),
        "collectors": collectors,
        "nodes": nodes,
        "edges": edges,
        "checks": checks,
        "assembly_checks": assembly_checks,
    }
    try:
        expected_hash = hashlib.sha256(
            _canonical(hash_payload).encode("utf-8")
        ).hexdigest()
    except (TypeError, ValueError, RecursionError):
        expected_hash = None
    if not isinstance(candidate_hash, str) or candidate_hash != expected_hash:
        issues.append(_validation_issue(
            "hash-mismatch", "BLOCKED", "graph integrity hash mismatch"
        ))

    unique = {_canonical(item.to_dict()): item for item in issues}
    return sorted(unique.values(), key=lambda item: item.check_id)
