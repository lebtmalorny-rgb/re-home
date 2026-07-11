#!/usr/bin/env python3
"""Assemble control/runtime results and render a fail-closed readiness report."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from live_discovery.contract import CheckResult, CollectorResult, DependencyEdge, ResourceNode
from live_discovery.graph import assemble_graph
from live_discovery.render import write_artifacts
from live_discovery.schema import SchemaColumn, SchemaSnapshot, build_directional_mapping
from live_discovery.verdict import compute_verdict


BUNDLE_VERSION = "openstack-rehome-control-bundle/v1alpha1"
_MAX_FILE = 8 * 1024 * 1024
_MAX_COLLECTORS = 128
_MAX_ITEMS = 100_000


def _has_symlink_component(path):
    absolute = Path(path).absolute()
    return any(candidate.is_symlink() and candidate.parent != Path("/") for candidate in (absolute, *absolute.parents))


def _read_json(path: Path):
    path = Path(path)
    if _has_symlink_component(path) or not path.is_file():
        raise ValueError("input file is unavailable")
    if path.stat().st_size > _MAX_FILE:
        raise ValueError("input file exceeds safety bounds")
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def _strings(value, limit=4096):
    if not isinstance(value, list) or len(value) > limit or not all(isinstance(item, str) for item in value):
        raise ValueError("invalid string list")
    return list(value)


def _collector(payload):
    allowed = {"schema_version", "service", "side", "nodes", "edges", "checks", "unknowns", "blockers", "evidence"}
    if not isinstance(payload, dict) or set(payload) != allowed:
        raise ValueError("collector envelope is invalid")
    if payload["schema_version"] != "openstack-rehome-live-discovery/v1alpha1":
        raise ValueError("collector version is invalid")
    result = CollectorResult(service=payload["service"], side=payload["side"])
    if any(not isinstance(payload[name], list) or len(payload[name]) > _MAX_ITEMS for name in ("nodes", "edges", "checks", "unknowns", "blockers", "evidence")):
        raise ValueError("collector payload exceeds safety bounds")
    for node in payload["nodes"]:
        if not isinstance(node, dict) or set(node) != {"kind", "id", "side", "facts", "evidence_ids", "key"} or node["key"] != f"{node['kind']}:{node['id']}":
            raise ValueError("collector node is invalid")
        result.nodes.append(ResourceNode(node["kind"], node["id"], node["side"], node["facts"], _strings(node["evidence_ids"])))
    for edge in payload["edges"]:
        if not isinstance(edge, dict) or set(edge) != {"source", "target", "relation", "required"} or not isinstance(edge["required"], bool):
            raise ValueError("collector edge is invalid")
        result.edges.append(DependencyEdge(edge["source"], edge["target"], edge["relation"], edge["required"]))
    for check in payload["checks"]:
        if not isinstance(check, dict) or set(check) != {"check_id", "status", "reason", "resource_ids", "evidence_ids"}:
            raise ValueError("collector check is invalid")
        result.checks.append(CheckResult(check["check_id"], check["status"], check["reason"], _strings(check["resource_ids"]), _strings(check["evidence_ids"])))
    result.unknowns = _strings(payload["unknowns"])
    result.blockers = _strings(payload["blockers"])
    if not isinstance(payload["evidence"], list):
        raise ValueError("collector evidence is invalid")
    result.evidence = payload["evidence"]
    return result


def _bundle(path: Path):
    payload = _read_json(path)
    if isinstance(payload, dict) and payload.get("schema_version") == "openstack-rehome-live-discovery/v1alpha1":
        if not isinstance(payload.get("evidence"), list) or not payload["evidence"]:
            raise ValueError("raw runtime evidence is missing")
        empty_bundle = {
            "schema_version": BUNDLE_VERSION,
            "collectors": [payload],
            "checks": [],
            "schema_capabilities": {},
            "uuid_filters": {"source": {}, "target": {}},
            "evidence_index": payload["evidence"],
            "sensitive_evidence": {},
        }
        return [_collector(payload)], [], empty_bundle
    allowed = {"schema_version", "collectors", "checks", "schema_capabilities", "uuid_filters", "evidence_index", "sensitive_evidence"}
    if not isinstance(payload, dict) or set(payload) != allowed or payload.get("schema_version") != BUNDLE_VERSION:
        raise ValueError("control bundle is invalid")
    if not isinstance(payload["collectors"], list) or len(payload["collectors"]) > _MAX_COLLECTORS:
        raise ValueError("collector set exceeds safety bounds")
    checks = []
    for item in payload["checks"]:
        if not isinstance(item, dict) or set(item) != {"check_id", "status", "reason", "resource_ids", "evidence_ids"}:
            raise ValueError("readiness check is invalid")
        checks.append(CheckResult(item["check_id"], item["status"], item["reason"], _strings(item["resource_ids"]), _strings(item["evidence_ids"])))
    return [_collector(item) for item in payload["collectors"]], checks, payload


_ROLE_REQUIREMENTS = {
    "source-control": {
        ("source", "nova"), ("source", "neutron"),
        ("source", "cinder"), ("source", "glance"),
    },
    "target-control": {
        ("target", "target-profile"), ("target", "runtime-capabilities"),
        ("target", "neutron"), ("target", "cinder"),
        ("target", "glance"),
    },
    "runtime": {("source", "runtime")},
}


def _validate_role(collectors, role):
    expected = _ROLE_REQUIREMENTS[role]
    actual = [(result.side, result.service) for result in collectors]
    if len(actual) != len(set(actual)) or set(actual) != expected:
        raise ValueError(f"{role} artifact role is invalid")


def _validate_evidence_entry(entry):
    common = {"evidence_id", "kind", "side", "service"}
    shapes = {
        "openstack-json": common | {"command"},
        "runtime-command": common | {"command"},
        "db-jsonl": common | {"schema", "table", "filters"},
        "storage-probe": common | {"resource_id", "backend_kind", "backend_identity", "resource_identity", "resource_fingerprint", "scope", "expected_size", "observed_size", "status"},
        "glance-range": common | {"resource_id", "endpoint_origin", "expected_size", "observed_size", "required", "store_ids", "status"},
        "cinder-connection": common | {"volume_id", "attachment_id", "backend_kind", "backend_id", "resource_identity", "resource_fingerprint"},
    }
    if not isinstance(entry, dict) or entry.get("kind") not in shapes or set(entry) != shapes.get(entry.get("kind"), set()):
        raise ValueError("evidence index entry schema is invalid")
    if not all(isinstance(entry.get(key), str) and entry[key] for key in ("evidence_id", "side", "service")) or entry["side"] not in {"source", "target"}:
        raise ValueError("evidence index provenance is invalid")
    if entry["kind"] in {"openstack-json", "runtime-command"}:
        if not isinstance(entry["command"], list) or not entry["command"] or not all(isinstance(value, str) and value for value in entry["command"]):
            raise ValueError("evidence command is invalid")
    elif entry["kind"] == "db-jsonl":
        if not all(isinstance(entry[key], str) and entry[key] for key in ("schema", "table")) or not isinstance(entry["filters"], dict) or not entry["filters"]:
            raise ValueError("DB evidence is invalid")
    elif entry["kind"] == "storage-probe":
        if entry["scope"] not in {"source-compute", "target-storage"} or entry["status"] not in {"PASS", "WARN", "UNKNOWN", "BLOCKED"} or not isinstance(entry["expected_size"], int) or (entry["observed_size"] is not None and not isinstance(entry["observed_size"], int)) or (entry["status"] == "PASS" and entry["observed_size"] != entry["expected_size"]):
            raise ValueError("storage evidence is invalid")
    elif entry["kind"] == "glance-range":
        if entry["status"] not in {"PASS", "WARN", "UNKNOWN", "BLOCKED"} or not isinstance(entry["required"], bool) or not isinstance(entry["expected_size"], int) or (entry["observed_size"] is not None and not isinstance(entry["observed_size"], int)) or (entry["status"] == "PASS" and entry["observed_size"] != entry["expected_size"]) or not isinstance(entry["store_ids"], list) or not entry["store_ids"]:
            raise ValueError("Glance evidence is invalid")
    elif entry["kind"] == "cinder-connection":
        if not all(isinstance(entry[key], str) and entry[key] for key in ("volume_id", "attachment_id", "backend_kind", "backend_id", "resource_identity", "resource_fingerprint")):
            raise ValueError("Cinder connection evidence is invalid")


def _validate_evidence_closure(collectors, checks, bundle):
    entries = bundle.get("evidence_index")
    if not isinstance(entries, list):
        raise ValueError("evidence index is invalid")
    by_id = {}
    for entry in entries:
        _validate_evidence_entry(entry)
        identity = entry["evidence_id"]
        if identity in by_id:
            raise ValueError("evidence identity is duplicated")
        by_id[identity] = entry
    for result in collectors:
        for item in [*result.nodes, *result.checks]:
            for evidence_id in item.evidence_ids:
                entry = by_id.get(evidence_id)
                if entry is None:
                    raise ValueError("graph evidence is missing")
                if entry["side"] != result.side or entry["service"] != result.service:
                    raise ValueError("graph evidence provenance conflicts")
    for check in checks:
        for evidence_id in check.evidence_ids:
            if evidence_id not in by_id:
                raise ValueError("readiness evidence is missing")


def _fixture_paths(directory: Path):
    directory = Path(directory)
    if _has_symlink_component(directory) or not directory.is_dir():
        raise ValueError("fixture directory is unavailable")
    policy = directory / "schema-policy.json"
    if not policy.exists():
        policy = directory.parent / "schema-policy.json"
    ready = directory.parent / "ready"
    role_paths = []
    for name in ("source-control.json", "target-control.json", "runtime.json"):
        candidate = directory / name
        if not candidate.exists():
            candidate = ready / name
        role_paths.append(candidate)
    return [*role_paths, policy, directory / "status.json"]


def _directional_mapping(policy, capabilities):
    if not isinstance(policy, dict):
        raise ValueError("schema policy is invalid")
    if policy.get("schema_version") == "openstack-rehome-directional-schema-mapping/v1alpha1":
        return policy
    if policy.get("schema_version") != "openstack-rehome-schema-policy/v1alpha1":
        raise ValueError("schema policy version is invalid")

    snapshots = {}
    used_columns = {}
    for side in ("source", "target"):
        payload = capabilities.get("services", {}).get(f"{side}-information-schema")
        if not isinstance(payload, dict) or set(payload) != {"tables", "used_columns"} or not isinstance(payload["tables"], dict) or not isinstance(payload["used_columns"], dict):
            raise ValueError("live information_schema capability is missing")
        tables = {}
        for table, columns in payload["tables"].items():
            if not isinstance(table, str) or not isinstance(columns, dict):
                raise ValueError("live information_schema capability is invalid")
            tables[table] = {}
            for name, definition in columns.items():
                if not isinstance(definition, dict) or set(definition) != {"name", "ordinal", "column_type", "nullable", "default", "extra"} or definition.get("name") != name:
                    raise ValueError("live SchemaColumn is invalid")
                tables[table][name] = SchemaColumn(**definition)
        snapshots[side] = SchemaSnapshot(tables=tables)
        for table, columns in payload["used_columns"].items():
            if not isinstance(table, str) or not isinstance(columns, list) or not columns or not all(isinstance(column, str) for column in columns):
                raise ValueError("used schema columns are invalid")
            used_columns.setdefault(table, set()).update(columns)
    if not used_columns:
        raise ValueError("used schema columns are missing")
    return build_directional_mapping(
        snapshots["source"], snapshots["target"],
        {table: sorted(columns) for table, columns in sorted(used_columns.items())},
        policy,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description="Assemble read-only live discovery")
    parser.add_argument("--source-control", type=Path)
    parser.add_argument("--target-control", type=Path)
    parser.add_argument("--runtime", type=Path)
    parser.add_argument("--schema-policy", type=Path)
    parser.add_argument("--fixture-dir", type=Path)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    live = (args.source_control, args.target_control, args.runtime, args.schema_policy)
    if args.fixture_dir is not None and any(item is not None for item in live):
        parser.error("--fixture-dir is mutually exclusive with live inputs")
    if args.fixture_dir is None and not all(item is not None for item in live):
        parser.error("all live inputs are required")
    try:
        if args.fixture_dir is not None:
            fixture_paths = _fixture_paths(args.fixture_dir)
            role_paths = list(zip(fixture_paths[:3], ("source-control", "target-control", "runtime")))
            mapping_path = fixture_paths[3]
            fixture_status_path = fixture_paths[4]
        else:
            role_paths = [
                (args.source_control, "source-control"),
                (args.target_control, "target-control"),
                (args.runtime, "runtime"),
            ]
            mapping_path = args.schema_policy
            fixture_status_path = None
        collectors = []
        checks = []
        bundles = []
        for path, role in role_paths:
            new_collectors, new_checks, bundle = _bundle(path)
            _validate_role(new_collectors, role)
            _validate_evidence_closure(new_collectors, new_checks, bundle)
            collectors.extend(new_collectors)
            checks.extend(new_checks)
            bundles.append(bundle)
        if fixture_status_path is not None and fixture_status_path.exists():
            status_payload = _read_json(fixture_status_path)
            if not isinstance(status_payload, dict) or set(status_payload) != {"status", "reason"} or status_payload["status"] not in {"PASS", "WARN", "UNKNOWN", "BLOCKED"} or not isinstance(status_payload["reason"], str):
                raise ValueError("fixture status is invalid")
            checks.append(CheckResult("fixture.aggregate", status_payload["status"], status_payload["reason"]))
        policy = _read_json(mapping_path)
        capabilities = {"schema_version": "openstack-rehome-schema-capabilities/v1alpha1", "services": {}}
        filters = {"schema_version": "openstack-rehome-uuid-filters/v1alpha1", "source": {}, "target": {}}
        entries = []
        sensitive = {}
        for bundle in bundles:
            side_caps = bundle["schema_capabilities"]
            if not isinstance(side_caps, dict):
                raise ValueError("schema capabilities are invalid")
            for service, service_capabilities in side_caps.items():
                if service in capabilities["services"] and capabilities["services"][service] != service_capabilities:
                    raise ValueError("schema capability identity conflicts")
                capabilities["services"][service] = service_capabilities
            side_filters = bundle["uuid_filters"]
            if not isinstance(side_filters, dict):
                raise ValueError("UUID filters are invalid")
            for side in ("source", "target"):
                value = side_filters.get(side, {})
                if not isinstance(value, dict):
                    raise ValueError("UUID filters are invalid")
                for identity, scoped_filter in value.items():
                    if identity in filters[side] and filters[side][identity] != scoped_filter:
                        raise ValueError("UUID filter identity conflicts")
                    filters[side][identity] = scoped_filter
            if not isinstance(bundle["evidence_index"], list) or not isinstance(bundle["sensitive_evidence"], dict):
                raise ValueError("evidence is invalid")
            entries.extend(bundle["evidence_index"])
            for key, value in bundle["sensitive_evidence"].items():
                if key in sensitive:
                    raise ValueError("sensitive evidence identity is duplicated")
                sensitive[key] = value
        entries.sort(key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
        evidence_ids = [item.get("evidence_id") for item in entries if isinstance(item, dict)]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("evidence index identity is duplicated")
        mapping = _directional_mapping(policy, capabilities)
        graph = assemble_graph(collectors)
        verdict = compute_verdict(graph, checks, mapping)
        evidence = {"uuid_filters": filters, "index": {"schema_version": "openstack-rehome-evidence-index/v1alpha1", "entries": entries}, "sensitive": sensitive}
        write_artifacts(args.out_dir, graph, verdict, capabilities, mapping, evidence)
        print(f"VERDICT={verdict['verdict']} EXIT_CODE={verdict['exit_code']}")
        return verdict["exit_code"]
    except (OSError, ValueError, TypeError, json.JSONDecodeError, RecursionError):
        print("live discovery input rejected", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
