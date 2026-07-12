"""Bind protected probe plans to the authoritative typed backend inventory."""

from copy import deepcopy
import argparse
from datetime import datetime
import hashlib
import hmac
import json
from pathlib import Path
import re
import shutil
import tempfile


_SUPPORTED = {"nfs": "nfs", "file": "nfs", "rbd": "rbd", "lvm": "lvm"}
_BACKEND_KEYS = {"kind", "source_delegate", "target_delegate", "allowed_scopes", "probe_template"}
_PHASE_FILES = ("api-result.json", "uuid-filters.json", "db-query-plan.json")
_DELEGATE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,252}$")
_PROBE_RESULT_KEYS = {
    "storage_probe_results", "glance_data_probe_results",
    "glance_store_capabilities",
}
_EVIDENCE_METADATA_KEYS = {
    "observed_at", "returncode", "failure_class", "stderr_sha256",
    "raw_artifact_ref",
}


def _canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _phase_id(side, delegate):
    return hashlib.sha256(f"{side}\0{delegate}".encode("utf-8")).hexdigest()


def _binding(api_result, uuid_filters, query_plan, key):
    if not isinstance(key, bytes) or len(key) < 16:
        raise ValueError("phase trust anchor is invalid")
    payload = {
        "api_result": api_result,
        "uuid_filters": uuid_filters,
        "db_query_plan": query_plan,
    }
    return hmac.new(
        key,
        ("openstack-rehome-phase:live:v1\n" + _canonical(payload)).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _plan(value, side, range_enabled):
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != "openstack-rehome-probe-config/v1alpha1"
        or not isinstance(value.get("storage"), list)
        or not isinstance(value.get("glance"), dict)
        or value["glance"].get("token_env") != "LIVE_DISCOVERY_GLANCE_TOKEN"
        or not isinstance(value["glance"].get("images"), list)
    ):
        raise ValueError(f"{side} probe plan is invalid")
    if not range_enabled and value["glance"]["images"]:
        raise ValueError(f"{side} Glance range plan is disabled")
    return value


def validate_probe_contract(
    backends, source_plan, target_plan, range_enabled,
    source_controller, target_controller, inventory_hosts,
):
    if not isinstance(backends, dict) or not isinstance(range_enabled, bool):
        raise ValueError("backend contract is invalid")
    hosts = set(inventory_hosts)
    source = _plan(source_plan, "source", range_enabled)
    target = _plan(target_plan, "target", range_enabled)
    normalized = {}
    for backend_id, item in backends.items():
        if not isinstance(backend_id, str) or not backend_id or not isinstance(item, dict) or set(item) != _BACKEND_KEYS:
            raise ValueError("typed backend is invalid")
        kind = item["kind"]
        expected_template = _SUPPORTED.get(kind, "unsupported")
        if (
            not isinstance(kind, str) or not kind
            or item["probe_template"] != expected_template
            or sorted(item["allowed_scopes"]) != ["source-compute", "target-storage"]
            or item["source_delegate"] not in hosts
            or item["target_delegate"] not in hosts
        ):
            raise ValueError("typed backend policy is invalid")
        normalized[backend_id] = deepcopy(item)
    for side, plan, expected_scope in (
        ("source", source, "source-compute"),
        ("target", target, "target-storage"),
    ):
        for probe in plan["storage"]:
            if not isinstance(probe, dict):
                raise ValueError(f"{side} storage probe is invalid")
            backend_id = probe.get("backend_id")
            backend = normalized.get(backend_id)
            if (
                backend is None
                or probe.get("kind") != backend["kind"]
                or probe.get("scope") != expected_scope
                or expected_scope not in backend["allowed_scopes"]
            ):
                raise ValueError(f"{side} storage probe conflicts with inventory")
    if not normalized and (source["storage"] or target["storage"]):
        raise ValueError("empty backend inventory cannot authorize storage probes")

    def groups(side, plan, controller):
        delegate_key = f"{side}_delegate"
        delegates = sorted({item[delegate_key] for item in normalized.values()})
        if not delegates:
            delegates = [controller]
        grouped = []
        for delegate in delegates:
            storage = [
                deepcopy(probe) for probe in plan["storage"]
                if normalized[probe["backend_id"]][delegate_key] == delegate
            ]
            grouped.append({
                "delegate": delegate,
                "phase_id": _phase_id(side, delegate),
                "backend_ids": sorted({probe["backend_id"] for probe in storage}),
                "probe_plan": {
                    "schema_version": plan["schema_version"],
                    "storage": storage,
                    "glance": deepcopy(plan["glance"]),
                },
            })
        return grouped

    source_groups = groups("source", source, source_controller)
    target_groups = groups("target", target, target_controller)
    return {
        "source_delegates": [item["delegate"] for item in source_groups],
        "target_delegates": [item["delegate"] for item in target_groups],
        "source_groups": source_groups,
        "target_groups": target_groups,
        "source_phase_manifest": [
            {"delegate": item["delegate"], "phase_id": item["phase_id"]}
            for item in source_groups
        ],
        "target_phase_manifest": [
            {"delegate": item["delegate"], "phase_id": item["phase_id"]}
            for item in target_groups
        ],
        "backend_kinds": sorted({item["kind"] for item in normalized.values()}),
        "supported": {
            key: value["probe_template"] != "unsupported"
            for key, value in sorted(normalized.items())
        },
    }


def _phase_document(value, side, schema_version, payload_key):
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "side", payload_key, "binding_sha256"}
        or value.get("schema_version") != schema_version
        or value.get("side") != side
        or not isinstance(value.get(payload_key), (dict, list))
        or not isinstance(value.get("binding_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", value["binding_sha256"]) is None
    ):
        raise ValueError("delegate phase envelope is invalid")
    return {key: deepcopy(item) for key, item in value.items() if key != "binding_sha256"}


def merge_probe_documents(side, key, phases):
    if side not in {"source", "target"} or not isinstance(phases, list) or not phases:
        raise ValueError("delegate phase set is invalid")
    ordered = sorted(phases, key=lambda item: item.get("delegate", "") if isinstance(item, dict) else "")
    delegates = [item.get("delegate") for item in ordered if isinstance(item, dict)]
    if (
        len(delegates) != len(ordered)
        or len(delegates) != len(set(delegates))
        or any(not isinstance(delegate, str) or _DELEGATE.fullmatch(delegate) is None for delegate in delegates)
    ):
        raise ValueError("delegate identity is invalid")

    common_api = None
    common_filters = None
    common_plan = None
    common_glance = None
    common_stores = None
    storage = []
    evidence_ids = set()
    provenance = []
    observed_timestamps = []
    glance_acquisitions = {}
    for phase in ordered:
        delegate = phase["delegate"]
        if phase.get("phase_id") != _phase_id(side, delegate):
            raise ValueError("delegate phase identity is invalid")
        api = phase.get("api-result.json")
        filters = phase.get("uuid-filters.json")
        plan = phase.get("db-query-plan.json")
        api_base = _phase_document(
            api, side, "openstack-rehome-control-api-result/v1alpha1", "api_result",
        )
        filters_base = _phase_document(
            filters, side, "openstack-rehome-uuid-filters/v1alpha1", "filters",
        )
        plan_base = _phase_document(
            plan, side, "openstack-rehome-db-query-plan/v1alpha1", "queries",
        )
        expected_binding = _binding(api_base, filters_base, plan_base, key)
        if {
            api["binding_sha256"], filters["binding_sha256"],
            plan["binding_sha256"],
        } != {expected_binding}:
            raise ValueError("delegate phase binding is invalid")

        api_payload = deepcopy(api_base["api_result"])
        if "probe_delegate_provenance" in api_payload:
            raise ValueError("nested probe delegate provenance is forbidden")
        probe_values = {
            name: api_payload.pop(name, []) for name in sorted(_PROBE_RESULT_KEYS)
        }
        phase_observed_at = api_payload.pop("observed_at", None)
        try:
            parsed_observed_at = datetime.fromisoformat(
                phase_observed_at.replace("Z", "+00:00")
            )
        except (AttributeError, ValueError):
            raise ValueError("delegate phase timestamp is invalid") from None
        if parsed_observed_at.tzinfo is None:
            raise ValueError("delegate phase timestamp is invalid")
        observed_timestamps.append((parsed_observed_at, phase_observed_at))
        semantic_glance = []
        for item in probe_values["glance_data_probe_results"]:
            if not isinstance(item, dict) or not _EVIDENCE_METADATA_KEYS.issubset(item):
                raise ValueError("delegate Glance evidence metadata is invalid")
            evidence_id = item.get("evidence_id")
            if not isinstance(evidence_id, str) or not evidence_id:
                raise ValueError("delegate Glance evidence identity is invalid")
            semantic_glance.append({
                key: deepcopy(value) for key, value in item.items()
                if key not in _EVIDENCE_METADATA_KEYS and key != "delegate_provenance"
            })
            glance_acquisitions.setdefault(evidence_id, []).append({
                "metadata": {
                    key: deepcopy(item[key]) for key in _EVIDENCE_METADATA_KEYS
                },
                "delegate": delegate,
                "phase_id": phase["phase_id"],
                "phase_binding_sha256": expected_binding,
                "observed_at": phase_observed_at,
            })
        if not all(isinstance(value, list) for value in probe_values.values()):
            raise ValueError("delegate probe result is invalid")
        if common_api is None:
            common_api = api_payload
            common_filters = filters_base
            common_plan = plan_base
            common_glance = semantic_glance
            common_stores = probe_values["glance_store_capabilities"]
        elif (
            api_payload != common_api
            or filters_base != common_filters
            or plan_base != common_plan
            or semantic_glance != common_glance
            or probe_values["glance_store_capabilities"] != common_stores
        ):
            raise ValueError("delegate phases do not share one API and query scope")

        phase_evidence_ids = []
        phase_provenance = {
            "delegate": delegate,
            "phase_id": phase["phase_id"],
            "phase_binding_sha256": expected_binding,
            "observed_at": phase_observed_at,
        }
        for item in probe_values["storage_probe_results"]:
            evidence_id = item.get("evidence_id") if isinstance(item, dict) else None
            if (
                not isinstance(evidence_id, str) or not evidence_id
                or evidence_id in evidence_ids
            ):
                raise ValueError("delegate storage evidence identity is invalid")
            evidence_ids.add(evidence_id)
            phase_evidence_ids.append(evidence_id)
            if not _EVIDENCE_METADATA_KEYS.issubset(item):
                raise ValueError("delegate storage evidence metadata is invalid")
            storage.append({
                **deepcopy(item),
                "delegate_provenance": [deepcopy(phase_provenance)],
            })
        glance_evidence_ids = []
        for item in probe_values["glance_data_probe_results"]:
            evidence_id = item.get("evidence_id") if isinstance(item, dict) else None
            if not isinstance(evidence_id, str) or not evidence_id:
                raise ValueError("delegate Glance evidence identity is invalid")
            glance_evidence_ids.append(evidence_id)
        provenance.append({
            "delegate": delegate,
            "phase_id": phase["phase_id"],
            "phase_binding_sha256": expected_binding,
            "storage_evidence_ids": sorted(phase_evidence_ids),
            "glance_evidence_ids": sorted(glance_evidence_ids),
            "observed_at": phase_observed_at,
        })

    merged_api_base = deepcopy(common_api)
    merged_api_base["observed_at"] = max(observed_timestamps)[1]
    merged_api_base["storage_probe_results"] = sorted(
        storage, key=lambda item: item["evidence_id"],
    )
    merged_glance = []
    for item in common_glance:
        evidence_id = item["evidence_id"]
        acquisitions = glance_acquisitions.get(evidence_id, [])
        if len(acquisitions) != len(ordered):
            raise ValueError("delegate Glance acquisition set is incomplete")
        latest = max(
            acquisitions,
            key=lambda value: datetime.fromisoformat(
                value["metadata"]["observed_at"].replace("Z", "+00:00")
            ),
        )
        merged_glance.append({
            **deepcopy(item),
            **deepcopy(latest["metadata"]),
            "delegate_provenance": [
                {
                    key: deepcopy(acquisition[key])
                    for key in (
                        "delegate", "phase_id", "phase_binding_sha256",
                        "observed_at",
                    )
                }
                for acquisition in sorted(
                    acquisitions, key=lambda value: value["delegate"]
                )
            ],
        })
    merged_api_base["glance_data_probe_results"] = merged_glance
    merged_api_base["glance_store_capabilities"] = deepcopy(common_stores)
    merged_api_base["probe_delegate_provenance"] = provenance
    api_base = {
        "schema_version": "openstack-rehome-control-api-result/v1alpha1",
        "side": side,
        "api_result": merged_api_base,
    }
    binding = _binding(api_base, common_filters, common_plan, key)
    return {
        "api-result.json": {**api_base, "binding_sha256": binding},
        "uuid-filters.json": {**common_filters, "binding_sha256": binding},
        "db-query-plan.json": {**common_plan, "binding_sha256": binding},
    }


def _read_phase_file(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("delegate phase file is unsafe")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("delegate phase file is invalid") from error


def merge_probe_phases(side, key, phases, output, phase_root=None):
    documents = []
    for phase in phases:
        if not isinstance(phase, dict) or set(phase) not in (
            {"delegate", "phase_id"}, {"delegate", "phase_id", "directory"},
        ):
            raise ValueError("delegate phase path is invalid")
        if "directory" in phase:
            if phase_root is not None:
                raise ValueError("delegate phase root is ambiguous")
            directory = Path(phase["directory"])
        else:
            if phase_root is None:
                raise ValueError("delegate phase root is missing")
            directory = Path(phase_root) / phase["phase_id"]
        documents.append({
            "delegate": phase["delegate"],
            "phase_id": phase["phase_id"],
            **{name: _read_phase_file(directory / name) for name in _PHASE_FILES},
        })
    merged = merge_probe_documents(side, key, documents)
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError("merged phase output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=output.parent))
    try:
        for name in _PHASE_FILES:
            target = staging / name
            target.write_text(_canonical(merged[name]) + "\n", encoding="utf-8")
            target.chmod(0o640)
        staging.rename(output)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main(argv=None):
    selector = argparse.ArgumentParser(add_help=False)
    selector.add_argument("operation", nargs="?")
    selected, _ = selector.parse_known_args(argv)
    if selected.operation == "merge-phases":
        parser = argparse.ArgumentParser(description="Merge HMAC-bound delegate probe phases")
        parser.add_argument("operation", choices=("merge-phases",))
        parser.add_argument("--side", choices=("source", "target"), required=True)
        parser.add_argument("--phase-key-file", required=True, type=Path)
        parser.add_argument("--phases-json", required=True)
        parser.add_argument("--phase-root", type=Path)
        parser.add_argument("--out", required=True, type=Path)
        args = parser.parse_args(argv)
        if args.phase_key_file.is_symlink() or not args.phase_key_file.is_file():
            raise ValueError("phase trust anchor file is unsafe")
        key = args.phase_key_file.read_bytes()
        if len(key) > 4096:
            raise ValueError("phase trust anchor file is unsafe")
        phases = json.loads(args.phases_json)
        merge_probe_phases(args.side, key, phases, args.out, args.phase_root)
        print(json.dumps({"side": args.side, "phase_count": len(phases)}, sort_keys=True))
        return 0
    parser = argparse.ArgumentParser(description="Validate typed live probe contract")
    parser.add_argument("--backends-json", required=True)
    parser.add_argument("--source-plan", required=True, type=Path)
    parser.add_argument("--target-plan", required=True, type=Path)
    parser.add_argument("--range-enabled", choices=("true", "false"), required=True)
    parser.add_argument("--source-controller", required=True)
    parser.add_argument("--target-controller", required=True)
    parser.add_argument("--inventory-hosts-json", required=True)
    args = parser.parse_args(argv)
    result = validate_probe_contract(
        json.loads(args.backends_json),
        json.loads(args.source_plan.read_text(encoding="utf-8")),
        json.loads(args.target_plan.read_text(encoding="utf-8")),
        args.range_enabled == "true",
        args.source_controller,
        args.target_controller,
        set(json.loads(args.inventory_hosts_json)),
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
