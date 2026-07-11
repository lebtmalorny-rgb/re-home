"""Bind protected probe plans to the authoritative typed backend inventory."""

from copy import deepcopy
import argparse
import json
from pathlib import Path


_SUPPORTED = {"nfs": "nfs", "file": "nfs", "rbd": "rbd", "lvm": "lvm"}
_BACKEND_KEYS = {"kind", "source_delegate", "target_delegate", "allowed_scopes", "probe_template"}


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
    source_delegates = {item["source_delegate"] for item in normalized.values()}
    target_delegates = {item["target_delegate"] for item in normalized.values()}
    if len(source_delegates) > 1 or len(target_delegates) > 1:
        raise ValueError("one probe phase cannot use multiple delegates per side")
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
    return {
        "source_delegate": next(iter(source_delegates), source_controller),
        "target_delegate": next(iter(target_delegates), target_controller),
        "backend_kinds": sorted({item["kind"] for item in normalized.values()}),
        "supported": {
            key: value["probe_template"] != "unsupported"
            for key, value in sorted(normalized.items())
        },
    }


def main(argv=None):
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
