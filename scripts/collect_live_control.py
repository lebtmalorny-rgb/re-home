#!/usr/bin/env python3
"""Two-phase, UUID-scoped control-plane discovery transport."""

import argparse
from copy import deepcopy
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))

from live_discovery.mysql_json import build_json_row_query, validate_identifier
from live_discovery.cinder import CinderCollector, CORE_TABLES as CINDER_CORE_TABLES, OPTIONAL_TABLES as CINDER_OPTIONAL_TABLES
from live_discovery.contract import CheckResult, CollectorResult
from live_discovery.glance import GlanceCollector
from live_discovery.neutron import NeutronCollector, CORE_TABLES as NEUTRON_CORE_TABLES, OPTIONAL_TABLE_FAMILIES as NEUTRON_OPTIONAL_TABLE_FAMILIES
from live_discovery.nova import NovaCollector, DB_SCHEMAS as NOVA_DB_SCHEMAS, DB_TABLES as NOVA_DB_TABLES
from live_discovery.openstack import collect_target_profile
from live_discovery.render import render_json
from live_discovery.runner import ReadOnlyRunner, validate_select_only_sql
from live_discovery.runtime import collect_target_capabilities
from live_discovery.schema import parse_information_schema
from live_discovery.storage import probe_storage, _parse_size as _storage_parse_size
from live_discovery.image_data import probe_image_data


API_INPUT_VERSION = "openstack-rehome-control-api-input/v1alpha1"
API_RESULT_VERSION = "openstack-rehome-control-api-result/v1alpha1"
PLAN_VERSION = "openstack-rehome-db-query-plan/v1alpha1"
BUNDLE_VERSION = "openstack-rehome-control-bundle/v1alpha1"
_MAX_FILE = 8 * 1024 * 1024
_MAX_LINES = 100_000
_MAX_QUERIES = 512
_SOURCE_NOVA_TABLES = {
    "nova_api.host_mappings", "nova_api.instance_mappings",
    "nova_api.request_specs", "nova.instances",
    "nova.block_device_mapping", "nova.instance_info_caches",
    "nova.compute_nodes", "nova.services",
}
_NEUTRON_CORE_TABLES = {
    "neutron.ports", "neutron.networks", "neutron.subnets",
    "neutron.ipallocations", "neutron.networksegments",
    "neutron.ml2_port_bindings", "neutron.ml2_port_binding_levels",
}
_CINDER_CORE_TABLES = {
    "cinder.volumes", "cinder.volume_attachment",
    "cinder.volume_types", "cinder.services",
}
_SAFE_ROOT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@+-]{0,254}$")
_HOST_ROOT = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,252}[A-Za-z0-9])?$")
_TABLE_ROOT_FILTERS = {
    "nova_api.host_mappings": (("hosts", "host"), ("cells", "cell_id")),
    "nova_api.instance_mappings": (("instances", "instance_uuid"),),
    "nova_api.request_specs": (("instances", "instance_uuid"),),
    "nova.instances": (("instances", "uuid"),),
    "nova.block_device_mapping": (("instances", "instance_uuid"),),
    "nova.instance_info_caches": (("instances", "instance_uuid"),),
    "nova.compute_nodes": (("compute_nodes", "uuid"), ("hosts", "host")),
    "nova.services": (("services", "uuid"), ("hosts", "host")),
    "neutron.ports": (("ports", "id"),),
    "neutron.ipallocations": (("ports", "port_id"),),
    "neutron.networks": (("networks", "id"),),
    "neutron.subnets": (("subnets", "id"),),
    "neutron.networksegments": (("networks", "network_id"),),
    "neutron.ml2_port_bindings": (("ports", "port_id"),),
    "neutron.ml2_distributed_port_bindings": (("ports", "port_id"),),
    "neutron.ml2_port_binding_levels": (("ports", "port_id"),),
    "neutron.securitygroupportbindings": (("ports", "port_id"),),
    "neutron.securitygroups": (("security_groups", "id"),),
    "neutron.securitygrouprules": (("security_groups", "security_group_id"),),
    "neutron.allowedaddresspairs": (("ports", "port_id"),),
    "neutron.portdnses": (("ports", "port_id"),),
    "neutron.dnsnameservers": (("subnets", "subnet_id"),),
    "neutron.extradhcpopts": (("ports", "port_id"),),
    "neutron.qos_port_policy_bindings": (("ports", "port_id"),),
    "neutron.qos_network_policy_bindings": (("networks", "network_id"),),
    "neutron.qos_fip_policy_bindings": (("floating_ips", "fip_id"),),
    "neutron.qos_policies": (("qos_policies", "id"),),
    "neutron.trunks": (("ports", "port_id"), ("trunks", "id")),
    "neutron.subports": (("ports", "port_id"), ("trunks", "trunk_id")),
    "neutron.routers": (("routers", "id"),),
    "neutron.routerports": (("ports", "port_id"),),
    "neutron.routerroutes": (("routers", "router_id"),),
    "neutron.floatingips": (("ports", "fixed_port_id"), ("floating_ips", "id")),
    "neutron.portforwardings": (("ports", "internal_port_id"),),
    "neutron.address_groups": (("address_groups", "id"),),
    "neutron.address_associations": (("address_groups", "address_group_id"),),
    "neutron.addressgrouprbacs": (("address_groups", "object_id"),),
    "cinder.volumes": (("volumes", "id"),),
    "cinder.volume_attachment": (("volumes", "volume_id"),),
    "cinder.volume_types": (("volume_types", "id"),),
    "cinder.services": (("cinder_services", "uuid"),),
    "cinder.volume_type_extra_specs": (("volume_types", "volume_type_id"),),
    "cinder.volume_type_projects": (("volume_types", "volume_type_id"),),
    "cinder.volume_type_qos_specs": (("volume_types", "volume_type_id"),),
    "cinder.qos_specs": (("qos_specs", "id"),),
    "cinder.quality_of_service_specs": (("qos_specs", "specs_id"),),
    "cinder.encryption": (("volume_types", "volume_type_id"),),
    "cinder.snapshots": (("volumes", "volume_id"), ("snapshots", "id")),
    "cinder.volume_metadata": (("volumes", "volume_id"),),
    "cinder.volume_glance_metadata": (("volumes", "volume_id"),),
    "cinder.volume_admin_metadata": (("volumes", "volume_id"),),
    "cinder.groups": (("groups", "id"),),
    "cinder.group_snapshots": (("group_snapshots", "id"),),
}
_ROOT_CATEGORIES = frozenset({
    "hosts", "instances", "ports", "networks", "subnets", "security_groups",
    "qos_policies", "trunks", "floating_ips", "routers", "address_groups",
    "volumes", "volume_types", "cinder_services", "qos_specs", "snapshots",
    "groups", "group_snapshots", "images", "projects", "services",
    "compute_nodes", "cells", "flavors", "allocations", "attachments",
    "barbican_secrets", "image_members", "glance_stores",
})


def _collector_table_catalog():
    neutron = {
        f"neutron.{table}" for table in (
            set(NEUTRON_CORE_TABLES)
            | {table for family in NEUTRON_OPTIONAL_TABLE_FAMILIES.values() for table in family}
        )
    }
    cinder = {
        f"cinder.{table}" for table in set(CINDER_CORE_TABLES) | set(CINDER_OPTIONAL_TABLES)
    }
    nova = {f"{NOVA_DB_SCHEMAS[table]}.{table}" for table in NOVA_DB_TABLES}
    return {"nova": nova, "neutron": neutron, "cinder": cinder}


def _expected_plan_tables(side, roots, available_tables):
    catalog = _collector_table_catalog()
    available = set(available_tables)
    expected = set()
    if side == "source":
        if not catalog["nova"].issubset(available):
            raise ValueError("required Nova schema table is missing")
        expected.update(
            table for table in catalog["nova"]
            if any(roots.get(category) for category, _ in _TABLE_ROOT_FILTERS[table])
        )
    if roots.get("ports"):
        core = {f"neutron.{table}" for table in NEUTRON_CORE_TABLES}
        if not core.issubset(available):
            raise ValueError("required Neutron schema table is missing")
        expected.update(
            table for table in catalog["neutron"] & available
            if any(roots.get(category) for category, _ in _TABLE_ROOT_FILTERS[table])
        )
    if roots.get("volumes"):
        core = {f"cinder.{table}" for table in CINDER_CORE_TABLES}
        if not core.issubset(available):
            raise ValueError("required Cinder schema table is missing")
        expected.update(
            table for table in catalog["cinder"] & available
            if any(roots.get(category) for category, _ in _TABLE_ROOT_FILTERS[table])
        )
    return expected


def _canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _phase_binding(api_result, uuid_filters, query_plan, *, key):
    if not isinstance(key, bytes) or len(key) < 16:
        raise ValueError("phase trust anchor is invalid")
    return hmac.new(key, _canonical({
        "api_result": api_result,
        "uuid_filters": uuid_filters,
        "db_query_plan": query_plan,
    }).encode("utf-8"), hashlib.sha256).hexdigest()


def _root_filter_values(api_result):
    roots = api_result.get("roots")
    if not isinstance(roots, dict):
        raise ValueError("API UUID root manifest is missing")
    values = set()
    for name, items in roots.items():
        if name not in _ROOT_CATEGORIES or not isinstance(items, list):
            raise ValueError("API UUID root manifest is invalid")
        for item in items:
            if name == "hosts":
                if not isinstance(item, str) or _HOST_ROOT.fullmatch(item) is None:
                    raise ValueError("API host root is invalid")
            elif name == "glance_stores":
                if not isinstance(item, str) or _SAFE_ROOT.fullmatch(item) is None:
                    raise ValueError("API named root is invalid")
            elif _canonical_uuid(item) is None:
                raise ValueError("API UUID root is invalid")
            values.add(item)
    return values


def _validate_query_coverage(side, api_result, queries):
    identities = [
        (query["schema"], query["table"], _canonical(query["filters"]))
        for query in queries
    ]
    if len(identities) != len(set(identities)):
        raise ValueError("DB scoped query is duplicated")
    present = {f"{query['schema']}.{query['table']}" for query in queries}
    roots = api_result["roots"]
    available = api_result.get("available_tables")
    if not isinstance(available, list) or not all(isinstance(item, str) for item in available):
        raise ValueError("live schema table inventory is missing")
    required = _expected_plan_tables(side, roots, available)
    if present != required:
        raise ValueError("service DB query coverage differs from live schema scope")
    allowed_values = _root_filter_values(api_result)
    for query in queries:
        for values in query["filters"].values():
            if not set(values).issubset(allowed_values):
                raise ValueError("DB query filter is not bound to API roots")
        table = f"{query['schema']}.{query['table']}"
        for column, values in query["filters"].items():
            if not any(
                planned_column == column and set(values).issubset(set(roots.get(category, [])))
                for category, planned_column in _TABLE_ROOT_FILTERS.get(table, ())
            ):
                raise ValueError("DB query filter column differs from collector root scope")


def _canonical_uuid(value):
    try:
        return str(uuid.UUID(value)) if isinstance(value, str) and str(uuid.UUID(value)) == value else None
    except (ValueError, AttributeError):
        return None


def _scoped_in(column, values):
    normalized = []
    for value in values:
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            normalized.append(str(value))
        elif isinstance(value, str) and _SAFE_ROOT.fullmatch(value):
            normalized.append("'" + value + "'")
        else:
            raise ValueError("invalid scoped filter value")
    if not normalized:
        raise ValueError("scoped filter requires values")
    return f"`{validate_identifier(column)}` IN ({', '.join(normalized)})"


def _read_owned_file(path, maximum, label):
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"{label} file is unsafe") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or (hasattr(os, "geteuid") and metadata.st_uid != os.geteuid())
            or metadata.st_size <= 0
            or metadata.st_size > maximum
        ):
            raise ValueError(f"{label} file permissions are unsafe")
        chunks = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > maximum:
            raise ValueError(f"{label} file size is unsafe")
        return payload
    finally:
        os.close(descriptor)


def _load_protected_token(path):
    try:
        token = _read_owned_file(path, 16 * 1024, "Glance token").decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise ValueError("Glance token value is unsafe") from error
    if not token or "\r" in token or "\n" in token:
        raise ValueError("Glance token value is unsafe")
    return token


def _load_phase_key(args, *, fixture=False):
    if fixture:
        return b"fixture-only-phase-integrity-anchor-v1"
    key_file = getattr(args, "phase_key_file", None)
    key_env = getattr(args, "phase_key_env", None)
    if bool(key_file) == bool(key_env):
        raise ValueError("exactly one phase trust anchor is required")
    if key_file:
        key = _read_owned_file(key_file, 16 * 1024, "phase key").strip()
    else:
        variable = str(key_env)
        value = os.environ.get(variable)
        key = value.encode("utf-8") if isinstance(value, str) else b""
    if len(key) < 16 or len(key) > 16 * 1024 or b"\n" in key or b"\r" in key:
        raise ValueError("phase trust anchor is invalid")
    return key


def _execute_probe_config(config, runner, *, opener=None, token_loader=_load_protected_token):
    if not isinstance(config, dict) or set(config) != {"schema_version", "storage", "glance"} or config.get("schema_version") != "openstack-rehome-probe-config/v1alpha1":
        raise ValueError("probe configuration envelope is invalid")
    if not isinstance(config["storage"], list) or len(config["storage"]) > 4096:
        raise ValueError("storage probe configuration is invalid")
    storage_results = []
    for item in config["storage"]:
        if not isinstance(item, dict) or set(item) != {"volume_id", "scope", "kind", "backend_id", "resource"}:
            raise ValueError("storage probe row is invalid")
        volume_id = _canonical_uuid(item["volume_id"])
        if volume_id is None or item["scope"] not in {"source-compute", "target-storage"} or not isinstance(item["kind"], str) or not isinstance(item["backend_id"], str) or _SAFE_ROOT.fullmatch(item["backend_id"]) is None:
            raise ValueError("storage probe identity is invalid")
        observed = [None]
        class RecordingRunner:
            def run(self, argv, evidence_id):
                artifact = runner.run(argv, evidence_id)
                observed[0] = _storage_parse_size("nfs" if item["kind"] == "file" else item["kind"], getattr(artifact, "stdout", None))
                return artifact
        check = probe_storage(item["kind"], item["resource"], RecordingRunner())
        resource = item["resource"]
        if not isinstance(resource, dict):
            raise ValueError("storage probe resource is invalid")
        scoped_resource = {
            "nfs": resource.get("path"), "file": resource.get("path"),
            "rbd": f"{resource.get('pool')}/{resource.get('image')}",
            "lvm": f"{resource.get('vg')}/{resource.get('lv')}",
        }.get(item["kind"], str(resource.get("backend_id", "unsupported")))
        evidence_id = f"storage:{volume_id}:{item['scope']}:{item['kind']}:{item['backend_id']}"
        storage_results.append({
            "volume_id": volume_id, "scope": item["scope"], "kind": item["kind"],
            "backend_identity": item["backend_id"], "resource_identity": scoped_resource,
            "expected_size": resource.get("expected_size"), "observed_size": observed[0],
            "evidence_id": evidence_id, "status": check.status, "reason": check.reason,
        })
    glance = config["glance"]
    if not isinstance(glance, dict) or set(glance) not in (
        {"endpoint_url", "token_file", "images", "store_capabilities"},
        {"endpoint_url", "token_env", "images", "store_capabilities"},
    ):
        raise ValueError("Glance probe configuration is invalid")
    images = glance["images"]
    stores = glance["store_capabilities"]
    if not isinstance(images, list) or len(images) > 4096 or not isinstance(stores, list) or len(stores) > 4096:
        raise ValueError("Glance probe configuration exceeds safety bounds")
    normalized_stores = []
    for item in stores:
        if not isinstance(item, dict) or set(item) != {"store_id", "backend_type"} or not all(isinstance(value, str) and value for value in item.values()):
            raise ValueError("Glance store capability is invalid")
        normalized_stores.append(deepcopy(item))
    if "token_file" in glance:
        token = token_loader(glance["token_file"])
    else:
        variable = glance["token_env"]
        if not isinstance(variable, str) or not variable or variable not in os.environ:
            raise ValueError("Glance token environment reference is unavailable")
        token = os.environ[variable]
    image_results = []
    try:
        for item in images:
            if not isinstance(item, dict) or set(item) != {"image_id", "expected_size", "required"}:
                raise ValueError("Glance image probe row is invalid")
            image_id = _canonical_uuid(item["image_id"])
            if image_id is None or not isinstance(item["required"], bool):
                raise ValueError("Glance image probe identity is invalid")
            check = probe_image_data(
                f"{glance['endpoint_url'].rstrip('/')}/v2/images/{image_id}/file",
                token, item["expected_size"], opener=opener,
                endpoint_url=glance["endpoint_url"], image_id=image_id,
                required=item["required"],
            )
            endpoint_origin = glance["endpoint_url"].rstrip("/")
            image_results.append({
                "image_id": image_id, "endpoint_origin": endpoint_origin,
                "expected_size": item["expected_size"],
                "observed_size": item["expected_size"] if check.status == "PASS" else None,
                "required": item["required"],
                "store_ids": sorted(store["store_id"] for store in normalized_stores),
                "evidence_id": f"glance-range:{image_id}",
                "status": check.status, "reason": check.reason,
            })
    finally:
        token = None
    return {
        "storage_probe_results": storage_results,
        "glance_data_probe_results": image_results,
        "glance_store_capabilities": normalized_stores,
    }


class _CombinedClient:
    """Serve only the exact API/DB evidence acquired by the two phases."""

    def __init__(self, side, api_result, records, evidence):
        self.side = side
        self._api_result = deepcopy(api_result)
        self._api = {}
        for item in api_result.get("openstack", []):
            if not isinstance(item, dict) or set(item) != {"command", "payload", "evidence"} or not isinstance(item["command"], list):
                raise ValueError("cached OpenStack response is invalid")
            key = tuple(item["command"])
            if key in self._api:
                raise ValueError("cached OpenStack response is duplicated")
            self._api[key] = (deepcopy(item["payload"]), deepcopy(item["evidence"]))
        if not isinstance(records, list) or not isinstance(evidence, list):
            raise ValueError("cached DB transport is invalid")
        self._records = deepcopy(records)
        self._evidence = deepcopy(evidence)

    def json(self, command, evidence_id, required=True):
        del evidence_id, required
        key = tuple(command)
        if key not in self._api:
            return None, {"id": "cached-openstack-response-missing"}
        return deepcopy(self._api[key])

    def db_records(self, table, filters=None):
        exact = [
            item for item in self._records
            if item["table"] == table
            and (filters is None or item["filters"] == filters)
        ]
        matches = exact
        if not matches and isinstance(filters, dict) and filters:
            matches = [
                item for item in self._records
                if item["table"] == table
                and set(item.get("filters", {})) == set(filters)
                and all(set(filters[column]).issubset(set(item["filters"][column])) for column in filters)
                and all(any(
                    planned_column == column
                    and set(item["filters"][column]).issubset(set(self._api_result.get("roots", {}).get(category, [])))
                    for category, planned_column in _TABLE_ROOT_FILTERS.get(f"{item['schema']}.{table}", ())
                ) for column in filters)
            ]
        if len(matches) != 1:
            return [], {"evidence_id": f"{self.side}-db:unknown.{table}"}
        match = matches[0]
        evidence_matches = [
            item for item in self._evidence
            if item["schema"] == match["schema"]
            and item["table"] == match["table"]
            and item["filters"] == match["filters"]
        ]
        if len(evidence_matches) != 1:
            raise ValueError("collector DB evidence identity is ambiguous")
        rows = deepcopy(match["rows"])
        proof = {
            "evidence_id": evidence_matches[0]["evidence_id"],
            "schema": match["schema"], "table": match["table"],
            "filters": deepcopy(filters if filters is not None else match["filters"]),
        }
        if filters is not None and match["filters"] != filters:
            rows = [row for row in rows if any(row.get("row", {}).get(column) in values for column, values in filters.items())]
        return rows, proof

    def glance_store_capabilities(self, evidence_id):
        values = self._api_result.get("glance_store_capabilities", [])
        if not isinstance(values, list):
            raise ValueError("Glance store capabilities are invalid")
        normalized = []
        for item in values:
            if (
                not isinstance(item, dict)
                or set(item) != {"store_id", "backend_type"}
                or not all(isinstance(item[key], str) and item[key] for key in item)
            ):
                raise ValueError("Glance store capability row is invalid")
            normalized.append(deepcopy(item))
        return normalized, {"evidence_id": evidence_id}

    def probe_image_data(self, image_id, expected_size, required):
        values = self._api_result.get("glance_data_probe_results", [])
        if not isinstance(values, list):
            values = []
        capabilities = self._api_result.get("glance_store_capabilities", [])
        capability_store_ids = sorted(
            item.get("store_id") for item in capabilities
            if isinstance(item, dict) and isinstance(item.get("store_id"), str)
        ) if isinstance(capabilities, list) else []
        matches = [
            item for item in values
            if isinstance(item, dict) and item.get("image_id") == image_id
            and item.get("expected_size") == expected_size
            and item.get("observed_size") == expected_size
            and item.get("required") is required
            and item.get("store_ids") == capability_store_ids
        ]
        expected_keys = {"image_id", "endpoint_origin", "expected_size", "observed_size", "required", "store_ids", "evidence_id", "status", "reason"}
        if len(matches) != 1 or set(matches[0]) != expected_keys or not matches[0]["endpoint_origin"] or not matches[0]["store_ids"]:
            return CheckResult(
                f"glance.image-data.{image_id}", "UNKNOWN",
                "Glance image data probe evidence is missing",
            )
        status = matches[0].get("status")
        if status not in {"PASS", "WARN", "UNKNOWN", "BLOCKED"}:
            status = "UNKNOWN"
        reason = {
            "PASS": "Glance image data byte is readable",
            "WARN": "Glance image data probe completed with warning",
            "UNKNOWN": "Glance image data probe is inconclusive",
            "BLOCKED": "Glance image data probe blocked",
        }[status]
        return CheckResult(
            f"glance.image-data.{image_id}", status, reason,
            [f"image:{image_id}"], [matches[0]["evidence_id"]],
        )


class _CachedCapabilityRunner:
    def __init__(self, outputs):
        self.outputs = outputs if isinstance(outputs, dict) else {}
        self.side = "target"

    def run(self, argv, evidence_id, sensitive_stdout=False):
        del argv, sensitive_stdout
        if evidence_id not in self.outputs or not isinstance(self.outputs[evidence_id], str):
            raise RuntimeError("cached target capability output is missing")
        return type("Evidence", (), {
            "stdout": self.outputs[evidence_id], "stderr": "", "returncode": 0,
            "evidence_id": evidence_id,
            "to_dict": lambda instance: {"evidence_id": instance.evidence_id},
        })()


def _dependency_ids(result, kind):
    prefix = kind + ":"
    return sorted({
        edge.target[len(prefix):]
        for edge in result.edges
        if edge.required and edge.target.startswith(prefix)
    })


def _integrate_storage_readiness(result, volume_ids, api_result):
    values = api_result.get("storage_probe_results", [])
    if not isinstance(values, list):
        values = []
    for volume_id in volume_ids:
        volume_nodes = [node for node in result.nodes if node.kind == "volume" and node.id == volume_id]
        cinder_size = volume_nodes[0].facts.get("size") if len(volume_nodes) == 1 else None
        expected_bytes = cinder_size * 1024 ** 3 if isinstance(cinder_size, int) and not isinstance(cinder_size, bool) and cinder_size > 0 else None
        matches = [
            item for item in values
            if isinstance(item, dict) and item.get("volume_id") == volume_id
        ]
        scopes = set()
        for item in matches:
            expected_keys = {"volume_id", "scope", "kind", "backend_identity", "resource_identity", "expected_size", "observed_size", "evidence_id", "status", "reason"}
            if set(item) != expected_keys:
                continue
            scope = item["scope"]
            kind = item["kind"]
            status = item["status"]
            if (
                scope not in {"source-compute", "target-storage"}
                or not isinstance(kind, str) or not kind
                or status not in {"PASS", "WARN", "UNKNOWN", "BLOCKED"}
            ):
                continue
            scopes.add(scope)
            identity = item["backend_identity"]
            resource_identity = item["resource_identity"]
            evidence_id = item["evidence_id"]
            cinder_backend_id = volume_nodes[0].facts.get("storage_backend_id", volume_nodes[0].facts.get("backend_id")) if len(volume_nodes) == 1 else None
            bound = (
                isinstance(identity, str) and identity
                and isinstance(resource_identity, str) and resource_identity
                and isinstance(evidence_id, str) and evidence_id
                and cinder_backend_id == identity
                and isinstance(item["expected_size"], int)
                and expected_bytes is not None
                and item["expected_size"] == expected_bytes
                and (
                    item["observed_size"] == expected_bytes
                    if status == "PASS"
                    else item["observed_size"] is None or isinstance(item["observed_size"], int)
                )
            )
            if not bound:
                status = "BLOCKED"
            reason = {
                "PASS": "backing object is readable with expected size",
                "WARN": "backing object probe completed with warning",
                "UNKNOWN": (
                    "storage driver is unsupported"
                    if kind not in {"nfs", "file", "rbd", "lvm"}
                    else "backing object probe is inconclusive"
                ),
                "BLOCKED": "backing object probe is not bound to Cinder size and backend",
            }[status]
            identity_hash = hashlib.sha256(str(identity).encode("utf-8")).hexdigest()[:12]
            result.checks.append(CheckResult(
                f"cinder.storage.{volume_id}.{scope}.{kind}.{identity_hash}", status, reason,
                [f"volume:{volume_id}"], [evidence_id],
            ))
            if status == "BLOCKED" and reason not in result.blockers:
                result.blockers.append(reason)
            if status == "UNKNOWN" and reason not in result.unknowns:
                result.unknowns.append(reason)
        required_scopes = (
            {"source-compute"} if result.side == "source" else {"target-storage"}
        )
        for missing_scope in sorted(required_scopes - scopes):
            result.unknowns.append(
                f"storage probe evidence missing: {volume_id} {missing_scope}"
            )
            result.checks.append(CheckResult(
                f"cinder.storage.{missing_scope}.missing.{volume_id}",
                "UNKNOWN", "required storage probe evidence is missing",
                [f"volume:{volume_id}"],
            ))


def _compose_collectors(side, api_result, records, evidence, snapshot):
    client = _CombinedClient(side, api_result, records, evidence)
    results = []
    if side == "source":
        nova = NovaCollector(client, side).collect(api_result.get("rehome_host", ""))
        results.append(nova)
        port_ids = _dependency_ids(nova, "port")
        volume_ids = _dependency_ids(nova, "volume")
        image_ids = _dependency_ids(nova, "image_ref")
        project_ids = sorted({
            node.facts.get("project_id") for node in nova.nodes
            if node.kind == "instance" and isinstance(node.facts.get("project_id"), str)
        })
    else:
        roots = api_result.get("roots", {})
        port_ids = list(roots.get("ports", []))
        volume_ids = list(roots.get("volumes", []))
        image_ids = list(roots.get("images", []))
        project_ids = list(roots.get("projects", []))
        results.append(collect_target_profile(
            client,
            api_result.get("target_manage_outputs", {}),
            api_result.get("target_image_inspects", {}),
        ))
        results.append(collect_target_capabilities(
            _CachedCapabilityRunner(api_result.get("target_runtime_outputs", {})),
            api_result.get("target_virsh_argv", ["virsh"]),
            api_result.get("target_qemu_argv", ["qemu-system-x86_64"]),
        ))
    results.append(NeutronCollector(client, side, snapshot).collect(port_ids))
    cinder = CinderCollector(client, side, snapshot).collect(volume_ids)
    _integrate_storage_readiness(cinder, volume_ids, api_result)
    results.append(cinder)
    requirements = {
        image_id: {
            "required": True,
            "reason": "local_root",
            "bdm_proves_no_local_root": False,
            "runtime_proves_no_local_root": False,
            "consumer_project_ids": project_ids,
        }
        for image_id in image_ids
    }
    results.append(GlanceCollector(client, side).collect(requirements))
    return [result.to_dict() for result in results]


def _build_evidence_index(side, collectors, api_result, db_evidence):
    by_id = {}
    def add(entry):
        identity = entry["evidence_id"]
        if identity in by_id and by_id[identity] != entry:
            raise ValueError("evidence index identity conflicts")
        by_id[identity] = entry

    service_by_schema = {"nova":"nova", "nova_api":"nova", "neutron":"neutron", "cinder":"cinder"}
    for raw in db_evidence:
        entry = {
            "evidence_id": raw["evidence_id"], "kind":"db-jsonl", "side":side,
            "service": service_by_schema.get(raw["schema"], raw["schema"]),
            "schema":raw["schema"], "table":raw["table"], "filters":deepcopy(raw["filters"]),
        }
        if entry["evidence_id"] in by_id:
            existing = by_id[entry["evidence_id"]]
            if existing["schema"] != entry["schema"] or existing["table"] != entry["table"]:
                raise ValueError("DB evidence identity conflicts")
            for column, values in entry["filters"].items():
                existing["filters"].setdefault(column, [])
                existing["filters"][column] = sorted(set(existing["filters"][column]) | set(values))
        else:
            by_id[entry["evidence_id"]] = entry

    cached = {}
    for item in api_result.get("openstack", []):
        evidence = item.get("evidence", {}) if isinstance(item, dict) else {}
        identity = evidence.get("evidence_id") or evidence.get("id") if isinstance(evidence, dict) else None
        if isinstance(identity, str) and identity:
            if identity in cached and cached[identity] != item.get("command"):
                raise ValueError("cached API evidence identity conflicts")
            cached[identity] = deepcopy(item.get("command"))

    storage = {item.get("evidence_id"): item for item in api_result.get("storage_probe_results", []) if isinstance(item, dict)}
    glance = {item.get("evidence_id"): item for item in api_result.get("glance_data_probe_results", []) if isinstance(item, dict)}
    references = {}
    for collector in collectors:
        provenance = (collector["side"], collector["service"])
        for item in [*collector["nodes"], *collector["checks"]]:
            for identity in item["evidence_ids"]:
                if identity in references and references[identity] != provenance:
                    raise ValueError("evidence reference provenance conflicts")
                references[identity] = provenance
    for identity, (_, service) in references.items():
        if identity in by_id:
            if by_id[identity]["service"] != service:
                raise ValueError("DB evidence service conflicts")
            continue
        if identity in storage:
            item = storage[identity]
            add({"evidence_id":identity,"kind":"storage-probe","side":side,"service":service,
                 "resource_id":item["volume_id"],"backend_kind":item["kind"],"backend_identity":item["backend_identity"],"resource_identity":item["resource_identity"],
                 "scope":item["scope"],"expected_size":item["expected_size"],"observed_size":item["observed_size"],"status":item["status"]})
        elif identity in glance:
            item = glance[identity]
            add({"evidence_id":identity,"kind":"glance-range","side":side,"service":service,
                 "resource_id":item["image_id"],"endpoint_origin":item["endpoint_origin"],"expected_size":item["expected_size"],
                 "observed_size":item["observed_size"],"required":item["required"],"store_ids":deepcopy(item["store_ids"]),"status":item["status"]})
        elif identity in cached:
            add({"evidence_id":identity,"kind":"openstack-json","side":side,"service":service,"command":cached[identity]})
        elif service == "runtime-capabilities":
            add({"evidence_id":identity,"kind":"runtime-command","side":side,"service":service,"command":["cached-runtime-capability", identity]})
        elif service in {"target-profile", "glance"}:
            add({"evidence_id":identity,"kind":"openstack-json","side":side,"service":service,"command":["cached-capability-input", identity]})
        else:
            raise ValueError("collector evidence is absent from acquired closure")
    return [by_id[key] for key in sorted(by_id)]


def _has_symlink_component(path):
    absolute = Path(path).absolute()
    return any(candidate.is_symlink() and candidate.parent != Path("/") for candidate in (absolute, *absolute.parents))


def _read_json(path):
    path = Path(path)
    if _has_symlink_component(path) or not path.is_file() or path.stat().st_size > _MAX_FILE:
        raise ValueError("input file is unsafe")
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def _read_protected_json(path):
    try:
        return json.loads(_read_owned_file(path, _MAX_FILE, "protected JSON").decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("protected JSON is invalid") from error


def _safe_out(path):
    path = Path(path)
    if _has_symlink_component(path) or path.name in {"", ".", ".."}:
        raise ValueError("output path is unsafe")
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _write_directory(path, files):
    path = _safe_out(path)
    staging = Path(tempfile.mkdtemp(prefix=f".{path.name}.staging-", dir=path.parent))
    try:
        for name, payload in files.items():
            if "/" in name or name in {"", ".", ".."}:
                raise ValueError("output filename is unsafe")
            target = staging / name
            target.write_text(render_json(payload), encoding="utf-8")
        if path.exists():
            raise ValueError("output directory already exists")
        os.replace(staging, path)
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def _request(item, index):
    single = {"schema", "table", "columns", "filter_column", "filter_values"}
    multiple = {"schema", "table", "columns", "filters"}
    if not isinstance(item, dict) or set(item) not in (single, multiple):
        raise ValueError("query request is invalid")
    schema = validate_identifier(item["schema"])
    table = validate_identifier(item["table"])
    columns = item["columns"]
    if not isinstance(columns, list) or not columns:
        raise ValueError("query request is unscoped")
    columns = [validate_identifier(value) for value in columns]
    if len(columns) != len(set(columns)):
        raise ValueError("query columns are duplicated")
    raw_filters = (
        {item["filter_column"]: item["filter_values"]}
        if set(item) == single else item["filters"]
    )
    if not isinstance(raw_filters, dict) or not raw_filters:
        raise ValueError("query request is unscoped")
    filters = {}
    for raw_column, values in raw_filters.items():
        column = validate_identifier(raw_column)
        if not isinstance(values, list) or not values:
            raise ValueError("query request is unscoped")
        filters[column] = list(values)
    where = "(" + ") OR (".join(
        _scoped_in(column, filters[column]) for column in sorted(filters)
    ) + ")"
    sql = build_json_row_query(schema, table, columns, where)
    filename = f"{index:04d}-{schema}-{table}"
    return {
        "query_id": filename,
        "schema": schema,
        "table": table,
        "columns": columns,
        "filters": filters,
        "sql": sql,
        "jsonl_file": filename + ".jsonl",
        "rc_file": filename + ".rc",
    }


def _auto_requests(side, snapshot, roots):
    expected = _expected_plan_tables(side, roots, snapshot.tables.keys())
    requests = []
    for identity in sorted(expected):
        schema, table = identity.split(".", 1)
        columns_by_name = snapshot.tables[identity]
        columns = [
            column.name for column in sorted(
                columns_by_name.values(), key=lambda item: item.ordinal
            )
            if re.search(
                r"password|passwd|token|secret|chap|credential|connector|connection[_-]?(?:info|data)",
                column.name, re.IGNORECASE,
            ) is None
        ]
        active_filters = []
        for category, filter_column in _TABLE_ROOT_FILTERS[identity]:
            values = roots.get(category, [])
            if not values:
                continue
            if filter_column not in columns_by_name:
                raise ValueError(f"live schema filter column is missing: {identity}.{filter_column}")
            if filter_column not in columns:
                columns.append(filter_column)
            active_filters.append((filter_column, list(values)))
        if not active_filters:
            continue
        groups = (
            [{column: values} for column, values in active_filters]
            if identity in {"neutron.trunks", "neutron.subports"}
            else [dict(active_filters)]
            if identity in {"neutron.floatingips", "cinder.snapshots"}
            else [{active_filters[0][0]: active_filters[0][1]}]
        )
        for filters in groups:
            requests.append({
                "schema": schema, "table": table, "columns": columns,
                "filters": filters,
            })
    return requests


def _payload_ids(payload, *keys):
    items = payload if isinstance(payload, list) else [payload]
    values = []
    for item in items:
        if not isinstance(item, dict):
            continue
        for key in keys:
            raw = item.get(key)
            if isinstance(raw, dict):
                raw = raw.get("id") or raw.get("uuid")
            if isinstance(raw, list):
                candidates = raw
            else:
                candidates = [raw]
            for candidate in candidates:
                if isinstance(candidate, dict):
                    candidate = candidate.get("id") or candidate.get("uuid") or candidate.get("attachment_id")
                if _canonical_uuid(candidate) is not None:
                    values.append(candidate)
    return sorted(dict.fromkeys(values))


def _api_phase(args):
    fixture_mode = args.fixture is not None
    if not fixture_mode:
        required = (
            args.rehome_host, args.cloud, args.clouds_file, args.container,
            args.information_schema,
        )
        if not all(required):
            raise ValueError("live API arguments are incomplete")
        from live_discovery.openstack import OpenStackClient
        client = OpenStackClient(ReadOnlyRunner(), args.cloud, args.container, str(args.clouds_file))
        cached = []
        acquired = {}
        def acquire(command, evidence_id):
            key = tuple(command)
            if key in acquired:
                return deepcopy(acquired[key])
            value, evidence = client.json(command, evidence_id)
            cached.append({"command": list(command), "payload": value, "evidence": evidence})
            acquired[key] = deepcopy(value)
            return value
        server_command = ["server", "list", "--all-projects", "--host", args.rehome_host, "--long", "-f", "json"]
        servers = acquire(server_command, f"nova-{args.side}-server-list-{args.rehome_host}")
        instance_ids = sorted({item.get("ID") or item.get("id") for item in servers if isinstance(item, dict) and (item.get("ID") or item.get("id"))})
        roots = {
            "hosts": [args.rehome_host], "instances": instance_ids,
            "ports": [], "networks": [], "subnets": [], "security_groups": [],
            "qos_policies": [], "trunks": [], "floating_ips": [], "routers": [],
            "address_groups": [], "volumes": [], "volume_types": [],
            "cinder_services": [], "qos_specs": [], "snapshots": [],
            "groups": [], "group_snapshots": [], "images": [], "projects": [],
            "services": [], "compute_nodes": [], "cells": [],
            "flavors": [], "allocations": [], "attachments": [],
            "barbican_secrets": [], "image_members": [], "glance_stores": [],
        }
        if args.root_manifest is not None:
            manifest = _read_json(args.root_manifest)
            if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "side", "roots"} or manifest.get("schema_version") != "openstack-rehome-root-manifest/v1alpha1" or manifest.get("side") != args.side or not isinstance(manifest["roots"], dict):
                raise ValueError("root manifest is invalid")
            _root_filter_values({"roots": manifest["roots"]})
            for category, values in manifest["roots"].items():
                if category not in roots or not isinstance(values, list):
                    raise ValueError("root manifest category is invalid")
                roots[category].extend(values)
        roots = {key: sorted(dict.fromkeys(values)) for key, values in roots.items()}
        instance_ids = roots["instances"]
        service_command = ["compute", "service", "list", "--host", args.rehome_host, "-f", "json"]
        services = acquire(service_command, f"nova-{args.side}-compute-service-list-{args.rehome_host}")
        roots["services"] = _payload_ids(services, "uuid", "UUID")
        hypervisor_command = ["hypervisor", "show", args.rehome_host, "-f", "json"]
        hypervisor = acquire(hypervisor_command, f"nova-{args.side}-hypervisor-show-{args.rehome_host}")
        roots["compute_nodes"] = _payload_ids(hypervisor, "uuid")
        provider_command = ["resource", "provider", "list", "--name", args.rehome_host, "-f", "json"]
        acquire(provider_command, f"nova-{args.side}-resource-provider-list-{args.rehome_host}")
        for instance_id in instance_ids:
            server = acquire(["server", "show", instance_id, "-f", "json"], f"nova-{args.side}-server-show-{instance_id}")
            roots["images"].extend(_payload_ids(server, "image", "image_id"))
            roots["projects"].extend(_payload_ids(server, "project_id"))
            roots["flavors"].extend(_payload_ids(server, "flavor", "flavor_id"))
            acquire(["resource", "provider", "allocation", "show", instance_id, "-f", "json"], f"nova-{args.side}-placement-allocation-show-{instance_id}")
            ports = acquire(["port", "list", "--server", instance_id, "-f", "json"], f"neutron-{args.side}-port-list-{instance_id}")
            roots["ports"].extend(_payload_ids(ports, "id", "ID"))
            volumes = acquire(["server", "volume", "list", instance_id, "-f", "json"], f"cinder-{args.side}-server-volume-list-{instance_id}")
            roots["volumes"].extend(_payload_ids(volumes, "id", "ID", "volume_id"))
        for flavor_id in sorted(set(roots["flavors"])):
            acquire(["flavor", "show", flavor_id, "-f", "json"], f"nova-{args.side}-flavor-show-{flavor_id}")
        for port_id in sorted(set(roots["ports"])):
            port = acquire(["port", "show", port_id, "-f", "json"], f"neutron-{args.side}-port-show-{port_id}")
            roots["networks"].extend(_payload_ids(port, "network_id"))
            roots["security_groups"].extend(_payload_ids(port, "security_group_ids", "security_groups"))
            roots["qos_policies"].extend(_payload_ids(port, "qos_policy_id"))
            fixed_ips = port.get("fixed_ips", []) if isinstance(port, dict) else []
            roots["subnets"].extend(_payload_ids(fixed_ips, "subnet_id"))
        for network_id in sorted(set(roots["networks"])):
            acquire(["network", "show", network_id, "-f", "json"], f"neutron-{args.side}-network-show-{network_id}")
        for subnet_id in sorted(set(roots["subnets"])):
            acquire(["subnet", "show", subnet_id, "-f", "json"], f"neutron-{args.side}-subnet-show-{subnet_id}")
        for security_group_id in sorted(set(roots["security_groups"])):
            acquire(["security", "group", "show", security_group_id, "-f", "json"], f"neutron-{args.side}-security-group-show-{security_group_id}")
        for qos_policy_id in sorted(set(roots["qos_policies"])):
            acquire(["network", "qos", "policy", "show", qos_policy_id, "-f", "json"], f"neutron-{args.side}-qos-policy-show-{qos_policy_id}")
        for trunk_id in sorted(set(roots["trunks"])):
            acquire(["network", "trunk", "show", trunk_id, "-f", "json"], f"neutron-{args.side}-trunk-show-{trunk_id}")
        for floating_ip_id in sorted(set(roots["floating_ips"])):
            acquire(["floating", "ip", "show", floating_ip_id, "-f", "json"], f"neutron-{args.side}-floating-ip-show-{floating_ip_id}")
        for router_id in sorted(set(roots["routers"])):
            acquire(["router", "show", router_id, "-f", "json"], f"neutron-{args.side}-router-show-{router_id}")
        for address_group_id in sorted(set(roots["address_groups"])):
            acquire(["address", "group", "show", address_group_id, "-f", "json"], f"neutron-{args.side}-address-group-show-{address_group_id}")
        pending_volumes = list(sorted(set(roots["volumes"])))
        seen_volumes = set()
        while pending_volumes:
            volume_id = pending_volumes.pop(0)
            if volume_id in seen_volumes:
                continue
            seen_volumes.add(volume_id)
            volume = acquire(["volume", "show", volume_id, "-f", "json"], f"cinder-{args.side}-volume-show-{volume_id}")
            roots["volume_types"].extend(_payload_ids(volume, "volume_type_id", "type_id"))
            roots["cinder_services"].extend(_payload_ids(volume, "service_uuid"))
            roots["snapshots"].extend(_payload_ids(volume, "snapshot_id"))
            discovered_volumes = _payload_ids(volume, "source_volid")
            roots["volumes"].extend(discovered_volumes)
            pending_volumes.extend(discovered_volumes)
            roots["attachments"].extend(_payload_ids(volume, "attachments", "attachment_ids"))
            roots["groups"].extend(_payload_ids(volume, "group_id", "consistencygroup_id"))
            roots["group_snapshots"].extend(_payload_ids(volume, "group_snapshot_id"))
        for attachment_id in sorted(set(roots["attachments"])):
            acquire(["volume", "attachment", "show", attachment_id, "-f", "json"], f"cinder-{args.side}-attachment-show-{attachment_id}")
        for type_id in sorted(set(roots["volume_types"])):
            acquire(["volume", "type", "show", type_id, "-f", "json"], f"cinder-{args.side}-volume-type-show-{type_id}")
        for snapshot_id in sorted(set(roots["snapshots"])):
            acquire(["volume", "snapshot", "show", snapshot_id, "-f", "json"], f"cinder-{args.side}-snapshot-show-{snapshot_id}")
        if roots["volumes"] or roots["cinder_services"]:
            acquire(["volume", "service", "list", "--long", "-f", "json"], f"cinder-{args.side}-volume-service-list")
        for secret_id in sorted(set(roots["barbican_secrets"])):
            acquire(["secret", "get", secret_id, "-f", "json"], f"cinder-{args.side}-secret-get-{secret_id}")
        if roots["images"]:
            stores = acquire(["image", "stores", "info", "-f", "json"], f"glance-{args.side}-stores-info")
            if isinstance(stores, list):
                roots["glance_stores"].extend(str(item.get("id")) for item in stores if isinstance(item, dict) and isinstance(item.get("id"), str))
        for image_id in sorted(set(roots["images"])):
            acquire(["image", "show", image_id, "-f", "json"], f"glance-{args.side}-image-show-{image_id}")
            acquire(["image", "member", "list", image_id, "-f", "json"], f"glance-{args.side}-image-member-list-{image_id}")
        roots = {key: sorted(dict.fromkeys(values)) for key, values in roots.items()}
        snapshot = parse_information_schema(args.information_schema)
        api_result = {
            "rehome_host": args.rehome_host, "instances": instance_ids,
            "roots": roots, "available_tables": sorted(snapshot.tables),
            "openstack": cached,
        }
        payload = {
            "schema_version": API_INPUT_VERSION, "side": args.side,
            "api_result": api_result,
            "requests": _auto_requests(args.side, snapshot, roots),
        }
    else:
        payload = _read_json(args.fixture)
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "side", "api_result", "requests"} or payload["schema_version"] != API_INPUT_VERSION or payload["side"] != args.side:
        raise ValueError("API fixture envelope is invalid")
    allowed_api_result = {
        "rehome_host", "instances", "roots", "available_tables", "openstack",
        "storage_probe_results", "glance_data_probe_results",
        "glance_store_capabilities", "target_manage_outputs",
        "target_image_inspects", "target_runtime_outputs", "target_virsh_argv",
        "target_qemu_argv", "schema_capabilities",
    }
    if (
        not isinstance(payload["api_result"], dict)
        or not set(payload["api_result"]).issubset(allowed_api_result)
        or not isinstance(payload["requests"], list)
        or not payload["requests"] or len(payload["requests"]) > _MAX_QUERIES
    ):
        raise ValueError("API result is invalid")
    if "collectors" in payload["api_result"]:
        raise ValueError("cached collector composition bypass is forbidden")
    if args.probe_config is not None:
        probe_results = _execute_probe_config(
            _read_protected_json(args.probe_config), ReadOnlyRunner()
        )
        for key, value in probe_results.items():
            if key in payload["api_result"]:
                raise ValueError("probe result identity is duplicated")
            payload["api_result"][key] = value
    if args.capability_config is not None:
        capability = _read_protected_json(args.capability_config)
        expected = {
            "schema_version", "target_manage_outputs", "target_image_inspects",
            "target_runtime_outputs", "target_virsh_argv", "target_qemu_argv",
            "schema_capabilities",
        }
        if (
            not isinstance(capability, dict) or set(capability) != expected
            or capability.get("schema_version") != "openstack-rehome-target-capability-input/v1alpha1"
        ):
            raise ValueError("target capability input is invalid")
        for key in expected - {"schema_version"}:
            if key in payload["api_result"]:
                raise ValueError("target capability identity is duplicated")
            payload["api_result"][key] = deepcopy(capability[key])
    queries = [_request(item, index + 1) for index, item in enumerate(payload["requests"])]
    _validate_query_coverage(args.side, payload["api_result"], queries)
    query_ids = [item["query_id"] for item in queries]
    if len(query_ids) != len(set(query_ids)):
        raise ValueError("query identity is duplicated")
    filters = [
        {"query_id": query["query_id"], "schema": query["schema"],
         "table": query["table"], "filters": deepcopy(query["filters"])}
        for query in queries
    ]
    phase_mode = "fixture" if fixture_mode else "live"
    api_base = json.loads(render_json({"schema_version": API_RESULT_VERSION, "side": args.side, "phase_mode": phase_mode, "api_result": payload["api_result"]}))
    filters_base = json.loads(render_json({"schema_version": "openstack-rehome-uuid-filters/v1alpha1", "side": args.side, "phase_mode": phase_mode, "filters": filters}))
    plan_base = json.loads(render_json({"schema_version": PLAN_VERSION, "side": args.side, "phase_mode": phase_mode, "queries": queries}))
    binding = _phase_binding(api_base, filters_base, plan_base, key=_load_phase_key(args, fixture=fixture_mode))
    api_result = {**api_base, "binding_sha256": binding}
    uuid_filters = {**filters_base, "binding_sha256": binding}
    plan = {**plan_base, "binding_sha256": binding}
    _write_directory(args.out, {"api-result.json": api_result, "uuid-filters.json": uuid_filters, "db-query-plan.json": plan})


def _read_jsonl(path, query):
    path = Path(path)
    if _has_symlink_component(path) or not path.is_file() or path.stat().st_size > _MAX_FILE:
        raise ValueError("DB JSONL output is unsafe")
    records = []
    with path.open("r", encoding="utf-8") as stream:
        for index, line in enumerate(stream):
            if index >= _MAX_LINES or len(line) > 1024 * 1024:
                raise ValueError("DB JSONL exceeds safety bounds")
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError("DB JSONL record is malformed") from error
            if not isinstance(record, dict) or set(record) != {"_schema", "_table", "row"} or record["_schema"] != query["schema"] or record["_table"] != query["table"] or not isinstance(record["row"], dict):
                raise ValueError("DB JSONL provenance is invalid")
            if set(record["row"]) != set(query["columns"]):
                raise ValueError("DB JSONL selected columns do not match query plan")
            if not any(record["row"].get(field) in values for field, values in query["filters"].items()):
                raise ValueError("DB JSONL row is outside query scope")
            records.append(record)
    return records


def _combine_phase(args):
    api = _read_json(args.api_result)
    filters_document = _read_json(Path(args.api_result).with_name("uuid-filters.json"))
    plan = _read_json(Path(args.api_result).with_name("db-query-plan.json"))
    if not isinstance(api, dict) or set(api) != {"schema_version", "side", "phase_mode", "api_result", "binding_sha256"} or api.get("schema_version") != API_RESULT_VERSION or api.get("side") != args.side or api.get("phase_mode") not in {"fixture", "live"}:
        raise ValueError("API result envelope is invalid")
    if not isinstance(filters_document, dict) or set(filters_document) != {"schema_version", "side", "phase_mode", "filters", "binding_sha256"} or filters_document.get("schema_version") != "openstack-rehome-uuid-filters/v1alpha1" or filters_document.get("side") != args.side or not isinstance(filters_document.get("filters"), list):
        raise ValueError("UUID filter envelope is invalid")
    if not isinstance(plan, dict) or set(plan) != {"schema_version", "side", "phase_mode", "queries", "binding_sha256"} or plan.get("schema_version") != PLAN_VERSION or plan.get("side") != args.side or not isinstance(plan["queries"], list) or not plan["queries"] or len(plan["queries"]) > _MAX_QUERIES or {api["phase_mode"], filters_document.get("phase_mode"), plan.get("phase_mode")} != {api["phase_mode"]}:
        raise ValueError("DB query plan is invalid")
    if api["phase_mode"] == "fixture" and any((getattr(args, "phase_key_file", None), getattr(args, "phase_key_env", None))):
        raise ValueError("fixture phase trust anchor input is forbidden")
    api_base = {key: value for key, value in api.items() if key != "binding_sha256"}
    filters_base = {key: value for key, value in filters_document.items() if key != "binding_sha256"}
    plan_base = {key: value for key, value in plan.items() if key != "binding_sha256"}
    binding = _phase_binding(api_base, filters_base, plan_base, key=_load_phase_key(args, fixture=api["phase_mode"] == "fixture"))
    if {api["binding_sha256"], filters_document["binding_sha256"], plan["binding_sha256"]} != {binding}:
        raise ValueError("API/filter/query phase binding is invalid")
    planned_filters = [
        {"query_id": query.get("query_id"), "schema": query.get("schema"),
         "table": query.get("table"), "filters": query.get("filters")}
        for query in plan["queries"] if isinstance(query, dict)
    ]
    if planned_filters != filters_document["filters"]:
        raise ValueError("UUID filters differ from query plan")
    _validate_query_coverage(args.side, api["api_result"], plan["queries"])
    db_dir = Path(args.db_jsonl_dir)
    if _has_symlink_component(db_dir) or not db_dir.is_dir() or len(list(db_dir.iterdir())) > _MAX_QUERIES * 2:
        raise ValueError("DB output directory is unsafe")
    expected_outputs = {
        name
        for query in plan["queries"] if isinstance(query, dict)
        for name in (query.get("jsonl_file"), query.get("rc_file"))
        if isinstance(name, str)
    }
    actual_outputs = {entry.name for entry in db_dir.iterdir()}
    if actual_outputs != expected_outputs:
        raise ValueError("DB output set does not match query plan")
    records = []
    evidence = []
    for query_index, query in enumerate(plan["queries"], start=1):
        expected = {"query_id", "schema", "table", "columns", "filters", "sql", "jsonl_file", "rc_file"}
        if not isinstance(query, dict) or set(query) != expected or not query["filters"]:
            raise ValueError("DB query is invalid")
        if (
            not isinstance(query["columns"], list)
            or not query["columns"]
            or not isinstance(query["filters"], dict)
            or not query["filters"]
        ):
            raise ValueError("DB query scope is invalid")
        schema = validate_identifier(query["schema"])
        table = validate_identifier(query["table"])
        columns = [validate_identifier(value) for value in query["columns"]]
        normalized_filters = {
            validate_identifier(column): values
            for column, values in query["filters"].items()
        }
        where = "(" + ") OR (".join(
            _scoped_in(column, normalized_filters[column])
            for column in sorted(normalized_filters)
        ) + ")"
        expected_sql = build_json_row_query(
            schema, table, columns, where
        )
        if query["sql"] != expected_sql:
            raise ValueError("DB query does not match its reviewed scope")
        validate_select_only_sql(query["sql"])
        expected_query_id = f"{query_index:04d}-{schema}-{table}"
        if query["query_id"] != expected_query_id or query["jsonl_file"] != expected_query_id + ".jsonl" or query["rc_file"] != expected_query_id + ".rc":
            raise ValueError("DB query filenames are invalid")
        rc_path = db_dir / query["rc_file"]
        output_path = db_dir / query["jsonl_file"]
        if rc_path.parent != db_dir or output_path.parent != db_dir or rc_path.is_symlink() or output_path.is_symlink() or not rc_path.is_file():
            raise ValueError("DB query status is missing")
        if rc_path.stat().st_size > 16 or rc_path.read_text(encoding="ascii").strip() != "0":
            raise ValueError("DB query failed")
        rows = _read_jsonl(output_path, query)
        key = f"{query['schema']}.{query['table']}"
        record_identity = (query["schema"], query["table"], _canonical(query["filters"]))
        if any((item["schema"], item["table"], _canonical(item["filters"])) == record_identity for item in records):
            raise ValueError("DB query output is duplicated")
        records.append({"schema": query["schema"], "table": query["table"], "filters": deepcopy(query["filters"]), "rows": rows})
        evidence.append({"evidence_id": f"{args.side}-db:{key}", "kind": "db-jsonl", "schema": query["schema"], "table": query["table"], "filters": deepcopy(query["filters"])})
    # Parse/validate the two policy inputs now; service collectors consume these
    # exact documents in the next orchestration layer.
    if _has_symlink_component(args.information_schema) or not args.information_schema.is_file() or args.information_schema.stat().st_size > _MAX_FILE:
        raise ValueError("information_schema input is unsafe")
    snapshot = parse_information_schema(args.information_schema)
    if not snapshot.tables:
        raise ValueError("information_schema evidence is empty")
    live_expected_tables = _expected_plan_tables(
        args.side, api["api_result"]["roots"], snapshot.tables.keys()
    )
    planned_table_set = {
        f"{query['schema']}.{query['table']}" for query in plan["queries"]
    }
    if planned_table_set != live_expected_tables:
        raise ValueError("DB query plan differs from live schema-gated collector scope")
    schema_policy = _read_json(args.schema_policy)
    if not isinstance(schema_policy, dict):
        raise ValueError("schema policy is invalid")
    collectors = _compose_collectors(
        args.side, api["api_result"], records, evidence, snapshot
    )
    evidence_index = _build_evidence_index(args.side, collectors, api["api_result"], evidence)
    side_filters = {"source": {}, "target": {}}
    side_filters[args.side] = {
        query["query_id"]: {
            "schema": query["schema"], "table": query["table"],
            "filters": deepcopy(query["filters"]),
        }
        for query in plan["queries"]
    }
    capabilities = deepcopy(api["api_result"].get("schema_capabilities", {}))
    if not isinstance(capabilities, dict):
        raise ValueError("schema capabilities are invalid")
    used_columns = {}
    for query in plan["queries"]:
        used_columns.setdefault(f"{query['schema']}.{query['table']}", set()).update(query["columns"])
    capabilities[f"{args.side}-information-schema"] = {
        "tables": {
            table: {
                column: definition.to_dict()
                for column, definition in sorted(columns.items())
            }
            for table, columns in sorted(snapshot.tables.items())
        },
        "used_columns": {
            table: sorted(columns) for table, columns in sorted(used_columns.items())
        },
    }
    combined = {
        "schema_version": BUNDLE_VERSION,
        "collectors": collectors,
        "checks": [],
        "schema_capabilities": capabilities,
        "uuid_filters": side_filters,
        "evidence_index": evidence_index,
        "sensitive_evidence": {},
    }
    _write_directory(args.out, {"control-result.json": combined})


def main(argv=None):
    parser = argparse.ArgumentParser(description="Collect read-only control-plane facts")
    parser.add_argument("--phase", choices=("api", "combine"), required=True)
    parser.add_argument("--side", choices=("source", "target"), required=True)
    parser.add_argument("--rehome-host")
    parser.add_argument("--cloud")
    parser.add_argument("--clouds-file", type=Path)
    parser.add_argument("--container")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--api-result", type=Path)
    parser.add_argument("--db-jsonl-dir", type=Path)
    parser.add_argument("--information-schema", type=Path)
    parser.add_argument("--schema-policy", type=Path)
    parser.add_argument("--probe-config", type=Path)
    parser.add_argument("--root-manifest", type=Path)
    parser.add_argument("--capability-config", type=Path)
    trust = parser.add_mutually_exclusive_group()
    trust.add_argument("--phase-key-file", type=Path)
    trust.add_argument("--phase-key-env")
    args = parser.parse_args(argv)
    try:
        if args.phase == "api":
            if any((args.api_result, args.db_jsonl_dir, args.schema_policy)):
                raise ValueError("combine arguments are forbidden in API phase")
            if args.fixture is not None and any((args.rehome_host, args.cloud, args.clouds_file, args.container, args.information_schema, args.root_manifest, args.probe_config, args.capability_config, args.phase_key_file, args.phase_key_env)):
                raise ValueError("fixture and live API arguments are mutually exclusive")
            _api_phase(args)
        else:
            if args.fixture is not None or args.probe_config is not None or args.root_manifest is not None or args.capability_config is not None or any((args.rehome_host, args.cloud, args.clouds_file, args.container)) or not all((args.api_result, args.db_jsonl_dir, args.information_schema, args.schema_policy)):
                raise ValueError("combine arguments are incomplete")
            _combine_phase(args)
        print(f"PHASE={args.phase} SIDE={args.side} STATUS=OK")
        return 0
    except Exception:
        print("live control discovery input rejected", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
