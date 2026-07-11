#!/usr/bin/env python3
"""Two-phase, UUID-scoped control-plane discovery transport."""

import argparse
from copy import deepcopy
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tempfile
import uuid
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))

from live_discovery.mysql_json import build_json_row_query, validate_identifier
from live_discovery.cinder import CinderCollector, CORE_TABLES as CINDER_CORE_TABLES, OPTIONAL_TABLES as CINDER_OPTIONAL_TABLES
from live_discovery.contract import CheckResult, CollectorResult
from live_discovery.glance import GlanceCollector
from live_discovery.neutron import NeutronCollector, CORE_TABLES as NEUTRON_CORE_TABLES, OPTIONAL_TABLE_FAMILIES as NEUTRON_OPTIONAL_TABLE_FAMILIES
from live_discovery.nova import NovaCollector, DB_SCHEMAS as NOVA_DB_SCHEMAS, DB_TABLES as NOVA_DB_TABLES
from live_discovery.openstack import collect_target_profile
from live_discovery.render import render_json
from live_discovery.runner import CommandEvidence, ProbeFailed, ReadOnlyRunner, validate_select_only_sql
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
    "encryption_keys", "image_members", "glance_stores",
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


def _phase_binding(api_result, uuid_filters, query_plan, *, key, trust_domain="live"):
    if not isinstance(key, bytes) or len(key) < 16:
        raise ValueError("phase trust anchor is invalid")
    if trust_domain not in {"live", "fixture"}:
        raise ValueError("phase trust domain is invalid")
    return hmac.new(key, (f"openstack-rehome-phase:{trust_domain}:v1\n" + _canonical({
        "api_result": api_result,
        "uuid_filters": uuid_filters,
        "db_query_plan": query_plan,
    })).encode("utf-8"), hashlib.sha256).hexdigest()


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


def _endpoint_origin(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or parsed.hostname is None or parsed.username is not None or parsed.password is not None:
            return None
        port = parsed.port
    except (TypeError, ValueError):
        return None
    default = 443 if parsed.scheme == "https" else 80
    suffix = "" if port in {None, default} else f":{port}"
    return f"{parsed.scheme}://{parsed.hostname.lower()}{suffix}"


def _execute_probe_config(
    config, runner, *, opener=None, token_loader=_load_protected_token,
    catalog_origin=None, image_store_ids=None,
):
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
        probe_kind = "nfs" if item["kind"] == "file" else item["kind"]
        evidence_id = f"storage:{volume_id}:{item['scope']}:{probe_kind}:{item['backend_id']}"
        resource_fingerprint = hashlib.sha256(f"{probe_kind}:{scoped_resource}".encode("utf-8")).hexdigest()
        storage_results.append({
            "volume_id": volume_id, "scope": item["scope"], "kind": probe_kind,
            "backend_identity": item["backend_id"], "resource_identity": scoped_resource,
            "resource_fingerprint": resource_fingerprint,
            "expected_size": resource.get("expected_size"), "observed_size": observed[0],
            "evidence_id": evidence_id, "status": check.status, "reason": check.reason,
        })
    glance = config["glance"]
    if not isinstance(glance, dict) or set(glance) not in (
        {"endpoint_url", "token_file", "images", "store_capabilities"},
        {"endpoint_url", "token_env", "images", "store_capabilities"},
    ):
        raise ValueError("Glance probe configuration is invalid")
    trusted_origin = _endpoint_origin(catalog_origin)
    configured_origin = _endpoint_origin(glance["endpoint_url"])
    if trusted_origin is None or configured_origin != trusted_origin:
        raise ValueError("Glance endpoint differs from service catalog")
    if not isinstance(image_store_ids, dict):
        raise ValueError("Glance image store closure is missing")
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
            if not isinstance(item, dict) or set(item) != {"image_id", "expected_size", "required", "store_ids"}:
                raise ValueError("Glance image probe row is invalid")
            image_id = _canonical_uuid(item["image_id"])
            stores_for_image = item.get("store_ids")
            trusted_stores = image_store_ids.get(image_id) if image_id is not None else None
            if (
                image_id is None or not isinstance(item["required"], bool)
                or not isinstance(stores_for_image, list) or not stores_for_image
                or not all(isinstance(value, str) and _SAFE_ROOT.fullmatch(value) for value in stores_for_image)
                or not isinstance(trusted_stores, list)
                or sorted(stores_for_image) != sorted(trusted_stores)
            ):
                raise ValueError("Glance image probe identity is invalid")
            if not set(stores_for_image).issubset({store["store_id"] for store in normalized_stores}):
                raise ValueError("Glance image store capability is missing")
            check = probe_image_data(
                f"{glance['endpoint_url'].rstrip('/')}/v2/images/{image_id}/file",
                token, item["expected_size"], opener=opener,
                endpoint_url=glance["endpoint_url"], image_id=image_id,
                required=item["required"],
            )
            endpoint_origin = trusted_origin
            image_results.append({
                "image_id": image_id, "endpoint_origin": endpoint_origin,
                "expected_size": item["expected_size"],
                "observed_size": item["expected_size"] if check.status == "PASS" else None,
                "required": item["required"],
                "store_ids": sorted(stores_for_image),
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
        self.cache_misses = []
        self.db_cache_misses = []
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
            if key not in self.cache_misses:
                self.cache_misses.append(key)
            return None, {"id": "cached-openstack-response-missing"}
        return deepcopy(self._api[key])

    def _db_miss(self, schema, table, filters):
        miss = {
            "schema": schema,
            "table": str(table),
            "filters": deepcopy(filters) if isinstance(filters, dict) else {},
        }
        if _canonical(miss) not in {_canonical(item) for item in self.db_cache_misses}:
            self.db_cache_misses.append(miss)
        return [], {
            "evidence_id": f"{self.side}-db:unknown.{schema}.{table}",
            **deepcopy(miss),
        }

    def db_records(self, schema, table, filters=None):
        identity = f"{schema}.{table}"
        if identity not in _TABLE_ROOT_FILTERS:
            raise ValueError("collector DB identity is not allowed")
        exact = [
            item for item in self._records
            if item["schema"] == schema and item["table"] == table
            and (filters is None or item["filters"] == filters)
        ]
        matches = exact
        if not matches and isinstance(filters, dict) and filters:
            matches = [
                item for item in self._records
                if item["schema"] == schema and item["table"] == table
                and set(item.get("filters", {})) == set(filters)
                and all(set(filters[column]).issubset(set(item["filters"][column])) for column in filters)
                and all(any(
                    planned_column == column
                    and set(item["filters"][column]).issubset(set(self._api_result.get("roots", {}).get(category, [])))
                    for category, planned_column in _TABLE_ROOT_FILTERS.get(identity, ())
                ) for column in filters)
            ]
        if len(matches) != 1:
            return self._db_miss(schema, table, filters)
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
        effective_filters = filters if isinstance(filters, dict) else match["filters"]
        proof = {
            "evidence_id": evidence_matches[0]["evidence_id"],
            "schema": match["schema"], "table": match["table"],
            "filters": deepcopy(effective_filters),
        }
        if filters is not None and match["filters"] != filters:
            rows = [row for row in rows if any(row.get("row", {}).get(column) in values for column, values in filters.items())]
        if identity in {"nova.services", "cinder.services"} and effective_filters and not rows:
            return self._db_miss(schema, table, effective_filters)
        return rows, proof

    def glance_store_capabilities(self, evidence_id):
        del evidence_id
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
        return normalized, {"evidence_id": f"glance-{self.side}-stores-info"}

    def probe_image_data(self, image_id, expected_size, required):
        values = self._api_result.get("glance_data_probe_results", [])
        if not isinstance(values, list):
            values = []
        capabilities = self._api_result.get("glance_store_capabilities", [])
        capability_store_ids = sorted(
            item.get("store_id") for item in capabilities
            if isinstance(item, dict) and isinstance(item.get("store_id"), str)
        ) if isinstance(capabilities, list) else []
        trusted_store_ids = self._api_result.get("image_store_ids", {}).get(image_id, [])
        trusted_origin = self._api_result.get("glance_catalog_origin")
        matches = [
            item for item in values
            if isinstance(item, dict) and item.get("image_id") == image_id
            and item.get("expected_size") == expected_size
            and item.get("observed_size") == expected_size
            and item.get("required") is required
            and item.get("store_ids") == sorted(trusted_store_ids)
            and set(item.get("store_ids", [])).issubset(set(capability_store_ids))
            and item.get("endpoint_origin") == trusted_origin
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


class _SchemaBoundCombinedClient:
    """Expose a collector's table names only within its reviewed DB schemas."""

    def __init__(self, client, table_schemas):
        self._client = client
        self._table_schemas = dict(table_schemas)

    def db_records(self, table, filters=None):
        schema = self._table_schemas.get(table)
        if schema is None:
            raise ValueError("collector DB table is not bound to a schema")
        return self._client.db_records(schema, table, filters)

    def __getattr__(self, name):
        return getattr(self._client, name)


class _ProtectedCinderClient:
    """Overlay protected attachment fields only on ephemeral collector rows."""

    def __init__(self, client, summaries, sensitive_evidence):
        if not isinstance(summaries, list) or not isinstance(sensitive_evidence, dict):
            raise ValueError("protected Cinder overlay is invalid")
        self._client = client
        self._by_pair = {}
        expected_evidence_ids = set()
        for summary in summaries:
            if not isinstance(summary, dict):
                raise ValueError("protected Cinder overlay summary is invalid")
            evidence_id = summary.get("evidence_id")
            volume_id = summary.get("volume_id")
            attachment_id = summary.get("attachment_id")
            raw = sensitive_evidence.get(evidence_id)
            connector = raw.get("connector") if isinstance(raw, dict) else None
            connection_info = raw.get("connection_info") if isinstance(raw, dict) else None
            driver_type = connection_info.get("driver_volume_type") if isinstance(connection_info, dict) else None
            normalized_driver = "nfs" if driver_type == "file" else driver_type
            pair = (volume_id, attachment_id)
            if (
                not isinstance(evidence_id, str)
                or raw is None
                or raw.get("volume_id") != volume_id
                or raw.get("attachment_id") != attachment_id
                or not isinstance(connector, dict)
                or connector.get("volume_id") != volume_id
                or connector.get("attachment_id") != attachment_id
                or not isinstance(connection_info, dict)
                or normalized_driver != summary.get("backend_kind")
                or pair in self._by_pair
            ):
                raise ValueError("protected Cinder overlay identity is invalid")
            expected_evidence_ids.add(evidence_id)
            self._by_pair[pair] = {
                "connector": deepcopy(connector),
                "connection_info": deepcopy(connection_info),
            }
        if set(sensitive_evidence) != expected_evidence_ids:
            raise ValueError("protected Cinder overlay evidence set is invalid")

    def db_records(self, table, filters=None):
        rows, evidence = self._client.db_records(table, filters)
        if table != "volume_attachment":
            return rows, evidence
        overlaid = deepcopy(rows)
        for envelope in overlaid:
            row = envelope.get("row") if isinstance(envelope, dict) else None
            pair = (row.get("volume_id"), row.get("id")) if isinstance(row, dict) else None
            protected = self._by_pair.get(pair)
            if protected is not None:
                row.update(deepcopy(protected))
        return overlaid, evidence

    def __getattr__(self, name):
        return getattr(self._client, name)


class _CachedCapabilityRunner:
    def __init__(self, outputs):
        self.outputs = outputs if isinstance(outputs, dict) else {}
        self.side = "target"

    def run(self, argv, evidence_id, sensitive_stdout=False):
        del sensitive_stdout
        value = self.outputs.get(evidence_id)
        if isinstance(value, str):
            # Retain fixture compatibility. Live orchestration always supplies
            # the rc-bearing record shape below.
            return CommandEvidence(evidence_id, [str(item) for item in argv], 0, value, "")
        expected = {"evidence_id", "command", "returncode", "stdout", "stderr"}
        if not isinstance(value, dict) or set(value) != expected:
            raise RuntimeError("cached target capability output is missing")
        if value["evidence_id"] != evidence_id or value["command"] != [str(item) for item in argv]:
            raise RuntimeError("cached target capability identity conflicts")
        evidence = CommandEvidence(
            evidence_id, deepcopy(value["command"]), value["returncode"],
            value["stdout"], value["stderr"],
        )
        if evidence.returncode != 0:
            raise ProbeFailed(evidence)
        return evidence


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
            expected_keys = {"volume_id", "scope", "kind", "backend_identity", "resource_identity", "resource_fingerprint", "expected_size", "observed_size", "evidence_id", "status", "reason"}
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
            cinder_backend_kind = volume_nodes[0].facts.get("backend_kind") if len(volume_nodes) == 1 else None
            cinder_resource_identity = volume_nodes[0].facts.get("resource_identity") if len(volume_nodes) == 1 else None
            cinder_resource_fingerprint = volume_nodes[0].facts.get("resource_fingerprint") if len(volume_nodes) == 1 else None
            connection_evidence_ids = volume_nodes[0].facts.get("connection_evidence_ids", []) if len(volume_nodes) == 1 else []
            bound = (
                isinstance(identity, str) and identity
                and isinstance(resource_identity, str) and resource_identity
                and isinstance(evidence_id, str) and evidence_id
                and cinder_backend_id == identity
                and cinder_backend_kind == kind
                and cinder_resource_identity == resource_identity
                and item["resource_fingerprint"] == cinder_resource_fingerprint
                and item["resource_fingerprint"] == hashlib.sha256(f"{kind}:{resource_identity}".encode("utf-8")).hexdigest()
                and isinstance(connection_evidence_ids, list) and connection_evidence_ids
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
                [f"volume:{volume_id}"], [evidence_id, *connection_evidence_ids],
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


def _bind_cinder_connection_summaries(cinder, connection_summaries):
    if not isinstance(connection_summaries, list):
        raise ValueError("Cinder connection summaries are invalid")
    volume_nodes = {node.id: node for node in cinder.nodes if node.kind == "volume"}
    attachment_nodes = {node.id: node for node in cinder.nodes if node.kind == "volume_attachment"}
    backend_nodes = {node.id: node for node in cinder.nodes if node.kind == "storage_backend"}
    required_attachment_edges = {
        (edge.source, edge.target) for edge in cinder.edges
        if edge.required and edge.relation == "has_attachment"
    }
    required_backend_edges = {
        (edge.source, edge.target) for edge in cinder.edges
        if edge.required and edge.relation == "has_backing_backend"
    }
    summaries_by_volume = {}
    bound_pairs = set()
    for summary in connection_summaries:
        if not isinstance(summary, dict):
            raise ValueError("Cinder connection summary is invalid")
        volume_id = summary.get("volume_id")
        attachment_id = summary.get("attachment_id")
        volume_node = volume_nodes.get(volume_id)
        attachment_node = attachment_nodes.get(attachment_id)
        backend_id = summary.get("backend_id")
        backend_kind = summary.get("backend_kind")
        connection_summary = attachment_node.facts.get("connection_summary") if attachment_node is not None else None
        graph_driver = connection_summary.get("driver_type") if isinstance(connection_summary, dict) else None
        valid = (
            volume_node is not None and attachment_node is not None
            and attachment_node.facts.get("volume_id") == volume_id
            and (f"volume:{volume_id}", f"volume_attachment:{attachment_id}") in required_attachment_edges
            and volume_node.facts.get("storage_backend_id") == backend_id
            and backend_id in backend_nodes
            and (f"volume:{volume_id}", f"storage_backend:{backend_id}") in required_backend_edges
            and graph_driver == backend_kind
            and (volume_id, attachment_id) not in bound_pairs
        )
        if not valid:
            cinder.blockers.append(f"Cinder protected attachment evidence mismatch: {attachment_id}")
            continue
        summaries_by_volume.setdefault(volume_id, []).append(summary)
        bound_pairs.add((volume_id, attachment_id))
        attachment_node.evidence_ids.append(summary["evidence_id"])
        volume_node.evidence_ids.append(summary["evidence_id"])
    for volume_id, summaries in summaries_by_volume.items():
        identities = {(item["backend_kind"], item["backend_id"], item["resource_identity"], item["resource_fingerprint"]) for item in summaries}
        if len(identities) != 1:
            cinder.blockers.append(f"Cinder multiattach backing identity conflicts: {volume_id}")
            continue
        backend_kind, backend_id, resource_identity, resource_fingerprint = next(iter(identities))
        volume_nodes[volume_id].facts.update({
            "backend_kind": backend_kind, "resource_identity": resource_identity,
            "resource_fingerprint": resource_fingerprint,
            "connection_evidence_ids": sorted(item["evidence_id"] for item in summaries),
            "attachment_ids": sorted(item["attachment_id"] for item in summaries),
        })
    for attachment_id, attachment_node in attachment_nodes.items():
        volume_id = attachment_node.facts.get("volume_id")
        if (
            isinstance(volume_id, str)
            and (f"volume:{volume_id}", f"volume_attachment:{attachment_id}") in required_attachment_edges
            and (volume_id, attachment_id) not in bound_pairs
        ):
            cinder.blockers.append(f"Cinder protected attachment evidence missing: {attachment_id}")
    return cinder


def _compose_collectors(side, api_result, records, evidence, snapshot, sensitive_evidence=None):
    client = _CombinedClient(side, api_result, records, evidence)
    collector_schema = getattr(snapshot, "tables", snapshot)
    nova_client = _SchemaBoundCombinedClient(client, NOVA_DB_SCHEMAS)
    neutron_client = _SchemaBoundCombinedClient(client, {
        table: "neutron" for table in (
            set(NEUTRON_CORE_TABLES)
            | {table for family in NEUTRON_OPTIONAL_TABLE_FAMILIES.values() for table in family}
        )
    })
    cinder_client = _SchemaBoundCombinedClient(client, {
        table: "cinder" for table in set(CINDER_CORE_TABLES) | set(CINDER_OPTIONAL_TABLES)
    })
    results = []
    if side == "source":
        nova = NovaCollector(nova_client, side).collect(api_result.get("rehome_host", ""))
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
    results.append(NeutronCollector(neutron_client, side, collector_schema).collect(port_ids))
    protected_cinder_client = (
        _ProtectedCinderClient(
            cinder_client,
            api_result.get("cinder_connection_summaries", []),
            sensitive_evidence,
        )
        if sensitive_evidence is not None else cinder_client
    )
    cinder = CinderCollector(protected_cinder_client, side, collector_schema).collect(volume_ids)
    _bind_cinder_connection_summaries(
        cinder, api_result.get("cinder_connection_summaries", [])
    )
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
    return (
        [result.to_dict() for result in results],
        [list(command) for command in client.cache_misses],
        deepcopy(client.db_cache_misses),
    )


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

    for entry in api_result.get("capability_evidence", []):
        common = {"evidence_id", "kind", "side", "service", "command"}
        if (
            not isinstance(entry, dict) or set(entry) != common
            or entry.get("kind") not in {"openstack-json", "runtime-command"}
            or entry.get("side") != side
            or not all(isinstance(entry.get(key), str) and entry[key] for key in ("evidence_id", "service"))
            or not isinstance(entry.get("command"), list) or not entry["command"]
            or not all(isinstance(value, str) and value for value in entry["command"])
        ):
            raise ValueError("capability evidence is invalid")
        add(deepcopy(entry))

    for summary in api_result.get("cinder_connection_summaries", []):
        expected = {"volume_id", "evidence_id", "attachment_id", "backend_kind", "backend_id", "resource_identity", "resource_fingerprint"}
        if not isinstance(summary, dict) or set(summary) != expected or _canonical_uuid(summary.get("volume_id")) is None:
            raise ValueError("Cinder connection summary is invalid")
        add({
            "evidence_id": summary["evidence_id"], "kind": "cinder-connection",
            "side": side, "service": "cinder", "volume_id": summary["volume_id"],
            "attachment_id": summary["attachment_id"], "backend_kind": summary["backend_kind"],
            "backend_id": summary["backend_id"], "resource_identity": summary["resource_identity"],
            "resource_fingerprint": summary["resource_fingerprint"],
        })

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
        for entry in collector.get("evidence", []):
            if (
                isinstance(entry, dict)
                and set(entry) == {"evidence_id", "kind", "side", "service", "command"}
                and entry.get("kind") in {"openstack-json", "runtime-command"}
                and entry.get("side") == side
                and entry.get("service") == collector.get("service")
                and isinstance(entry.get("command"), list) and entry["command"]
            ):
                add(deepcopy(entry))
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
                 "resource_fingerprint":item["resource_fingerprint"],"scope":item["scope"],"expected_size":item["expected_size"],"observed_size":item["observed_size"],"status":item["status"]})
        elif identity in glance:
            item = glance[identity]
            add({"evidence_id":identity,"kind":"glance-range","side":side,"service":service,
                 "resource_id":item["image_id"],"endpoint_origin":item["endpoint_origin"],"expected_size":item["expected_size"],
                 "observed_size":item["observed_size"],"required":item["required"],"store_ids":deepcopy(item["store_ids"]),"status":item["status"]})
        elif identity in cached:
            add({"evidence_id":identity,"kind":"openstack-json","side":side,"service":service,"command":cached[identity]})
        else:
            raise ValueError(f"collector evidence is absent from acquired closure: {identity}")
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


def _load_cinder_sensitive_evidence(path, side):
    payload = _read_protected_json(path)
    if (
        not isinstance(payload, dict)
        or set(payload) != {"schema_version", "side", "entries"}
        or payload.get("schema_version") != "openstack-rehome-cinder-sensitive-evidence/v1alpha1"
        or payload.get("side") != side
        or not isinstance(payload.get("entries"), list)
        or not payload["entries"]
        or len(payload["entries"]) > 4096
    ):
        raise ValueError("Cinder sensitive evidence envelope is invalid")
    summaries = []
    sensitive = {}
    seen_pairs = set()
    expected = {"evidence_id", "volume_id", "attachment_id", "backend_kind", "backend_id", "resource_identity", "connector", "connection_info"}
    for entry in payload["entries"]:
        if not isinstance(entry, dict) or set(entry) != expected:
            raise ValueError("Cinder sensitive evidence row is invalid")
        volume_id = _canonical_uuid(entry["volume_id"])
        attachment_id = _canonical_uuid(entry["attachment_id"])
        evidence_id = entry["evidence_id"]
        backend_kind = entry["backend_kind"].lower() if isinstance(entry["backend_kind"], str) else ""
        backend_id = entry["backend_id"]
        declared_identity = entry["resource_identity"]
        if backend_kind == "file":
            backend_kind = "nfs"
        connection_info = entry["connection_info"]
        connector = entry["connector"]
        driver_type = connection_info.get("driver_volume_type") if isinstance(connection_info, dict) else None
        data = connection_info.get("data") if isinstance(connection_info, dict) else None
        derived_identity = None
        if isinstance(data, dict):
            if backend_kind == "rbd":
                pool, image = data.get("pool"), data.get("image")
                name = data.get("name")
                if (not isinstance(pool, str) or not isinstance(image, str)) and isinstance(name, str) and name.count("/") == 1:
                    pool, image = name.split("/", 1)
                if isinstance(pool, str) and isinstance(image, str) and _SAFE_ROOT.fullmatch(pool) and _SAFE_ROOT.fullmatch(image):
                    derived_identity = f"{pool}/{image}"
            elif backend_kind == "nfs":
                candidate = data.get("device_path") or data.get("path")
                if isinstance(candidate, str):
                    parsed = PurePosixPath(candidate)
                    if candidate.startswith("/") and str(parsed) == candidate and ".." not in parsed.parts:
                        derived_identity = candidate
            elif backend_kind == "lvm":
                vg, lv = data.get("volume_group"), data.get("logical_volume")
                device = data.get("device_path")
                if (not isinstance(vg, str) or not isinstance(lv, str)) and isinstance(device, str) and device.startswith("/dev/"):
                    parts = PurePosixPath(device).parts
                    if len(parts) == 4:
                        vg, lv = parts[2], parts[3]
                if isinstance(vg, str) and isinstance(lv, str) and _SAFE_ROOT.fullmatch(vg) and _SAFE_ROOT.fullmatch(lv):
                    derived_identity = f"{vg}/{lv}"
            else:
                candidate = data.get("resource_id")
                if isinstance(candidate, str) and _SAFE_ROOT.fullmatch(candidate):
                    derived_identity = candidate
        pair = (volume_id, attachment_id)
        if (
            volume_id is None or attachment_id is None
            or not isinstance(evidence_id, str) or _SAFE_ROOT.fullmatch(evidence_id) is None
            or not backend_kind or _SAFE_ROOT.fullmatch(backend_kind) is None
            or not isinstance(backend_id, str) or _SAFE_ROOT.fullmatch(backend_id) is None
            or derived_identity is None or declared_identity != derived_identity
            or not isinstance(connector, dict) or not connector
            or not isinstance(connection_info, dict) or not connection_info
            or driver_type not in {backend_kind, "file" if backend_kind == "nfs" else backend_kind}
            or connector.get("attachment_id") != attachment_id
            or connector.get("volume_id") != volume_id
            or pair in seen_pairs or evidence_id in sensitive
        ):
            raise ValueError("Cinder sensitive evidence identity is invalid")
        seen_pairs.add(pair)
        summaries.append({
            "volume_id": volume_id,
            "evidence_id": evidence_id, "attachment_id": attachment_id,
            "backend_kind": backend_kind, "backend_id": backend_id,
            "resource_identity": derived_identity,
            "resource_fingerprint": hashlib.sha256(f"{backend_kind}:{derived_identity}".encode("utf-8")).hexdigest(),
        })
        sensitive[evidence_id] = deepcopy(entry)
    return sorted(summaries, key=lambda item: (item["volume_id"], item["attachment_id"])), sensitive


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


def _deep_payload_ids(payload, *keys):
    wanted = set(keys)
    found = []
    stack = [payload]
    visited = 0
    while stack:
        current = stack.pop()
        visited += 1
        if visited > 100_000:
            raise ValueError("API dependency closure exceeds safety bounds")
        if isinstance(current, dict):
            for key, value in current.items():
                if key in wanted:
                    candidates = value if isinstance(value, list) else [value]
                    for candidate in candidates:
                        if isinstance(candidate, dict):
                            candidate = candidate.get("id") or candidate.get("uuid") or candidate.get("port_id")
                        canonical = _canonical_uuid(candidate)
                        if canonical is not None:
                            found.append(canonical)
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
    return sorted(set(found))


def _deep_named_values(payload, *keys):
    wanted = set(keys)
    found = []
    stack = [payload]
    visited = 0
    while stack:
        current = stack.pop()
        visited += 1
        if visited > 100_000:
            raise ValueError("API named dependency closure exceeds safety bounds")
        if isinstance(current, dict):
            for key, value in current.items():
                if key in wanted:
                    candidates = value if isinstance(value, list) else [value]
                    for candidate in candidates:
                        if isinstance(candidate, dict):
                            candidate = candidate.get("store") or candidate.get("id")
                        if isinstance(candidate, str) and _SAFE_ROOT.fullmatch(candidate):
                            found.append(candidate)
                stack.append(value)
        elif isinstance(current, list):
            stack.extend(current)
    return sorted(set(found))


def _catalog_public_origin(payload):
    candidates = []
    if isinstance(payload, dict):
        for key in ("public", "publicURL", "url"):
            if isinstance(payload.get(key), str):
                candidates.append(payload[key])
        endpoints = payload.get("endpoints")
        if isinstance(endpoints, list):
            candidates.extend(
                item.get("url") for item in endpoints
                if isinstance(item, dict)
                and str(item.get("interface", "public")).lower() == "public"
                and isinstance(item.get("url"), str)
            )
    origins = sorted({_endpoint_origin(value) for value in candidates if _endpoint_origin(value) is not None})
    if len(origins) > 1:
        raise ValueError("Glance catalog public origin is ambiguous")
    return origins[0] if origins else None


def _expand_live_api_roots(roots, acquire, side, *, need_glance_catalog=False):
    processed = {category: set() for category in roots}
    image_store_ids = {}
    catalog_origin = None

    def extend(category, values):
        if category not in roots:
            raise ValueError("API dependency category is invalid")
        roots[category].extend(values)
        roots[category] = sorted(set(roots[category]))

    while True:
        work = [
            (category, identity)
            for category in sorted(roots)
            for identity in sorted(roots[category])
            if identity not in processed[category]
        ]
        if not work:
            break
        for category, identity in work:
            processed[category].add(identity)
            payload = None
            if category == "instances":
                payload = acquire(["server", "show", identity, "-f", "json"], f"nova-{side}-server-show-{identity}")
                acquire(["resource", "provider", "allocation", "show", identity, "-f", "json"], f"nova-{side}-placement-allocation-show-{identity}")
                ports = acquire(["port", "list", "--server", identity, "-f", "json"], f"neutron-{side}-port-list-{identity}")
                volumes = acquire(["server", "volume", "list", identity, "-f", "json"], f"cinder-{side}-server-volume-list-{identity}")
                extend("ports", _deep_payload_ids(ports, "id", "ID", "port_id"))
                extend("volumes", _deep_payload_ids(volumes, "id", "ID", "volume_id"))
                extend("images", _deep_payload_ids(payload, "image_id", "image"))
                extend("projects", _deep_payload_ids(payload, "project_id", "tenant_id"))
                extend("flavors", _deep_payload_ids(payload, "flavor_id", "flavor"))
            elif category == "flavors":
                payload = acquire(["flavor", "show", identity, "-f", "json"], f"nova-{side}-flavor-show-{identity}")
            elif category == "ports":
                payload = acquire(["port", "show", identity, "-f", "json"], f"neutron-{side}-port-show-{identity}")
                extend("networks", _deep_payload_ids(payload, "network_id", "floating_network_id"))
                extend("subnets", _deep_payload_ids(payload, "subnet_id"))
                extend("security_groups", _deep_payload_ids(payload, "security_group_ids", "security_groups"))
                extend("qos_policies", _deep_payload_ids(payload, "qos_policy_id"))
                extend("trunks", _deep_payload_ids(payload, "trunk_id"))
            elif category == "networks":
                payload = acquire(["network", "show", identity, "-f", "json"], f"neutron-{side}-network-show-{identity}")
                extend("subnets", _deep_payload_ids(payload, "subnet_ids", "subnets"))
                extend("qos_policies", _deep_payload_ids(payload, "qos_policy_id"))
            elif category == "subnets":
                payload = acquire(["subnet", "show", identity, "-f", "json"], f"neutron-{side}-subnet-show-{identity}")
                extend("networks", _deep_payload_ids(payload, "network_id"))
            elif category == "security_groups":
                payload = acquire(["security", "group", "show", identity, "-f", "json"], f"neutron-{side}-security-group-show-{identity}")
                extend("security_groups", _deep_payload_ids(payload, "remote_group_id"))
                extend("address_groups", _deep_payload_ids(payload, "remote_address_group_id"))
            elif category == "qos_policies":
                payload = acquire(["network", "qos", "policy", "show", identity, "-f", "json"], f"neutron-{side}-qos-policy-show-{identity}")
            elif category == "trunks":
                payload = acquire(["network", "trunk", "show", identity, "-f", "json"], f"neutron-{side}-trunk-show-{identity}")
                extend("ports", _deep_payload_ids(payload, "port_id", "parent_port_id"))
            elif category == "floating_ips":
                payload = acquire(["floating", "ip", "show", identity, "-f", "json"], f"neutron-{side}-floating-ip-show-{identity}")
                extend("ports", _deep_payload_ids(payload, "port_id", "fixed_port_id"))
                extend("networks", _deep_payload_ids(payload, "floating_network_id"))
                extend("routers", _deep_payload_ids(payload, "router_id"))
                extend("qos_policies", _deep_payload_ids(payload, "qos_policy_id"))
            elif category == "routers":
                payload = acquire(["router", "show", identity, "-f", "json"], f"neutron-{side}-router-show-{identity}")
                extend("ports", _deep_payload_ids(payload, "port_id"))
                extend("networks", _deep_payload_ids(payload, "network_id"))
            elif category == "address_groups":
                payload = acquire(["address", "group", "show", identity, "-f", "json"], f"neutron-{side}-address-group-show-{identity}")
            elif category == "volumes":
                payload = acquire(["volume", "show", identity, "-f", "json"], f"cinder-{side}-volume-show-{identity}")
                extend("volume_types", _deep_payload_ids(payload, "volume_type_id", "type_id"))
                extend("cinder_services", _deep_payload_ids(payload, "service_uuid"))
                extend("snapshots", _deep_payload_ids(payload, "snapshot_id"))
                extend("volumes", _deep_payload_ids(payload, "source_volid", "source_volume_id"))
                extend("attachments", _deep_payload_ids(payload, "attachment_id", "attachments"))
                extend("groups", _deep_payload_ids(payload, "group_id", "consistencygroup_id"))
                extend("group_snapshots", _deep_payload_ids(payload, "group_snapshot_id"))
                extend("encryption_keys", _payload_ids(payload, "encryption_key_id", "encryption_key_uuid", "secret_id", "key_id"))
            elif category == "attachments":
                payload = acquire(["volume", "attachment", "show", identity, "-f", "json"], f"cinder-{side}-attachment-show-{identity}")
                extend("volumes", _deep_payload_ids(payload, "volume_id"))
                extend("instances", _deep_payload_ids(payload, "server_id", "instance_uuid"))
            elif category == "volume_types":
                payload = acquire(["volume", "type", "show", identity, "-f", "json"], f"cinder-{side}-volume-type-show-{identity}")
                extend("qos_specs", _deep_payload_ids(payload, "qos_specs_id", "qos_spec_id"))
                extend("encryption_keys", _deep_payload_ids(payload, "key_id", "secret_id"))
            elif category == "qos_specs":
                payload = acquire(["volume", "qos", "show", identity, "-f", "json"], f"cinder-{side}-qos-show-{identity}")
            elif category == "snapshots":
                payload = acquire(["volume", "snapshot", "show", identity, "-f", "json"], f"cinder-{side}-snapshot-show-{identity}")
                extend("volumes", _deep_payload_ids(payload, "volume_id"))
                extend("group_snapshots", _deep_payload_ids(payload, "group_snapshot_id"))
            elif category == "groups":
                payload = acquire(["volume", "group", "show", identity, "-f", "json"], f"cinder-{side}-group-show-{identity}")
                extend("volume_types", _deep_payload_ids(payload, "volume_types", "volume_type_id"))
            elif category == "group_snapshots":
                payload = acquire(["volume", "group", "snapshot", "show", identity, "-f", "json"], f"cinder-{side}-group-snapshot-show-{identity}")
                extend("groups", _deep_payload_ids(payload, "group_id"))
            elif category == "encryption_keys":
                payload = acquire(["secret", "get", identity, "-f", "json"], f"cinder-{side}-secret-get-{identity}")
            elif category == "images":
                payload = acquire(["image", "show", identity, "-f", "json"], f"glance-{side}-image-show-{identity}")
                members = acquire(["image", "member", "list", identity, "-f", "json"], f"glance-{side}-image-member-list-{identity}")
                stores = _deep_named_values(payload, "store", "stores")
                image_store_ids[identity] = stores
                extend("glance_stores", stores)
                member_ids = _deep_payload_ids(members, "member_id", "project_id", "tenant_id")
                extend("image_members", member_ids)
                extend("projects", member_ids)

    if roots["volumes"] or roots["cinder_services"]:
        acquire(["volume", "service", "list", "--long", "-f", "json"], f"cinder-{side}-volume-service-list")
    if roots["images"] or need_glance_catalog:
        stores = acquire(["image", "stores", "info", "-f", "json"], f"glance-{side}-stores-info")
        extend("glance_stores", _deep_named_values(stores, "id", "store"))
        catalog = acquire(["catalog", "show", "glance", "-f", "json"], f"glance-{side}-catalog-show")
        catalog_origin = _catalog_public_origin(catalog)
    return catalog_origin, {key: sorted(value) for key, value in sorted(image_store_ids.items())}


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
            "encryption_keys": [], "image_members": [], "glance_stores": [],
        }
        if args.root_manifest is not None:
            manifest = _read_protected_json(args.root_manifest)
            if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "side", "roots"} or manifest.get("schema_version") != "openstack-rehome-root-manifest/v1alpha1" or manifest.get("side") != args.side or not isinstance(manifest["roots"], dict):
                raise ValueError("root manifest is invalid")
            _root_filter_values({"roots": manifest["roots"]})
            for category, values in manifest["roots"].items():
                if category not in roots or not isinstance(values, list):
                    raise ValueError("root manifest category is invalid")
                roots[category].extend(values)
        roots = {key: sorted(dict.fromkeys(values)) for key, values in roots.items()}
        service_command = ["compute", "service", "list", "--host", args.rehome_host, "-f", "json"]
        services = acquire(service_command, f"nova-{args.side}-compute-service-list-{args.rehome_host}")
        roots["services"] = _deep_payload_ids(services, "uuid", "UUID")
        hypervisor_command = ["hypervisor", "show", args.rehome_host, "-f", "json"]
        hypervisor = acquire(hypervisor_command, f"nova-{args.side}-hypervisor-show-{args.rehome_host}")
        roots["compute_nodes"] = _deep_payload_ids(hypervisor, "uuid")
        provider_command = ["resource", "provider", "list", "--name", args.rehome_host, "-f", "json"]
        acquire(provider_command, f"nova-{args.side}-resource-provider-list-{args.rehome_host}")
        catalog_origin, image_store_ids = _expand_live_api_roots(
            roots, acquire, args.side, need_glance_catalog=args.probe_config is not None
        )
        roots = {key: sorted(dict.fromkeys(values)) for key, values in roots.items()}
        snapshot = parse_information_schema(args.information_schema)
        api_result = {
            "rehome_host": args.rehome_host, "instances": list(roots["instances"]),
            "roots": roots, "available_tables": sorted(snapshot.tables),
            "openstack": cached,
            "image_store_ids": image_store_ids,
        }
        if catalog_origin is not None:
            api_result["glance_catalog_origin"] = catalog_origin
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
        "capability_evidence", "probe_statuses",
        "glance_catalog_origin", "image_store_ids",
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
            _read_protected_json(args.probe_config), ReadOnlyRunner(),
            catalog_origin=payload["api_result"].get("glance_catalog_origin"),
            image_store_ids=payload["api_result"].get("image_store_ids"),
        )
        for key, value in probe_results.items():
            if key in payload["api_result"]:
                raise ValueError("probe result identity is duplicated")
            payload["api_result"][key] = value
    if args.capability_config is not None:
        capability = _read_protected_json(args.capability_config)
        required = {
            "schema_version", "target_manage_outputs", "target_image_inspects",
            "target_runtime_outputs", "target_virsh_argv", "target_qemu_argv",
            "schema_capabilities", "capability_evidence",
        }
        allowed = required | {"probe_statuses"}
        if (
            not isinstance(capability, dict) or not required.issubset(capability)
            or not set(capability).issubset(allowed)
            or capability.get("schema_version") != "openstack-rehome-target-capability-input/v1alpha1"
        ):
            raise ValueError("target capability input is invalid")
        for key in set(capability) - {"schema_version"}:
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
    api_base = json.loads(render_json({"schema_version": API_RESULT_VERSION, "side": args.side, "api_result": payload["api_result"]}))
    filters_base = json.loads(render_json({"schema_version": "openstack-rehome-uuid-filters/v1alpha1", "side": args.side, "filters": filters}))
    plan_base = json.loads(render_json({"schema_version": PLAN_VERSION, "side": args.side, "queries": queries}))
    binding = _phase_binding(api_base, filters_base, plan_base, key=_load_phase_key(args, fixture=fixture_mode), trust_domain="fixture" if fixture_mode else "live")
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


def _verified_query_plan(args):
    api = _read_json(args.api_result)
    filters_document = _read_json(Path(args.api_result).with_name("uuid-filters.json"))
    plan = _read_json(Path(args.api_result).with_name("db-query-plan.json"))
    if not isinstance(api, dict) or set(api) != {"schema_version", "side", "api_result", "binding_sha256"} or api.get("schema_version") != API_RESULT_VERSION or api.get("side") != args.side:
        raise ValueError("API result envelope is invalid")
    if not isinstance(filters_document, dict) or set(filters_document) != {"schema_version", "side", "filters", "binding_sha256"} or filters_document.get("schema_version") != "openstack-rehome-uuid-filters/v1alpha1" or filters_document.get("side") != args.side or not isinstance(filters_document.get("filters"), list):
        raise ValueError("UUID filter envelope is invalid")
    if not isinstance(plan, dict) or set(plan) != {"schema_version", "side", "queries", "binding_sha256"} or plan.get("schema_version") != PLAN_VERSION or plan.get("side") != args.side or not isinstance(plan["queries"], list) or not plan["queries"] or len(plan["queries"]) > _MAX_QUERIES:
        raise ValueError("DB query plan is invalid")
    fixture_mode = bool(getattr(args, "fixture_phase", False))
    if fixture_mode and any((getattr(args, "phase_key_file", None), getattr(args, "phase_key_env", None))):
        raise ValueError("fixture phase trust anchor input is forbidden")
    api_base = {key: value for key, value in api.items() if key != "binding_sha256"}
    filters_base = {key: value for key, value in filters_document.items() if key != "binding_sha256"}
    plan_base = {key: value for key, value in plan.items() if key != "binding_sha256"}
    binding = _phase_binding(
        api_base, filters_base, plan_base,
        key=_load_phase_key(args, fixture=fixture_mode),
        trust_domain="fixture" if fixture_mode else "live",
    )
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
    for query_index, query in enumerate(plan["queries"], start=1):
        expected = {"query_id", "schema", "table", "columns", "filters", "sql", "jsonl_file", "rc_file"}
        if not isinstance(query, dict) or set(query) != expected or not query["filters"]:
            raise ValueError("DB query is invalid")
        schema = validate_identifier(query["schema"])
        table = validate_identifier(query["table"])
        if not isinstance(query["columns"], list) or not query["columns"]:
            raise ValueError("DB query columns are invalid")
        columns = [validate_identifier(value) for value in query["columns"]]
        if len(columns) != len(set(columns)) or not isinstance(query["filters"], dict):
            raise ValueError("DB query scope is invalid")
        normalized_filters = {
            validate_identifier(column): values
            for column, values in query["filters"].items()
        }
        if any(not isinstance(values, list) or not values for values in normalized_filters.values()):
            raise ValueError("DB query scope is invalid")
        where = "(" + ") OR (".join(
            _scoped_in(column, normalized_filters[column])
            for column in sorted(normalized_filters)
        ) + ")"
        expected_sql = build_json_row_query(schema, table, columns, where)
        expected_query_id = f"{query_index:04d}-{schema}-{table}"
        if (
            query["sql"] != expected_sql
            or query["query_id"] != expected_query_id
            or query["jsonl_file"] != expected_query_id + ".jsonl"
            or query["rc_file"] != expected_query_id + ".rc"
        ):
            raise ValueError("DB query identity or SQL is invalid")
        validate_select_only_sql(query["sql"])
    if _has_symlink_component(args.information_schema) or not args.information_schema.is_file() or args.information_schema.stat().st_size > _MAX_FILE:
        raise ValueError("information_schema input is unsafe")
    snapshot = parse_information_schema(args.information_schema)
    if not snapshot.tables:
        raise ValueError("information_schema evidence is empty")
    expected_tables = _expected_plan_tables(
        args.side, api["api_result"]["roots"], snapshot.tables.keys()
    )
    if {f"{query['schema']}.{query['table']}" for query in plan["queries"]} != expected_tables:
        raise ValueError("DB query plan differs from live schema scope")
    return plan


def _write_verified_plan(path, plan):
    path = _safe_out(path)
    staging = Path(tempfile.mkdtemp(prefix=f".{path.name}.staging-", dir=path.parent))
    try:
        query_ids = [query["query_id"] for query in plan["queries"]]
        marker = {
            "schema_version": "openstack-rehome-verified-plan/v1alpha1",
            "side": plan["side"],
            "plan_sha256": hashlib.sha256(_canonical(plan).encode("utf-8")).hexdigest(),
            "binding_sha256": plan["binding_sha256"],
            "query_ids": query_ids,
        }
        marker_path = staging / "verified-plan.json"
        marker_path.write_text(render_json(marker), encoding="utf-8")
        marker_path.chmod(0o640)
        for query in plan["queries"]:
            sql_path = staging / f"{query['query_id']}.sql"
            sql_path.write_text(query["sql"] + "\n", encoding="utf-8")
            sql_path.chmod(0o600)
        if path.exists():
            raise ValueError("verified output directory already exists")
        os.replace(staging, path)
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def _verify_phase(args):
    _write_verified_plan(args.out, _verified_query_plan(args))


def _closure_checks(side, api_cache_misses, db_cache_misses):
    checks = []
    if api_cache_misses:
        checks.append(CheckResult(
            f"control.{side}.api-closure", "UNKNOWN",
            "required API dependency was discovered only after DB acquisition",
        ).to_dict())
    if db_cache_misses:
        checks.append(CheckResult(
            f"control.{side}.db-closure", "UNKNOWN",
            "required scoped DB dependency is absent from reviewed cache",
        ).to_dict())
    return checks


def _combine_phase(args):
    api = _read_json(args.api_result)
    filters_document = _read_json(Path(args.api_result).with_name("uuid-filters.json"))
    plan = _read_json(Path(args.api_result).with_name("db-query-plan.json"))
    if not isinstance(api, dict) or set(api) != {"schema_version", "side", "api_result", "binding_sha256"} or api.get("schema_version") != API_RESULT_VERSION or api.get("side") != args.side:
        raise ValueError("API result envelope is invalid")
    if not isinstance(filters_document, dict) or set(filters_document) != {"schema_version", "side", "filters", "binding_sha256"} or filters_document.get("schema_version") != "openstack-rehome-uuid-filters/v1alpha1" or filters_document.get("side") != args.side or not isinstance(filters_document.get("filters"), list):
        raise ValueError("UUID filter envelope is invalid")
    if not isinstance(plan, dict) or set(plan) != {"schema_version", "side", "queries", "binding_sha256"} or plan.get("schema_version") != PLAN_VERSION or plan.get("side") != args.side or not isinstance(plan["queries"], list) or not plan["queries"] or len(plan["queries"]) > _MAX_QUERIES:
        raise ValueError("DB query plan is invalid")
    fixture_mode = bool(getattr(args, "fixture_phase", False))
    if fixture_mode and any((getattr(args, "phase_key_file", None), getattr(args, "phase_key_env", None))):
        raise ValueError("fixture phase trust anchor input is forbidden")
    api_base = {key: value for key, value in api.items() if key != "binding_sha256"}
    filters_base = {key: value for key, value in filters_document.items() if key != "binding_sha256"}
    plan_base = {key: value for key, value in plan.items() if key != "binding_sha256"}
    binding = _phase_binding(api_base, filters_base, plan_base, key=_load_phase_key(args, fixture=fixture_mode), trust_domain="fixture" if fixture_mode else "live")
    if {api["binding_sha256"], filters_document["binding_sha256"], plan["binding_sha256"]} != {binding}:
        raise ValueError("API/filter/query phase binding is invalid")
    sensitive_evidence = {}
    if getattr(args, "cinder_sensitive_evidence", None) is not None:
        if fixture_mode:
            raise ValueError("fixture Cinder sensitive evidence is forbidden")
        summaries, sensitive_evidence = _load_cinder_sensitive_evidence(
            args.cinder_sensitive_evidence, args.side
        )
        api["api_result"]["cinder_connection_summaries"] = summaries
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
    collectors, cache_misses, db_cache_misses = _compose_collectors(
        args.side, api["api_result"], records, evidence, snapshot,
        sensitive_evidence,
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
        "checks": _closure_checks(args.side, cache_misses, db_cache_misses),
        "schema_capabilities": capabilities,
        "uuid_filters": side_filters,
        "evidence_index": evidence_index,
        # Raw protected connector/connection data is consumed only in memory.
        # The caller-owned protected input remains the sole persisted copy.
        "sensitive_evidence": {},
    }
    _write_directory(args.out, {"control-result.json": combined})


def main(argv=None):
    parser = argparse.ArgumentParser(description="Collect read-only control-plane facts")
    parser.add_argument("--phase", choices=("api", "verify", "combine"), required=True)
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
    parser.add_argument("--cinder-sensitive-evidence", type=Path)
    parser.add_argument("--fixture-phase", action="store_true")
    trust = parser.add_mutually_exclusive_group()
    trust.add_argument("--phase-key-file", type=Path)
    trust.add_argument("--phase-key-env")
    args = parser.parse_args(argv)
    try:
        if args.phase == "api":
            if any((args.api_result, args.db_jsonl_dir, args.schema_policy, args.fixture_phase, args.cinder_sensitive_evidence)):
                raise ValueError("combine arguments are forbidden in API phase")
            if args.fixture is not None and any((args.rehome_host, args.cloud, args.clouds_file, args.container, args.information_schema, args.root_manifest, args.probe_config, args.capability_config, args.phase_key_file, args.phase_key_env)):
                raise ValueError("fixture and live API arguments are mutually exclusive")
            _api_phase(args)
        elif args.phase == "verify":
            if args.fixture is not None or args.db_jsonl_dir is not None or args.schema_policy is not None or args.probe_config is not None or args.root_manifest is not None or args.capability_config is not None or args.cinder_sensitive_evidence is not None or any((args.rehome_host, args.cloud, args.clouds_file, args.container)) or not all((args.api_result, args.information_schema)):
                raise ValueError("verify arguments are incomplete")
            _verify_phase(args)
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
