from copy import deepcopy
import hashlib
import re
import uuid
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple
from urllib.parse import urlparse

from .contract import CheckResult, CollectorResult, DependencyEdge, ResourceNode


_FIXTURE_POLICY_TOKEN = object()
_FIXTURE_ALIAS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@#-]{0,127}$")
_SAFE_TEXT = re.compile(r"^[^\x00-\x1f\x7f]{1,1024}$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@+-]{0,127}$")
_SENSITIVE = re.compile(
    r"password|passwd|token|secret|credential|authorization|auth[_-]|key_id|private",
    re.IGNORECASE,
)
_IMAGE_STATES = {
    "active", "queued", "saving", "killed", "deleted", "pending_delete",
    "deactivated", "uploading", "importing",
}
_NOT_DATA_READY = _IMAGE_STATES - {"active"}
_VISIBILITIES = {"public", "private", "shared", "community"}
_MEMBER_STATES = {"pending", "accepted", "rejected"}
_HASH_LENGTHS = {
    "md5": 32,
    "sha1": 40,
    "sha224": 56,
    "sha256": 64,
    "sha384": 96,
    "sha512": 128,
}
_KNOWN_LOCATION_SCHEMES = {
    "file", "filesystem", "rbd", "swift", "swift+http", "swift+https",
    "s3", "s3+http", "s3+https", "http", "https", "cinder",
}
_DISK_FORMATS = {
    "aki", "ami", "ari", "iso", "ploop", "qcow2", "raw", "vdi",
    "vhd", "vhdx", "vmdk",
}
_CONTAINER_FORMATS = {"aki", "ami", "ari", "bare", "docker", "ova", "ovf"}
_REASONS = {"local_root", "ephemeral_root", "rebuild", "rescue", "volume_image_metadata"}
_PROPERTY_FIELDS = {
    "hw_architecture", "hw_disk_bus", "hw_machine_type",
    "hw_qemu_guest_agent", "hw_scsi_model", "hw_vif_model",
    "hypervisor_type", "img_config_drive", "os_distro", "os_type",
    "os_version", "vm_mode",
}
_MAX_BYTES = 64 * 1024
_MAX_DEPTH = 16
_MAX_NODES = 4096


def _id(value: object, allow_fixture_aliases: bool = False) -> Optional[str]:
    if not isinstance(value, str):
        return None
    try:
        normalized = str(uuid.UUID(value))
    except (ValueError, AttributeError):
        normalized = None
    if normalized == value:
        return value
    if allow_fixture_aliases and _FIXTURE_ALIAS.fullmatch(value):
        return value
    return None


def _field(payload: object, *names: str) -> Any:
    if not isinstance(payload, Mapping):
        return None
    for name in names:
        if name in payload:
            return payload[name]
    normalized = {
        re.sub(r"[ -]+", "_", str(key).lower()): value
        for key, value in payload.items()
    }
    for name in names:
        key = re.sub(r"[ -]+", "_", name.lower())
        if key in normalized:
            return normalized[key]
    return None


def _bounded(value: object) -> bool:
    stack = [(value, 0)]
    nodes = 0
    byte_count = 0
    try:
        while stack:
            current, depth = stack.pop()
            nodes += 1
            if nodes > _MAX_NODES or depth > _MAX_DEPTH:
                return False
            if isinstance(current, Mapping):
                for key, item in current.items():
                    if not isinstance(key, str):
                        return False
                    byte_count += len(key.encode("utf-8"))
                    stack.append((item, depth + 1))
            elif isinstance(current, (list, tuple)):
                stack.extend((item, depth + 1) for item in current)
            elif current is not None and not isinstance(current, (str, int, float, bool)):
                return False
            elif isinstance(current, str):
                byte_count += len(current.encode("utf-8"))
            if byte_count > _MAX_BYTES:
                return False
        return True
    except (Exception, MemoryError, RecursionError):
        return False


def _dedupe(values: Iterable[str]) -> List[str]:
    return list(dict.fromkeys(value for value in values if value))


def _safe_string(value: object) -> Optional[str]:
    if isinstance(value, str) and _SAFE_TEXT.fullmatch(value) and _SENSITIVE.search(value) is None:
        return value
    return None


def _safe_name(value: object) -> Optional[str]:
    if isinstance(value, str) and _SAFE_NAME.fullmatch(value) and _SENSITIVE.search(value) is None:
        return value
    return None


def _safe_properties(value: object) -> Tuple[Dict[str, Any], bool]:
    if value is None:
        return {}, True
    if not isinstance(value, Mapping) or not _bounded(value):
        return {}, False
    result: Dict[str, Any] = {}
    complete = True
    for key, item in value.items():
        if key not in _PROPERTY_FIELDS:
            complete = False
            continue
        if item is None or isinstance(item, bool) or (
            isinstance(item, int) and not isinstance(item, bool)
        ):
            result[key] = item
        elif _safe_string(item) is not None:
            result[key] = item
        else:
            complete = False
    return result, complete


def _hash(payload: Mapping[str, Any]) -> Tuple[Optional[Dict[str, str]], Optional[str]]:
    algorithm = _field(payload, "os_hash_algo")
    value = _field(payload, "os_hash_value")
    if algorithm is None and value is None:
        return None, "Glance preferred hash evidence missing"
    if not isinstance(algorithm, str) or algorithm not in _HASH_LENGTHS or not isinstance(value, str):
        return None, "Glance preferred hash evidence invalid"
    if len(value) != _HASH_LENGTHS[algorithm] or re.fullmatch(r"[0-9a-f]+", value) is None:
        return None, "Glance preferred hash evidence invalid"
    return {"algorithm": algorithm, "value": value}, None


def _legacy_checksum(value: object) -> Tuple[Optional[str], Optional[str]]:
    if value is None:
        return None, None
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{32}", value) is None:
        return None, "Glance legacy checksum invalid"
    return value, None


def _store_ids(value: object) -> Optional[List[str]]:
    if isinstance(value, str):
        raw = [item.strip() for item in value.split(",")]
    elif isinstance(value, (list, tuple)):
        raw = list(value)
    else:
        return None
    if not raw or any(_safe_name(item) is None for item in raw):
        return None
    normalized = [str(item) for item in raw]
    if len(set(normalized)) != len(normalized):
        return None
    return normalized


def _location(value: object) -> Optional[Tuple[str, str, str]]:
    if not isinstance(value, Mapping) or not _bounded(value):
        return None
    raw_url = value.get("url")
    metadata = value.get("metadata")
    if not isinstance(raw_url, str) or not isinstance(metadata, Mapping):
        return None
    store_id = _safe_name(_field(metadata, "store", "store_id", "backend"))
    if store_id is None:
        return None
    try:
        parsed = urlparse(raw_url)
        parsed.port
    except (ValueError, TypeError):
        return None
    if (
        _safe_name(parsed.scheme) is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path
    ):
        return None
    scheme = parsed.scheme.lower()
    if scheme != "file" and parsed.hostname is None:
        return None
    if scheme == "file" and not parsed.path.startswith("/"):
        return None
    return store_id, scheme, raw_url


def _sanitize_evidence(evidence: object) -> Optional[Dict[str, str]]:
    if not isinstance(evidence, Mapping):
        return None
    for name in ("evidence_id", "id"):
        value = evidence.get(name)
        if _safe_name(value) is not None:
            return {name: value}
    return None


class GlanceCollector:
    def __init__(self, client, side: str, *, _fixture_policy=None) -> None:
        if side not in {"source", "target"}:
            raise ValueError("Glance side must be source or target")
        self.client = client
        self.side = side
        self._allow_fixture_aliases = _fixture_policy is _FIXTURE_POLICY_TOKEN

    @classmethod
    def for_fixture(cls, client, side: str):
        if getattr(client, "_fixture_only", False) is not True:
            raise ValueError("fixture-only Glance client required")
        return cls(client, side, _fixture_policy=_FIXTURE_POLICY_TOKEN)

    def collect(self, image_requirements) -> CollectorResult:
        result = CollectorResult(service="glance", side=self.side)
        if self._allow_fixture_aliases:
            result._fixture_aliases = _FIXTURE_POLICY_TOKEN
        requirements = self._requirements(image_requirements)
        if requirements is None:
            result.blockers.append("Glance image requirements invalid")
            return result

        stores_payload, stores_evidence = self._api(
            ["image", "stores", "info", "-f", "json"],
            f"glance-{self.side}-stores-info", result, required=any(
                item["required"] for item in requirements.values()
            ),
        )
        enabled_stores, default_store = self._inventory(stores_payload, result)
        if stores_evidence:
            result.evidence.append(stores_evidence)
        inventory_node = ResourceNode(
            "glance_store_inventory", f"{self.side}-enabled-stores", self.side,
            {
                "enabled_store_ids": sorted(enabled_stores),
                "default_store_id": default_store,
            },
            [next(iter(stores_evidence.values()))] if stores_evidence else [],
        )
        result.nodes.append(inventory_node)

        for image_id, requirement in requirements.items():
            self._collect_image(image_id, requirement, enabled_stores, result)

        keys = {node.key for node in result.nodes}
        for edge in result.edges:
            if edge.required and (edge.source not in keys or edge.target not in keys):
                result.blockers.append("Glance required dependency evidence missing")
        result.blockers[:] = _dedupe(result.blockers)
        result.unknowns[:] = _dedupe(result.unknowns)
        return result

    def _requirements(self, value) -> Optional[Dict[str, Dict[str, Any]]]:
        if not isinstance(value, Mapping) or not value or not _bounded(value):
            return None
        result: Dict[str, Dict[str, Any]] = {}
        for raw_id, raw_requirement in value.items():
            image_id = _id(raw_id, self._allow_fixture_aliases)
            if image_id is None or not isinstance(raw_requirement, Mapping):
                return None
            required = raw_requirement.get("required")
            reason = raw_requirement.get("reason")
            bdm_proof = raw_requirement.get("bdm_proves_no_local_root", False)
            runtime_proof = raw_requirement.get("runtime_proves_no_local_root", False)
            if (
                not isinstance(required, bool)
                or reason not in _REASONS
                or not isinstance(bdm_proof, bool)
                or not isinstance(runtime_proof, bool)
                or (not required and reason != "volume_image_metadata")
            ):
                return None
            result[image_id] = {
                "required": required,
                "reason": reason,
                "bdm_proves_no_local_root": bdm_proof,
                "runtime_proves_no_local_root": runtime_proof,
            }
        return result

    def _api(
        self, command, evidence_id, result, required=True,
        tolerate_missing=False,
    ):
        try:
            payload, evidence = self.client.json(command, evidence_id, required=required)
        except Exception as error:
            status = getattr(error, "status_code", None)
            message = "Glance required API object unavailable"
            if tolerate_missing and status == 404:
                pass
            elif required and status in {403, 404}:
                result.blockers.append(message)
            else:
                result.unknowns.append("Glance API evidence unavailable")
            return None, None
        if not _bounded(payload):
            result.unknowns.append("Glance API evidence exceeds safety bounds")
            return None, _sanitize_evidence(evidence)
        return deepcopy(payload), _sanitize_evidence(evidence)

    def _inventory(self, payload, result) -> Tuple[Set[str], Optional[str]]:
        if not isinstance(payload, Mapping):
            result.unknowns.append("Glance enabled store inventory unavailable")
            return set(), None
        raw_stores = payload.get("stores")
        if not isinstance(raw_stores, list) or not raw_stores:
            result.unknowns.append("Glance enabled store inventory invalid")
            return set(), None
        values: List[str] = []
        defaults: List[str] = []
        for item in raw_stores:
            store_id = _safe_name(_field(item, "id")) if isinstance(item, Mapping) else None
            if store_id is None:
                result.unknowns.append("Glance enabled store inventory invalid")
                return set(), None
            values.append(store_id)
            if "default" in item:
                is_default = item.get("default")
                if not isinstance(is_default, bool):
                    result.unknowns.append("Glance default store evidence invalid")
                    return set(values), None
                if is_default:
                    defaults.append(store_id)
        if len(set(values)) != len(values):
            result.unknowns.append("Glance enabled store inventory ambiguous")
            return set(), None
        if len(defaults) != 1:
            result.unknowns.append("Glance default store evidence invalid")
            default = None
        else:
            default = defaults[0]
        return set(values), default

    def _collect_image(self, image_id, requirement, enabled_stores, result):
        required = requirement["required"]
        proven_historical = (
            not required
            and requirement["reason"] == "volume_image_metadata"
            and requirement["bdm_proves_no_local_root"]
            and requirement["runtime_proves_no_local_root"]
        )
        if not required and not proven_historical:
            result.unknowns.append(
                f"Glance historical image requirement proof incomplete: {image_id}"
            )
            return

        image, image_evidence = self._api(
            ["image", "show", image_id, "-f", "json"],
            f"glance-{self.side}-image-show-{image_id}", result, required=required,
            tolerate_missing=proven_historical,
        )
        if image_evidence:
            result.evidence.append(image_evidence)
        if not isinstance(image, Mapping):
            if proven_historical:
                result.checks.append(CheckResult(
                    f"glance.{self.side}.historical.{image_id}", "WARN",
                    "Historical volume image metadata is unavailable but local-root absence is proven",
                    [f"image:{image_id}"],
                ))
            return
        members, member_evidence = self._api(
            ["image", "member", "list", image_id, "-f", "json"],
            f"glance-{self.side}-image-member-list-{image_id}", result, required=required,
        )
        if member_evidence:
            result.evidence.append(member_evidence)

        facts, store_ids, locations, valid = self._image_facts(image_id, image, result)
        if facts is None:
            return
        facts["required_for_rehome"] = required
        facts["requirement_reason"] = requirement["reason"]
        image_node = ResourceNode(
            "image", image_id, self.side, facts,
            [next(iter(image_evidence.values()))] if image_evidence else [],
        )
        result.nodes.append(image_node)

        member_nodes = self._members(image_id, members, result)
        for member_node in member_nodes:
            if member_evidence:
                member_node.evidence_ids.append(next(iter(member_evidence.values())))
            result.nodes.append(member_node)
            result.edges.append(DependencyEdge(
                image_node.key, member_node.key, "shared_with", required and facts.get("visibility") == "shared"
            ))

        location_keys: Set[Tuple[str, str, str]] = set()
        for index, (store_id, scheme, raw_url) in enumerate(locations):
            fingerprint = hashlib.sha256(raw_url.encode("utf-8")).hexdigest()
            location_id = f"{image_id}:{store_id}:{fingerprint}"
            location_node = ResourceNode(
                "image_location", location_id, self.side,
                {
                    "image_id": image_id,
                    "store_id": store_id,
                    "scheme": scheme,
                    "ordinal": index,
                    "location_fingerprint": fingerprint,
                },
            )
            result.nodes.append(location_node)
            location_keys.add((store_id, scheme, raw_url))
            result.edges.append(DependencyEdge(
                image_node.key, location_node.key, "has_location", required
            ))
            result.edges.append(DependencyEdge(
                location_node.key, f"glance_store:{store_id}", "stored_in", required
            ))

        for store_id in store_ids:
            schemes = sorted({
                scheme for candidate, scheme, _ in location_keys
                if candidate == store_id
            })
            store_node = ResourceNode(
                "glance_store", store_id, self.side,
                {"enabled": store_id in enabled_stores, "location_schemes": schemes},
            )
            result.nodes.append(store_node)
            result.edges.append(DependencyEdge(
                image_node.key, store_node.key, "requires_store", required
            ))
            if store_id not in enabled_stores:
                valid = False
                (result.blockers if required else result.unknowns).append(
                    f"Glance referenced store not enabled: {store_id}"
                )
            if not schemes or any(scheme not in _KNOWN_LOCATION_SCHEMES for scheme in schemes):
                valid = False
                result.unknowns.append(f"Glance store readiness unsupported: {store_id}")
                result.checks.append(CheckResult(
                    f"glance.{self.side}.store.{store_id}", "UNKNOWN",
                    "Glance store backend readiness is unsupported",
                    [store_node.key],
                ))
            elif store_id in enabled_stores:
                result.checks.append(CheckResult(
                    f"glance.{self.side}.store.{store_id}", "PASS",
                    "Glance store is enabled and location metadata is typed",
                    [store_node.key],
                ))

        if proven_historical:
            result.checks.append(CheckResult(
                f"glance.{self.side}.historical.{image_id}", "WARN",
                "Historical image is not required because BDM and runtime prove no local root",
                [image_node.key],
            ))
            return

        if not valid:
            return
        probe = getattr(self.client, "probe_image_data", None)
        if not callable(probe):
            result.unknowns.append(f"Glance image data probe unavailable: {image_id}")
            return
        try:
            check = probe(image_id, facts["size"], required)
        except Exception:
            result.unknowns.append(f"Glance image data probe failed: {image_id}")
            return
        if not isinstance(check, CheckResult) or check.status not in {"PASS", "WARN", "BLOCKED", "UNKNOWN"}:
            result.unknowns.append(f"Glance image data probe invalid: {image_id}")
            return
        sanitized_check = CheckResult(
            f"glance.{self.side}.image-data.{image_id}",
            check.status,
            {
                "PASS": "Glance image data byte is readable",
                "WARN": "Glance image data probe completed with warning",
                "BLOCKED": "Glance image data probe blocked",
                "UNKNOWN": "Glance image data probe is inconclusive",
            }[check.status],
            [image_node.key],
        )
        result.checks.append(sanitized_check)
        if required and sanitized_check.status == "BLOCKED":
            result.blockers.append(f"Glance required image data blocked: {image_id}")
        elif required and sanitized_check.status == "UNKNOWN":
            result.unknowns.append(f"Glance required image data unknown: {image_id}")

    def _image_facts(self, image_id, image, result):
        valid = True
        if _id(_field(image, "id"), self._allow_fixture_aliases) != image_id:
            result.blockers.append(f"Glance image API UUID mismatch: {image_id}")
            return None, [], [], False
        status = _field(image, "status")
        if not isinstance(status, str) or status not in _IMAGE_STATES:
            result.unknowns.append(f"Glance image status invalid: {image_id}")
            valid = False
        elif status in _NOT_DATA_READY:
            result.blockers.append(f"Glance image is not data-ready: {image_id}")
            valid = False
        size = _field(image, "size")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            result.blockers.append(f"Glance image size invalid: {image_id}")
            valid = False
        visibility = _field(image, "visibility")
        if not isinstance(visibility, str) or visibility not in _VISIBILITIES:
            result.unknowns.append(f"Glance image visibility invalid: {image_id}")
            valid = False
        owner = _id(_field(image, "owner"), self._allow_fixture_aliases)
        if owner is None:
            result.blockers.append(f"Glance image owner invalid: {image_id}")
            valid = False
        protected = _field(image, "protected")
        if not isinstance(protected, bool):
            result.unknowns.append(f"Glance image protected flag invalid: {image_id}")
            valid = False
        store_ids = _store_ids(_field(image, "stores"))
        if store_ids is None:
            result.blockers.append(f"Glance image store metadata invalid: {image_id}")
            store_ids = []
            valid = False
        raw_locations = _field(image, "locations")
        locations: List[Tuple[str, str, str]] = []
        if not isinstance(raw_locations, list) or not raw_locations:
            result.blockers.append(f"Glance image locations missing: {image_id}")
            valid = False
        else:
            for raw_location in raw_locations:
                normalized = _location(raw_location)
                if normalized is None:
                    result.unknowns.append(f"Glance image location invalid: {image_id}")
                    valid = False
                    continue
                locations.append(normalized)
            if len(set(locations)) != len(locations):
                result.blockers.append(f"Glance image locations ambiguous: {image_id}")
                valid = False
            if set(store_ids) != {store_id for store_id, _, _ in locations}:
                result.blockers.append(f"Glance image store/location mismatch: {image_id}")
                valid = False
        preferred_hash, hash_error = _hash(image)
        checksum, checksum_error = _legacy_checksum(_field(image, "checksum"))
        if hash_error:
            result.unknowns.append(f"{hash_error}: {image_id}")
            valid = False
        if checksum_error:
            result.unknowns.append(f"{checksum_error}: {image_id}")
            valid = False
        tags = _field(image, "tags")
        if not isinstance(tags, list) or any(_safe_name(item) is None for item in tags) or len(tags) != len(set(tags)):
            result.unknowns.append(f"Glance image tags invalid: {image_id}")
            tags = []
            valid = False
        properties, complete_properties = _safe_properties(_field(image, "properties"))
        for property_name in sorted(_PROPERTY_FIELDS):
            top_level = _field(image, property_name)
            if top_level is None:
                continue
            normalized_property, property_complete = _safe_properties(
                {property_name: top_level}
            )
            if not property_complete or property_name not in normalized_property:
                complete_properties = False
                continue
            if (
                property_name in properties
                and properties[property_name] != normalized_property[property_name]
            ):
                complete_properties = False
                continue
            properties[property_name] = normalized_property[property_name]
        if not complete_properties:
            result.unknowns.append(f"Glance image properties incomplete: {image_id}")

        facts: Dict[str, Any] = {
            "status": status if status in _IMAGE_STATES else None,
            "size": size if isinstance(size, int) and not isinstance(size, bool) and size > 0 else None,
            "visibility": visibility if visibility in _VISIBILITIES else None,
            "owner": owner,
            "protected": protected if isinstance(protected, bool) else None,
            "store_ids": store_ids,
            "tags": list(tags),
            "properties": properties,
        }
        for field in ("name", "disk_format", "container_format"):
            safe = _safe_string(_field(image, field))
            if field == "disk_format" and safe not in _DISK_FORMATS:
                safe = None
            if field == "container_format" and safe not in _CONTAINER_FORMATS:
                safe = None
            if safe is not None:
                facts[field] = safe
            else:
                result.unknowns.append(f"Glance image {field} invalid: {image_id}")
                valid = False
        for field in ("min_disk", "min_ram"):
            value = _field(image, field)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                facts[field] = value
            else:
                result.unknowns.append(f"Glance image {field} invalid: {image_id}")
                valid = False
        if preferred_hash is not None:
            facts["hash"] = preferred_hash
        if checksum is not None:
            facts["legacy_checksum"] = checksum
        return facts, store_ids, locations, valid

    def _members(self, image_id, payload, result) -> List[ResourceNode]:
        if not isinstance(payload, list):
            result.unknowns.append(f"Glance image member evidence invalid: {image_id}")
            return []
        nodes: List[ResourceNode] = []
        seen: Set[str] = set()
        for raw in payload:
            if not isinstance(raw, Mapping):
                result.unknowns.append(f"Glance image member evidence invalid: {image_id}")
                continue
            observed_image = _id(_field(raw, "image_id"), self._allow_fixture_aliases)
            member_id = _id(_field(raw, "member_id", "member"), self._allow_fixture_aliases)
            status = _field(raw, "status")
            if observed_image != image_id or member_id is None or status not in _MEMBER_STATES:
                result.blockers.append(f"Glance image member evidence inconsistent: {image_id}")
                continue
            key = f"{image_id}:{member_id}"
            if key in seen:
                result.blockers.append(f"Glance image member evidence ambiguous: {image_id}")
                continue
            seen.add(key)
            nodes.append(ResourceNode(
                "image_member", key, self.side,
                {"image_id": image_id, "member_id": member_id, "status": status},
            ))
        return nodes
