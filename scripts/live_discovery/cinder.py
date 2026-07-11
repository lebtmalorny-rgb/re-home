from copy import deepcopy
import json
import re
import uuid
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse

from .contract import CollectorResult, DependencyEdge, ResourceNode


CORE_TABLES = ("volumes", "volume_attachment", "volume_types", "services")
OPTIONAL_TABLES = (
    "volume_type_extra_specs", "volume_type_projects", "volume_type_qos_specs",
    "qos_specs", "quality_of_service_specs", "encryption", "snapshots",
    "volume_metadata", "volume_glance_metadata", "volume_admin_metadata",
    "groups", "group_snapshots",
)

_FIXTURE_POLICY_TOKEN = object()
_FIXTURE_ALIAS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@#-]{0,127}$")
_BACKEND_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@#-]{0,254}$")
_SAFE_TEXT = re.compile(r"^[^\x00-\x1f\x7f]{0,1024}$")
_SENSITIVE = re.compile(
    r"password|passwd|(?:^|[_-])pwd(?:$|[_-])|token|secret|chap|"
    r"credential|connector|connection[_-]?(?:info|data)", re.IGNORECASE,
)
_SUPPORTED_ATTACHMENT_DRIVERS = {
    "iscsi", "fibre_channel", "rbd", "nfs", "file", "lvm",
}
_SAFE_NETLOC = re.compile(r"^[A-Za-z0-9.\-:\[\]]+$")
_ENCRYPTION_PROVIDER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$")
_CINDER_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_ATTACHMENT_STATES = {
    "attached", "attaching", "detaching", "detached", "reserved",
    "error_attaching", "error_detaching",
}
_ATTACHMENT_MODES = {"rw", "ro"}
_VOLUME_STATES = {
    "in-use", "available", "error", "maintenance", "creating",
    "attaching", "detaching", "deleting", "retyping", "extending",
    "downloading", "uploading", "backing-up", "restoring-backup",
    "awaiting-transfer", "error_deleting", "error_restoring",
    "error_extending",
}
_VOLUME_TRANSITIONAL_STATES = {
    "creating", "attaching", "detaching", "deleting", "retyping",
    "extending", "downloading", "uploading", "backing-up",
    "restoring-backup", "awaiting-transfer",
}
_ATTACHMENT_TRANSITIONAL_STATES = {"attaching", "detaching"}
_MAX_JSON_BYTES = 65536
_MAX_JSON_DEPTH = 16
_MAX_JSON_NODES = 4096

_TABLE_ID_FIELDS = {
    "volumes": (
        "id", "volume_type_id", "service_uuid", "encryption_key_id",
        "snapshot_id", "source_volid", "group_id", "consistencygroup_id",
        "group_snapshot_id",
    ),
    "volume_attachment": ("id", "volume_id", "instance_uuid"),
    "volume_types": ("id",),
    "volume_type_extra_specs": ("volume_type_id",),
    "volume_type_projects": ("volume_type_id", "project_id"),
    "volume_type_qos_specs": ("volume_type_id", "qos_specs_id"),
    "qos_specs": ("id",),
    "quality_of_service_specs": ("id", "specs_id"),
    "services": ("uuid",),
    "encryption": ("volume_type_id",),
    "snapshots": ("id", "volume_id", "group_snapshot_id"),
    "volume_metadata": ("volume_id",),
    "volume_glance_metadata": ("volume_id",),
    "volume_admin_metadata": ("volume_id",),
    "groups": ("id", "group_type_id"),
    "group_snapshots": ("id", "group_id"),
}

_VOLUME_FIELDS = (
    "id", "display_name", "status", "size", "availability_zone",
    "bootable", "multiattach", "volume_type_id", "service_uuid", "host",
    "cluster_name", "encryption_key_id", "snapshot_id", "source_volid",
    "group_id", "consistencygroup_id", "storage_backend_id",
    "group_snapshot_id",
)
_API_VOLUME_FIELDS = (
    "id", "name", "status", "size", "availability_zone", "bootable",
    "multiattach", "volume_type_id", "type_id", "service_uuid", "host",
    "cluster_name", "group_id", "consistencygroup_id", "group_snapshot_id",
)
_ATTACHMENT_FIELDS = (
    "id", "volume_id", "instance_uuid", "attach_status", "attach_mode",
    "mountpoint", "attached_host",
)
_TYPE_FIELDS = ("id", "name", "description", "is_public")
_SERVICE_FIELDS = (
    "uuid", "host", "cluster_name", "binary", "topic", "disabled",
    "backend_name", "availability_zone",
)
_SNAPSHOT_FIELDS = (
    "id", "volume_id", "status", "volume_size", "display_name",
    "group_snapshot_id",
)
_GROUP_FIELDS = ("id", "name", "status", "group_type_id")
_GROUP_SNAPSHOT_FIELDS = ("id", "group_id", "name", "status")


class _PolicyMapping(dict):
    def __init__(self, value: Mapping[str, Any], allow_fixture_aliases: bool):
        super().__init__(value)
        self.allow_fixture_aliases = allow_fixture_aliases


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


def _openstack_id(value: object, allow_fixture_aliases: bool = False) -> Optional[str]:
    if not isinstance(value, str):
        return None
    try:
        parsed = str(uuid.UUID(value))
    except (ValueError, AttributeError):
        parsed = None
    if parsed == value:
        return value
    if allow_fixture_aliases and _FIXTURE_ALIAS.fullmatch(value):
        return value
    return None


def _row_id(row: Mapping[str, Any], *names: str) -> Optional[str]:
    return _openstack_id(
        _field(row, *names), bool(getattr(row, "allow_fixture_aliases", False))
    )


def _volume_api_field(payload: object, field: str) -> Any:
    aliases = {
        "host": ("host", "os-vol-host-attr:host", "os_vol_host_attr_host"),
        "service_uuid": (
            "service_uuid", "os-vol-host-attr:service_uuid",
            "os_vol_host_attr_service_uuid",
        ),
    }
    return _field(payload, *aliases.get(field, (field,)))


def _schema_tables(schema: object) -> Set[str]:
    if isinstance(schema, Mapping):
        values = schema.keys()
    elif isinstance(schema, (list, tuple, set)):
        values = schema
    else:
        return set()
    return {
        str(value).split(".", 1)[-1]
        for value in values
        if isinstance(value, str) and str(value).split(".", 1)[0] in {"cinder", str(value)}
    }


def _dedupe(values: Iterable[str]) -> List[str]:
    return list(dict.fromkeys(value for value in values if value))


def _safe_value(value: object) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str) and _SAFE_TEXT.fullmatch(value):
        return value
    return None


def _safe_nonempty_string(value: object) -> Optional[str]:
    if (
        isinstance(value, str)
        and value != ""
        and _SAFE_TEXT.fullmatch(value)
    ):
        return value
    return None


def _safe_nonempty_string_list(value: object) -> Optional[List[str]]:
    if not isinstance(value, (list, tuple)) or len(value) == 0:
        return None
    normalized = [_safe_nonempty_string(item) for item in value]
    if any(item is None for item in normalized):
        return None
    return [item for item in normalized if item is not None]


def _typed_bool(value: object) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    return None


def _allowlisted(payload: object, fields: Sequence[str]) -> Dict[str, Any]:
    if not isinstance(payload, Mapping):
        return {}
    result: Dict[str, Any] = {}
    for field in fields:
        value = _field(payload, field)
        safe = _safe_value(value)
        if safe is not None:
            if isinstance(safe, str) and _SENSITIVE.search(safe) is not None:
                result[field] = "[REDACTED]"
            else:
                result[field] = safe
    return result


def _safe_key_values(rows: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    result = []
    for row in rows:
        key = _field(row, "key")
        value = _field(row, "value")
        if not isinstance(key, str) or not _SAFE_TEXT.fullmatch(key):
            continue
        if _SENSITIVE.search(key) is not None or (
            isinstance(value, str) and _SENSITIVE.search(value) is not None
        ):
            continue
        safe_value = _safe_value(value)
        if safe_value is not None:
            result.append({"key": key, "value": safe_value})
    return result


def _is_deleted(row: Mapping[str, Any]) -> bool:
    return _field(row, "deleted") not in (None, False, 0, "0", "")


def _bounded_structure(value: object) -> bool:
    stack = [(value, 0)]
    visited = 0
    byte_count = 0
    try:
        while stack:
            current, depth = stack.pop()
            visited += 1
            if visited > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
                return False
            if isinstance(current, Mapping):
                for key, item in current.items():
                    if not isinstance(key, str):
                        return False
                    byte_count += len(key.encode("utf-8"))
                    if byte_count > _MAX_JSON_BYTES:
                        return False
                    stack.append((item, depth + 1))
            elif isinstance(current, (list, tuple)):
                for item in current:
                    stack.append((item, depth + 1))
            elif current is not None and not isinstance(
                current, (str, int, float, bool)
            ):
                return False
            elif isinstance(current, str):
                byte_count += len(current.encode("utf-8"))
                if byte_count > _MAX_JSON_BYTES:
                    return False
        return True
    except (Exception, MemoryError, RecursionError):
        return False


def _parse_mapping(value: object) -> Optional[Mapping[str, Any]]:
    try:
        if isinstance(value, Mapping):
            if not _bounded_structure(value):
                return None
            encoded = json.dumps(
                value, ensure_ascii=False, separators=(",", ":")
            )
            if len(encoded.encode("utf-8")) > _MAX_JSON_BYTES:
                return None
            parsed = json.loads(encoded)
        elif isinstance(value, str):
            if len(value.encode("utf-8")) > _MAX_JSON_BYTES:
                return None
            parsed = json.loads(value)
        else:
            return None
        if not isinstance(parsed, Mapping) or not _bounded_structure(parsed):
            return None
        return parsed
    except (Exception, MemoryError, RecursionError):
        return None


def _attachment_state(value: object) -> Optional[str]:
    return value if isinstance(value, str) and value in _ATTACHMENT_STATES else None


def _attachment_mode(value: object) -> Optional[str]:
    return value if isinstance(value, str) and value in _ATTACHMENT_MODES else None


def _volume_state(value: object) -> Optional[str]:
    return value if isinstance(value, str) and value in _VOLUME_STATES else None


def _component(value: object) -> Optional[str]:
    if (
        isinstance(value, str)
        and _CINDER_COMPONENT.fullmatch(value)
        and _SENSITIVE.search(value) is None
    ):
        return value
    return None


def _cinder_host_components(value: object) -> Optional[Dict[str, str]]:
    if not isinstance(value, str) or value.count("@") != 1:
        return None
    host, backend_pool = value.split("@", 1)
    if backend_pool.count("#") > 1:
        return None
    backend, separator, pool = backend_pool.partition("#")
    normalized_host = _component(host)
    normalized_backend = _component(backend)
    normalized_pool = _component(pool) if separator else None
    if normalized_host is None or normalized_backend is None:
        return None
    if separator and normalized_pool is None:
        return None
    result = {"host": normalized_host, "backend_name": normalized_backend}
    if normalized_pool is not None:
        result["pool"] = normalized_pool
    return result


def _cluster_components(value: object) -> Optional[Dict[str, str]]:
    if not isinstance(value, str) or value.count("@") != 1:
        return None
    cluster, backend = value.split("@", 1)
    normalized_cluster = _component(cluster)
    normalized_backend = _component(backend)
    if normalized_cluster is None or normalized_backend is None:
        return None
    return {"cluster": normalized_cluster, "backend_name": normalized_backend}


def _canonical_host(components: Mapping[str, str]) -> str:
    suffix = f"#{components['pool']}" if "pool" in components else ""
    return f"{components['host']}@{components['backend_name']}{suffix}"


def _canonical_cluster(components: Mapping[str, str]) -> str:
    return f"{components['cluster']}@{components['backend_name']}"


def _connection_summary(
    value: object, connector: object = None
) -> Dict[str, Any]:
    payload = _parse_mapping(value) or {}
    driver = _field(payload, "driver_volume_type", "driver_type")
    driver_type = (
        driver
        if isinstance(driver, str)
        and driver in _SUPPORTED_ATTACHMENT_DRIVERS
        else None
    )
    data = _field(payload, "data")
    data = data if isinstance(data, Mapping) else {}
    target_count = 0
    for name in ("target_portals", "target_iqns", "target_wwns", "hosts", "mon_hosts"):
        candidate = _field(data, name)
        normalized = _safe_nonempty_string_list(candidate)
        if normalized is not None:
            target_count = max(target_count, len(normalized))
    if target_count == 0 and any(
        _safe_nonempty_string(_field(data, name)) is not None
        for name in (
            "target_portal", "target_iqn", "export", "device_path",
            "path", "name",
        )
    ):
        target_count = 1
    connector_payload = _parse_mapping(connector) or {}
    multipath = _field(data, "multipath")
    if multipath is None:
        multipath = _field(connector_payload, "multipath")
    return {
        "driver_type": driver_type,
        "target_count": target_count,
        "multipath": multipath if isinstance(multipath, bool) else None,
    }


def _active_connection_evidence_valid(
    connection_info: object, connector: object, summary: Mapping[str, Any]
) -> bool:
    connection = _parse_mapping(connection_info)
    connector_payload = _parse_mapping(connector)
    if (
        connection is None
        or len(connection) == 0
        or connector_payload is None
        or len(connector_payload) == 0
    ):
        return False
    typed_connector: Dict[str, Any] = {}
    for key in ("host", "initiator", "ip", "platform", "os_type"):
        if key in connector_payload:
            normalized = _safe_nonempty_string(connector_payload[key])
            if normalized is None:
                return False
            typed_connector[key] = normalized
    if "wwpns" in connector_payload:
        normalized_wwpns = _safe_nonempty_string_list(
            connector_payload["wwpns"]
        )
        if normalized_wwpns is None:
            return False
        typed_connector["wwpns"] = normalized_wwpns
    if "multipath" in connector_payload and not isinstance(
        connector_payload["multipath"], bool
    ):
        return False
    data = _field(connection, "data")
    if not isinstance(data, Mapping) or len(data) == 0:
        return False
    driver = summary.get("driver_type")
    target_count = summary.get("target_count")
    base_valid = (
        isinstance(driver, str)
        and driver != ""
        and isinstance(target_count, int)
        and not isinstance(target_count, bool)
        and target_count > 0
    )
    if not base_valid:
        return False
    if driver == "iscsi":
        if "initiator" not in typed_connector:
            return False
        if not isinstance(summary.get("multipath"), bool):
            return False
        portals = _field(data, "target_portals")
        iqns = _field(data, "target_iqns")
        if portals is None:
            portals = [_field(data, "target_portal")]
        if iqns is None:
            iqns = [_field(data, "target_iqn")]
        normalized_portals = _safe_nonempty_string_list(portals)
        normalized_iqns = _safe_nonempty_string_list(iqns)
        return (
            normalized_portals is not None
            and normalized_iqns is not None
            and len(normalized_portals) == len(normalized_iqns)
        )
    if driver == "fibre_channel":
        if "wwpns" not in typed_connector:
            return False
        if not isinstance(summary.get("multipath"), bool):
            return False
        targets = _field(data, "target_wwn", "target_wwns")
        return _safe_nonempty_string_list(targets) is not None
    if driver == "rbd":
        if "host" not in typed_connector:
            return False
        if "multipath" in data and not isinstance(
            _field(data, "multipath"), bool
        ):
            return False
        return (
            _safe_nonempty_string(_field(data, "name")) is not None
            and _safe_nonempty_string_list(
                _field(data, "hosts", "mon_hosts")
            ) is not None
        )
    if driver in {"nfs", "file", "lvm"}:
        if "host" not in typed_connector:
            return False
        if "multipath" in data and not isinstance(
            _field(data, "multipath"), bool
        ):
            return False
        return _safe_nonempty_string(
            _field(data, "export", "device_path", "path", "name")
        ) is not None
    return False


def _normalized_encryption_facts(row: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    provider = _safe_nonempty_string(_field(row, "provider"))
    control_location = _field(row, "control_location")
    key_size = _field(row, "key_size")
    cipher = _field(row, "cipher")
    if (
        provider is None
        or _ENCRYPTION_PROVIDER.fullmatch(provider) is None
        or _SENSITIVE.search(provider) is not None
        or control_location not in {"front-end", "back-end"}
        or not isinstance(key_size, int)
        or isinstance(key_size, bool)
        or key_size <= 0
        or (
            cipher is not None
            and (
                _safe_nonempty_string(cipher) is None
                or _SENSITIVE.search(cipher) is not None
            )
        )
    ):
        return None
    facts = {
        "provider": provider,
        "control_location": control_location,
        "key_size": key_size,
    }
    if cipher is not None:
        facts["cipher"] = cipher
    return facts


def _barbican_href_identity(
    href: object, allow_fixture_aliases: bool
) -> Optional[str]:
    if _safe_nonempty_string(href) is None:
        return None
    try:
        parsed = urlparse(href)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or _SAFE_NETLOC.fullmatch(parsed.netloc) is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.hostname is None
            or parsed.params
            or parsed.query
            or parsed.fragment
        ):
            return None
        # Access validates bracketed IPv6 and port syntax.
        parsed.port
        path_parts = parsed.path.split("/")
        if len(path_parts) != 4 or path_parts[:3] != ["", "v1", "secrets"]:
            return None
        identity = _openstack_id(
            path_parts[3], allow_fixture_aliases
        )
        if identity is None or parsed.path != f"/v1/secrets/{identity}":
            return None
        return identity
    except Exception:
        return None


class CinderCollector:
    def __init__(self, client, side: str, schema, *, _fixture_policy=None) -> None:
        self.client = client
        self.side = side
        self.available_tables = _schema_tables(schema)
        self._allow_fixture_aliases = _fixture_policy is _FIXTURE_POLICY_TOKEN

    @classmethod
    def for_fixture(cls, client, side: str, schema):
        if getattr(client, "_fixture_only", False) is not True:
            raise ValueError("fixture-only Cinder client required")
        return cls(client, side, schema, _fixture_policy=_FIXTURE_POLICY_TOKEN)

    def collect(self, volume_ids: Sequence[str]) -> CollectorResult:
        result = CollectorResult(service="cinder", side=self.side)
        if self._allow_fixture_aliases:
            result._fixture_aliases = _FIXTURE_POLICY_TOKEN
        if not volume_ids:
            result.blockers.append("Cinder volume roots missing")
            return result
        roots = [_openstack_id(value, self._allow_fixture_aliases) for value in volume_ids]
        if any(value is None for value in roots):
            result.blockers.append("Cinder volume roots invalid")
            return result
        root_ids = _dedupe(value for value in roots if value is not None)
        for table in CORE_TABLES:
            if table not in self.available_tables:
                result.blockers.append(f"Cinder required table missing: {table}")

        volume_rows = self._db_rows("volumes", {"id": root_ids}, result)
        # Source volume dependencies are acquired by UUID, never by scanning the table.
        seen = set(root_ids)
        pending = _dedupe(
            value for row in volume_rows
            if (value := _row_id(row, "source_volid")) is not None and value not in seen
        )
        while pending:
            seen.update(pending)
            extra = self._db_rows("volumes", {"id": pending}, result)
            volume_rows.extend(extra)
            pending = _dedupe(
                value for row in extra
                if (value := _row_id(row, "source_volid")) is not None and value not in seen
            )
        active_ids = _dedupe(
            value for row in volume_rows
            if not _is_deleted(row) and (value := _row_id(row, "id")) is not None
        )
        for root in root_ids:
            matches = [row for row in volume_rows if not _is_deleted(row) and _row_id(row, "id") == root]
            if len(matches) != 1:
                result.blockers.append(f"Cinder DB volume {'missing' if not matches else 'duplicate'}: {root}")

        attachments = self._db_rows("volume_attachment", {"volume_id": active_ids}, result)
        type_ids = _dedupe(
            value for row in volume_rows
            if (value := _row_id(row, "volume_type_id")) is not None
        )
        types = self._db_rows("volume_types", {"id": type_ids}, result) if type_ids else []
        private_type_ids = {
            value for row in types
            if _typed_bool(_field(row, "is_public")) is False
            and (value := _row_id(row, "id")) is not None
        }
        key_volume_type_ids = {
            value for row in volume_rows
            if _row_id(row, "encryption_key_id") is not None
            and (value := _row_id(row, "volume_type_id")) is not None
        }
        extra_specs = self._optional_rows("volume_type_extra_specs", {"volume_type_id": type_ids}, result)
        if private_type_ids and "volume_type_projects" not in self.available_tables:
            result.unknowns.append(
                "Cinder active schema family missing: volume_type_projects"
            )
        type_projects = self._optional_rows("volume_type_projects", {"volume_type_id": type_ids}, result)
        if type_ids and "volume_type_qos_specs" not in self.available_tables:
            result.unknowns.append(
                "Cinder active schema family missing: volume_type_qos_specs"
            )
        type_qos = self._optional_rows("volume_type_qos_specs", {"volume_type_id": type_ids}, result)
        qos_ids = _dedupe(
            value for row in type_qos if (value := _row_id(row, "qos_specs_id")) is not None
        )
        for table in ("qos_specs", "quality_of_service_specs"):
            if qos_ids and table not in self.available_tables:
                result.unknowns.append(
                    f"Cinder active schema family missing: {table}"
                )
        qos_definitions = self._optional_rows("qos_specs", {"id": qos_ids}, result)
        qos = self._optional_rows("quality_of_service_specs", {"specs_id": qos_ids}, result)
        service_ids = _dedupe(
            value for row in volume_rows
            if (value := _row_id(row, "service_uuid")) is not None
        )
        services = self._db_rows("services", {"uuid": service_ids}, result) if service_ids else []
        if key_volume_type_ids and "encryption" not in self.available_tables:
            result.unknowns.append(
                "Cinder active schema family missing: encryption"
            )
        encryptions = self._optional_rows("encryption", {"volume_type_id": type_ids}, result)
        snapshot_ids = _dedupe(
            value for row in volume_rows
            if (value := _row_id(row, "snapshot_id")) is not None
        )
        snapshot_filters: Dict[str, Sequence[str]] = {"volume_id": active_ids}
        if snapshot_ids:
            snapshot_filters["id"] = snapshot_ids
        snapshots = self._optional_rows("snapshots", snapshot_filters, result)
        metadata = {
            table: self._optional_rows(table, {"volume_id": active_ids}, result)
            for table in ("volume_metadata", "volume_glance_metadata", "volume_admin_metadata")
        }
        group_ids = _dedupe(
            value for row in volume_rows
            for name in ("group_id", "consistencygroup_id")
            if (value := _row_id(row, name)) is not None
        )
        if group_ids and "groups" not in self.available_tables:
            result.unknowns.append("Cinder active schema family missing: groups")
        groups = self._optional_rows("groups", {"id": group_ids}, result)
        group_snapshot_ids = _dedupe([
            *(
                value for row in volume_rows
                if (value := _row_id(row, "group_snapshot_id")) is not None
            ),
            *(
                value for row in snapshots
                if (value := _row_id(row, "group_snapshot_id")) is not None
            ),
        ])
        if group_snapshot_ids and "group_snapshots" not in self.available_tables:
            result.unknowns.append(
                "Cinder active schema family missing: group_snapshots"
            )
        group_snapshots = self._optional_rows(
            "group_snapshots", {"id": group_snapshot_ids}, result
        )
        group_ids = _dedupe([
            *group_ids,
            *(
                value for row in group_snapshots
                if (value := _row_id(row, "group_id")) is not None
            ),
        ])
        # A group snapshot can introduce its parent group after the first query.
        known_group_ids = {
            value for row in groups if (value := _row_id(row, "id")) is not None
        }
        missing_group_ids = [value for value in group_ids if value not in known_group_ids]
        if missing_group_ids and "groups" in self.available_tables:
            groups.extend(self._db_rows("groups", {"id": missing_group_ids}, result))

        nodes: Dict[str, ResourceNode] = {}
        edge_keys: Set[Tuple[str, str, str, bool]] = set()

        def add_node(kind: str, identifier: object, facts=None, evidence_ids=None):
            if identifier in (None, ""):
                return None
            node = ResourceNode(
                kind, str(identifier), self.side, deepcopy(dict(facts or {})),
                _dedupe(evidence_ids or []),
            )
            existing = nodes.get(node.key)
            if existing is None:
                nodes[node.key] = node
                result.nodes.append(node)
                return node
            existing.facts.update(node.facts)
            existing.evidence_ids[:] = _dedupe([*existing.evidence_ids, *node.evidence_ids])
            return existing

        def add_edge(source: str, target: str, relation: str, required: bool = True):
            key = (source, target, relation, required)
            if key not in edge_keys:
                edge_keys.add(key)
                result.edges.append(DependencyEdge(source, target, relation, required))

        attachment_by_volume: Dict[str, List[Mapping[str, Any]]] = {}
        for row in attachments:
            volume_id = _row_id(row, "volume_id")
            attachment_id = _row_id(row, "id")
            if not volume_id or not attachment_id or _is_deleted(row):
                continue
            attachment_by_volume.setdefault(volume_id, []).append(row)
            api, evidence_id = self._api(
                ["volume", "attachment", "show", attachment_id, "-f", "json"],
                f"cinder-{self.side}-attachment-show-{attachment_id}", result,
            )
            if _row_id(api, "id") != attachment_id or _row_id(api, "volume_id") != volume_id:
                result.blockers.append(f"attachment API/DB identity mismatch: {attachment_id}")
            api_server_id = _openstack_id(
                _field(api, "server_id", "instance_uuid"),
                self._allow_fixture_aliases,
            )
            db_server_id = _row_id(row, "instance_uuid")
            if api_server_id != db_server_id:
                result.blockers.append(
                    f"attachment API/DB server mismatch: {attachment_id}"
                )
            db_facts = _allowlisted(
                row, ("id", "volume_id", "instance_uuid")
            )
            api_facts = _allowlisted(
                api,
                (
                    "id", "volume_id", "server_id", "instance_uuid",
                ),
            )
            db_status = _attachment_state(_field(row, "attach_status"))
            api_status = _attachment_state(
                _field(api, "attach_status", "status")
            )
            db_mode = _attachment_mode(_field(row, "attach_mode"))
            api_mode = _attachment_mode(_field(api, "attach_mode"))
            if None in {db_status, api_status, db_mode, api_mode}:
                result.blockers.append(
                    f"attachment state or mode invalid: {attachment_id}"
                )
            elif db_status in _ATTACHMENT_TRANSITIONAL_STATES:
                result.unknowns.append(
                    f"attachment readiness transitional: {attachment_id}"
                )
            elif db_status != "attached":
                result.blockers.append(
                    f"required attachment not usable: {attachment_id}"
                )
            if db_status is not None and api_status is not None:
                db_facts["attach_status"] = db_status
                api_facts["status"] = api_status
            if db_mode is not None and api_mode is not None:
                db_facts["attach_mode"] = db_mode
                api_facts["attach_mode"] = api_mode
            if (
                db_status is not None
                and api_status is not None
                and db_status != api_status
            ):
                result.blockers.append(
                    f"attachment API/DB status mismatch: {attachment_id}"
                )
            if (
                db_mode is not None
                and api_mode is not None
                and db_mode != api_mode
            ):
                result.blockers.append(
                    f"attachment API/DB mode mismatch: {attachment_id}"
                )
            facts = db_facts
            facts["api_observed"] = api_facts
            connection_info = _field(row, "connection_info")
            connector = _field(row, "connector")
            summary = _connection_summary(connection_info, connector)
            parsed_connection = _parse_mapping(connection_info)
            parsed_connector = _parse_mapping(connector)
            if (
                db_status in {"attached", *_ATTACHMENT_TRANSITIONAL_STATES}
                and (
                    parsed_connection is None
                    or len(parsed_connection) == 0
                    or parsed_connector is None
                    or len(parsed_connector) == 0
                )
            ):
                result.blockers.append(
                    f"active attachment connection metadata invalid: {attachment_id}"
                )
            if (
                db_status in {"attached", *_ATTACHMENT_TRANSITIONAL_STATES}
                and not _active_connection_evidence_valid(
                    connection_info, connector, summary
                )
            ):
                result.blockers.append(
                    f"active attachment driver evidence invalid: {attachment_id}"
                )
            facts["connection_info"] = "[REDACTED]"
            facts["connector"] = "[REDACTED]"
            facts["connection_summary"] = summary
            add_node("volume_attachment", attachment_id, facts, [evidence_id] if evidence_id else [])

        encryption_rows_by_type: Dict[str, List[Mapping[str, Any]]] = {}
        for encryption_row in encryptions:
            encryption_type_id = _row_id(encryption_row, "volume_type_id")
            if encryption_type_id is not None:
                encryption_rows_by_type.setdefault(
                    encryption_type_id, []
                ).append(encryption_row)
        valid_encryption_facts: Dict[str, Dict[str, Any]] = {}
        for encryption_type_id in sorted(
            {*encryption_rows_by_type, *key_volume_type_ids}
        ):
            active_rows = [
                item for item in encryption_rows_by_type.get(
                    encryption_type_id, []
                )
                if not _is_deleted(item)
            ]
            if not active_rows:
                if encryption_type_id in key_volume_type_ids:
                    result.blockers.append(
                        f"required encryption definition missing: {encryption_type_id}"
                    )
                continue
            if len(active_rows) != 1:
                result.blockers.append(
                    f"encryption definition ambiguous: {encryption_type_id}"
                )
                continue
            normalized_encryption = _normalized_encryption_facts(active_rows[0])
            if normalized_encryption is None:
                result.blockers.append(
                    f"encryption definition invalid: {encryption_type_id}"
                )
                continue
            valid_encryption_facts[encryption_type_id] = normalized_encryption
        encryption_type_ids = set(valid_encryption_facts)
        type_rows = {_row_id(row, "id"): row for row in types if not _is_deleted(row)}
        service_rows_by_id: Dict[str, List[Mapping[str, Any]]] = {}
        for service_row in services:
            service_id = _row_id(service_row, "uuid")
            if service_id is not None and not _is_deleted(service_row):
                service_rows_by_id.setdefault(service_id, []).append(service_row)
        service_rows = {
            service_id: rows[0]
            for service_id, rows in service_rows_by_id.items() if len(rows) == 1
        }
        for service_id, rows in service_rows_by_id.items():
            if len(rows) != 1:
                result.blockers.append(
                    f"Cinder service DB identity ambiguous: {service_id}"
                )
        group_rows = {
            _row_id(row, "id"): row for row in groups if not _is_deleted(row)
        }
        group_row_ids = {value for value in group_rows if value is not None}
        group_snapshot_rows = {
            _row_id(row, "id"): row
            for row in group_snapshots if not _is_deleted(row)
        }
        snapshot_rows = {_row_id(row, "id"): row for row in snapshots if not _is_deleted(row)}

        for group_id, group_row in group_rows.items():
            if group_id is not None:
                add_node(
                    "volume_group", group_id,
                    _allowlisted(group_row, _GROUP_FIELDS),
                )
        for group_snapshot_id, group_snapshot_row in group_snapshot_rows.items():
            if group_snapshot_id is None:
                continue
            group_snapshot = add_node(
                "group_snapshot", group_snapshot_id,
                _allowlisted(group_snapshot_row, _GROUP_SNAPSHOT_FIELDS),
            )
            parent_group_id = _row_id(group_snapshot_row, "group_id")
            if parent_group_id:
                add_edge(
                    group_snapshot.key, f"volume_group:{parent_group_id}",
                    "belongs_to_group",
                )

        for snapshot_id, snapshot_row in snapshot_rows.items():
            if snapshot_id is None:
                continue
            snapshot = add_node(
                "snapshot", snapshot_id,
                _allowlisted(snapshot_row, _SNAPSHOT_FIELDS),
            )
            volume_id = _row_id(snapshot_row, "volume_id")
            if snapshot is not None and volume_id in active_ids:
                add_edge(
                    f"volume:{volume_id}", snapshot.key,
                    "retains_snapshot", required=False,
                )
            group_snapshot_id = _row_id(snapshot_row, "group_snapshot_id")
            if snapshot is not None and group_snapshot_id:
                add_edge(
                    snapshot.key, f"group_snapshot:{group_snapshot_id}",
                    "belongs_to_group_snapshot",
                )

        for volume_id in active_ids:
            rows_for_id = [row for row in volume_rows if not _is_deleted(row) and _row_id(row, "id") == volume_id]
            if not rows_for_id:
                continue
            row = rows_for_id[0]
            api, evidence_id = self._api(
                ["volume", "show", volume_id, "-f", "json"],
                f"cinder-{self.side}-volume-show-{volume_id}", result,
            )
            if _row_id(api, "id") != volume_id:
                result.blockers.append(f"volume API UUID mismatch: {volume_id}")
            api_size = _field(api, "size")
            db_size = _field(row, "size")
            if (
                not isinstance(api_size, int)
                or isinstance(api_size, bool)
                or not isinstance(db_size, int)
                or isinstance(db_size, bool)
                or api_size != db_size
            ):
                result.blockers.append(f"volume API/DB size mismatch: {volume_id}")
            db_volume_state = _volume_state(_field(row, "status"))
            api_volume_state = _volume_state(_field(api, "status"))
            if db_volume_state is None or api_volume_state is None:
                result.blockers.append(f"volume state invalid: {volume_id}")
            elif db_volume_state != api_volume_state:
                result.blockers.append(
                    f"volume API/DB status mismatch: {volume_id}"
                )
            if volume_id in root_ids:
                if db_volume_state in _VOLUME_TRANSITIONAL_STATES:
                    result.unknowns.append(
                        f"volume readiness transitional: {volume_id}"
                    )
                elif db_volume_state is not None and db_volume_state != "in-use":
                    result.blockers.append(
                        f"volume not usable for re-home: {volume_id}"
                    )
            api_type_id = _openstack_id(
                _field(api, "volume_type_id", "type_id", "type"),
                self._allow_fixture_aliases,
            )
            db_type_id = _row_id(row, "volume_type_id")
            if api_type_id != db_type_id:
                result.blockers.append(
                    f"volume API/DB type mismatch: {volume_id}"
                )
            for field, label in (
                ("service_uuid", "service"),
                ("group_id", "group"),
                ("consistencygroup_id", "consistency group"),
                ("group_snapshot_id", "group snapshot"),
            ):
                api_value = _openstack_id(
                    _volume_api_field(api, field), self._allow_fixture_aliases
                )
                db_value = _row_id(row, field)
                if api_value != db_value:
                    result.blockers.append(
                        f"volume API/DB {label} mismatch: {volume_id}"
                    )
            db_host_components = _cinder_host_components(_field(row, "host"))
            api_host_components = _cinder_host_components(
                _volume_api_field(api, "host")
            )
            db_cluster_components = _cluster_components(
                _field(row, "cluster_name")
            )
            api_cluster_components = _cluster_components(
                _volume_api_field(api, "cluster_name")
            )
            storage_backend_id = _component(
                _field(row, "storage_backend_id")
            )
            if (
                db_host_components is None
                or api_host_components is None
                or db_cluster_components is None
                or api_cluster_components is None
                or storage_backend_id is None
                or db_host_components["backend_name"]
                != db_cluster_components["backend_name"]
                or api_host_components["backend_name"]
                != api_cluster_components["backend_name"]
            ):
                result.blockers.append(
                    "Cinder host/backend/cluster facts invalid"
                )
            if (
                db_host_components is not None
                and api_host_components is not None
                and db_host_components != api_host_components
            ):
                result.blockers.append(
                    f"volume API/DB host mismatch: {volume_id}"
                )
            if (
                db_cluster_components is not None
                and api_cluster_components is not None
                and db_cluster_components != api_cluster_components
            ):
                result.blockers.append(
                    f"volume API/DB cluster_name mismatch: {volume_id}"
                )
            facts = _allowlisted(row, _VOLUME_FIELDS)
            api_facts = _allowlisted(api, _API_VOLUME_FIELDS)
            facts.pop("status", None)
            api_facts.pop("status", None)
            if db_volume_state is not None:
                facts["status"] = db_volume_state
            if api_volume_state is not None:
                api_facts["status"] = api_volume_state
            for unsafe_field in ("host", "cluster_name", "storage_backend_id"):
                facts.pop(unsafe_field, None)
                api_facts.pop(unsafe_field, None)
            if db_host_components is not None:
                facts["host"] = _canonical_host(db_host_components)
                facts["host_components"] = deepcopy(db_host_components)
            if db_cluster_components is not None:
                facts["cluster_name"] = _canonical_cluster(
                    db_cluster_components
                )
                facts["cluster_components"] = deepcopy(
                    db_cluster_components
                )
            if storage_backend_id is not None:
                facts["storage_backend_id"] = storage_backend_id
            if api_host_components is not None:
                api_facts["host"] = _canonical_host(api_host_components)
                api_facts["host_components"] = deepcopy(api_host_components)
            if api_cluster_components is not None:
                api_facts["cluster_name"] = _canonical_cluster(
                    api_cluster_components
                )
                api_facts["cluster_components"] = deepcopy(
                    api_cluster_components
                )
            facts["api_observed"] = api_facts
            facts["normalizations"] = {
                "service_uuid": _row_id(row, "service_uuid"),
                "volume_type_id": _row_id(row, "volume_type_id"),
            }
            if db_host_components is not None:
                facts["normalizations"]["host"] = _canonical_host(
                    db_host_components
                )
            if db_cluster_components is not None:
                facts["normalizations"]["cluster_name"] = _canonical_cluster(
                    db_cluster_components
                )
            for table, fact_name in (
                ("volume_metadata", "metadata"),
                ("volume_glance_metadata", "image_metadata"),
                ("volume_admin_metadata", "admin_metadata"),
            ):
                facts[fact_name] = _safe_key_values([
                    item for item in metadata[table] if _row_id(item, "volume_id") == volume_id
                ])
            volume = add_node("volume", volume_id, facts, [evidence_id] if evidence_id else [])
            assert volume is not None

            api_attachment_ids = self._attachment_ids(_field(api, "attachments"), result, volume_id)
            db_attachment_ids = {
                value for item in attachment_by_volume.get(volume_id, [])
                if (value := _row_id(item, "id")) is not None
            }
            for attachment_id in sorted(api_attachment_ids - db_attachment_ids):
                result.blockers.append(f"required attachment missing: {attachment_id}")
            if api_attachment_ids != db_attachment_ids:
                result.blockers.append(f"volume attachment API/DB mismatch: {volume_id}")
            if volume_id in root_ids and not db_attachment_ids:
                result.blockers.append(
                    f"required current attachment missing: {volume_id}"
                )
            for attachment_id in sorted(db_attachment_ids):
                add_edge(volume.key, f"volume_attachment:{attachment_id}", "has_attachment")

            type_id = _row_id(row, "volume_type_id")
            if type_id:
                type_row = type_rows.get(type_id)
                if type_row is None:
                    result.blockers.append(f"required volume type missing: {type_id}")
                else:
                    type_api, type_evidence = self._api(
                        ["volume", "type", "show", type_id, "-f", "json"],
                        f"cinder-{self.side}-volume-type-show-{type_id}", result,
                    )
                    if _row_id(type_api, "id") != type_id:
                        result.blockers.append(f"volume type API/DB identity mismatch: {type_id}")
                    type_facts = _allowlisted(type_row, _TYPE_FIELDS)
                    type_api_facts = _allowlisted(type_api, _TYPE_FIELDS)
                    for field, label in (("name", "name"),):
                        if _field(type_api, field) != _field(type_row, field):
                            result.blockers.append(
                                f"volume type API/DB {label} mismatch: {type_id}"
                            )
                    api_visibility = _typed_bool(_field(type_api, "is_public"))
                    db_visibility = _typed_bool(_field(type_row, "is_public"))
                    if api_visibility is None or db_visibility is None or api_visibility != db_visibility:
                        result.blockers.append(
                            f"volume type API/DB visibility mismatch: {type_id}"
                        )
                    type_facts["api_observed"] = type_api_facts
                    type_facts["extra_specs"] = _safe_key_values([
                        item for item in extra_specs if _row_id(item, "volume_type_id") == type_id
                    ])
                    type_facts["project_ids"] = sorted({
                        project_id for item in type_projects
                        if _row_id(item, "volume_type_id") == type_id
                        and not _is_deleted(item)
                        and (project_id := _row_id(item, "project_id")) is not None
                    })
                    if (
                        db_visibility is False
                        and not type_facts["project_ids"]
                    ):
                        result.blockers.append(
                            f"private volume type visibility missing: {type_id}"
                        )
                    type_qos_ids = {
                        _row_id(item, "qos_specs_id") for item in type_qos
                        if _row_id(item, "volume_type_id") == type_id
                    }
                    qos_definition_rows = {
                        _row_id(item, "id"): item
                        for item in qos_definitions if not _is_deleted(item)
                    }
                    type_facts["qos_specs"] = []
                    for qos_id in sorted(value for value in type_qos_ids if value):
                        definition = qos_definition_rows.get(qos_id)
                        if definition is None:
                            result.blockers.append(
                                f"required QoS definition missing: {qos_id}"
                            )
                            continue
                        qos_facts = _allowlisted(
                            definition, ("id", "name", "consumer")
                        )
                        qos_facts["specifications"] = _safe_key_values([
                            item for item in qos
                            if _row_id(item, "specs_id") == qos_id
                            and not _is_deleted(item)
                        ])
                        if not qos_facts["specifications"]:
                            result.blockers.append(
                                f"required QoS specifications missing: {qos_id}"
                            )
                        type_facts["qos_specs"].append(qos_facts)
                    normalized_encryption = valid_encryption_facts.get(type_id)
                    type_facts["encryption"] = (
                        [deepcopy(normalized_encryption)]
                        if normalized_encryption is not None else []
                    )
                    add_node("volume_type", type_id, type_facts, [type_evidence] if type_evidence else [])
                add_edge(volume.key, f"volume_type:{type_id}", "uses_volume_type")
            else:
                result.blockers.append(f"volume type UUID missing: {volume_id}")

            service_id = _row_id(row, "service_uuid")
            if service_id:
                service_row = service_rows.get(service_id)
                if service_row is None:
                    result.blockers.append(f"required Cinder service missing: {service_id}")
                else:
                    volume_host = _field(row, "host")
                    service_host = _field(service_row, "host")
                    volume_cluster = _field(row, "cluster_name")
                    service_cluster = _field(service_row, "cluster_name")
                    service_backend_name = _field(service_row, "backend_name")
                    volume_backend_name = self._backend_name_from_host(
                        volume_host
                    )
                    service_host_components = _cinder_host_components(
                        service_host
                    )
                    service_cluster_components = _cluster_components(
                        service_cluster
                    )
                    if (
                        service_host_components is None
                        or service_cluster_components is None
                        or _component(service_backend_name) is None
                    ):
                        result.blockers.append(
                            "Cinder host/backend/cluster facts invalid"
                        )
                    if (
                        service_host != volume_host
                        or self._backend_name_from_host(service_host)
                        != volume_backend_name
                        or service_cluster != volume_cluster
                        or self._backend_name_from_cluster(service_cluster)
                        != volume_backend_name
                        or service_backend_name != volume_backend_name
                    ):
                        result.blockers.append(
                            f"Cinder service backend mismatch: {service_id}"
                        )
                    if (
                        _typed_bool(_field(service_row, "disabled")) is not False
                        or _field(service_row, "binary") != "cinder-volume"
                    ):
                        result.blockers.append(
                            f"Cinder service not ready: {service_id}"
                        )
                    service_facts: Dict[str, Any] = {"uuid": service_id}
                    if (
                        service_host == volume_host
                        and volume_backend_name is not None
                        and isinstance(service_host, str)
                        and _SENSITIVE.search(service_host) is None
                    ):
                        service_facts["host"] = _canonical_host(
                            service_host_components
                        )
                        service_facts["host_components"] = deepcopy(
                            service_host_components
                        )
                    if (
                        service_cluster == volume_cluster
                        and self._backend_name_from_cluster(service_cluster)
                        is not None
                        and isinstance(service_cluster, str)
                        and _SENSITIVE.search(service_cluster) is None
                    ):
                        service_facts["cluster_name"] = _canonical_cluster(
                            service_cluster_components
                        )
                        service_facts["cluster_components"] = deepcopy(
                            service_cluster_components
                        )
                    if _field(service_row, "binary") == "cinder-volume":
                        service_facts["binary"] = "cinder-volume"
                    disabled = _typed_bool(_field(service_row, "disabled"))
                    if disabled is not None:
                        service_facts["disabled"] = disabled
                    if service_backend_name == volume_backend_name:
                        service_facts["backend_name"] = service_backend_name
                    topic = _safe_nonempty_string(_field(service_row, "topic"))
                    if topic == "cinder-volume":
                        service_facts["topic"] = topic
                    add_node("cinder_service", service_id, service_facts)
                add_edge(volume.key, f"cinder_service:{service_id}", "managed_by")
            else:
                result.blockers.append(f"Cinder service UUID missing: {volume_id}")

            backend_id = storage_backend_id
            if backend_id is not None:
                backend_facts: Dict[str, Any] = {}
                if db_host_components is not None:
                    backend_facts["host_components"] = deepcopy(
                        db_host_components
                    )
                if db_cluster_components is not None:
                    backend_facts["cluster_components"] = deepcopy(
                        db_cluster_components
                    )
                add_node("storage_backend", backend_id, backend_facts)
                add_edge(volume.key, f"storage_backend:{backend_id}", "has_backing_backend")
            else:
                result.blockers.append(
                    "Cinder host/backend/cluster facts invalid"
                )

            encrypted = type_id in encryption_type_ids
            key_id = _row_id(row, "encryption_key_id")
            if encrypted and key_id is None:
                result.blockers.append(f"encrypted volume {volume_id} has no key UUID")
            if key_id:
                key_api, key_evidence, failure = self._secret_metadata(key_id, result)
                key_facts = (
                    {"status": "ACTIVE"}
                    if _field(key_api, "status") == "ACTIVE" else {}
                )
                add_node("encryption_key_ref", key_id, key_facts, [key_evidence] if key_evidence else [])
                add_edge(volume.key, f"encryption_key_ref:{key_id}", "uses_encryption_key")
                if failure:
                    continue

            source_id = _row_id(row, "source_volid")
            if source_id:
                add_edge(volume.key, f"volume:{source_id}", "cloned_from")
            snapshot_id = _row_id(row, "snapshot_id")
            if snapshot_id:
                snapshot_row = snapshot_rows.get(snapshot_id)
                if snapshot_row is None:
                    result.blockers.append(f"required snapshot missing: {snapshot_id}")
                else:
                    snapshot_api, snapshot_evidence = self._api(
                        ["volume", "snapshot", "show", snapshot_id, "-f", "json"],
                        f"cinder-{self.side}-snapshot-show-{snapshot_id}", result,
                    )
                    if _row_id(snapshot_api, "id") != snapshot_id:
                        result.blockers.append(f"snapshot API/DB identity mismatch: {snapshot_id}")
                    snapshot_facts = _allowlisted(snapshot_row, _SNAPSHOT_FIELDS)
                    snapshot_api_facts = _allowlisted(
                        snapshot_api, _SNAPSHOT_FIELDS
                    )
                    for field, label in (
                        ("volume_id", "volume"),
                        ("group_snapshot_id", "group snapshot"),
                    ):
                        if _row_id(snapshot_api, field) != _row_id(snapshot_row, field):
                            result.blockers.append(
                                f"snapshot API/DB {label} mismatch: {snapshot_id}"
                            )
                    for field in ("status", "volume_size"):
                        if _field(snapshot_api, field) != _field(snapshot_row, field):
                            result.blockers.append(
                                f"snapshot API/DB {field} mismatch: {snapshot_id}"
                            )
                    snapshot_facts["api_observed"] = snapshot_api_facts
                    add_node("snapshot", snapshot_id, snapshot_facts, [snapshot_evidence] if snapshot_evidence else [])
                add_edge(volume.key, f"snapshot:{snapshot_id}", "created_from_snapshot")
            for group_id in (_row_id(row, "group_id"), _row_id(row, "consistencygroup_id")):
                if group_id:
                    if group_id not in group_row_ids:
                        result.blockers.append(
                            f"required volume group missing: {group_id}"
                        )
                    add_edge(
                        volume.key, f"volume_group:{group_id}",
                        "belongs_to_group",
                    )
            group_snapshot_id = _row_id(row, "group_snapshot_id")
            if group_snapshot_id:
                if group_snapshot_id not in group_snapshot_rows:
                    result.blockers.append(
                        f"required group snapshot missing: {group_snapshot_id}"
                    )
                add_edge(
                    volume.key, f"group_snapshot:{group_snapshot_id}",
                    "belongs_to_group_snapshot",
                )

        for snapshot_id, snapshot_row in snapshot_rows.items():
            group_snapshot_id = _row_id(snapshot_row, "group_snapshot_id")
            if group_snapshot_id and group_snapshot_id not in group_snapshot_rows:
                result.blockers.append(
                    f"required group snapshot missing: {group_snapshot_id}"
                )
            parent_group_id = (
                _row_id(group_snapshot_rows[group_snapshot_id], "group_id")
                if group_snapshot_id in group_snapshot_rows else None
            )
            if parent_group_id and parent_group_id not in group_row_ids:
                result.blockers.append(
                    f"required volume group missing: {parent_group_id}"
                )

        # Service list is a second independent API view used to confirm UUID/host identity.
        service_api, service_evidence = self._api(
            ["volume", "service", "list", "--long", "-f", "json"],
            f"cinder-{self.side}-volume-service-list", result,
        )
        if isinstance(service_api, list):
            for service_id in service_ids:
                db_service = service_rows.get(service_id, {})
                db_host = _field(db_service, "host")
                db_binary = _field(db_service, "binary")
                matches = [
                    item for item in service_api
                    if isinstance(item, Mapping)
                    and (
                        _openstack_id(
                            _field(item, "uuid", "id"),
                            self._allow_fixture_aliases,
                        ) == service_id
                        or (
                            _field(item, "uuid", "id") in (None, "")
                            and _field(item, "host") == db_host
                            and _field(item, "binary") == db_binary
                        )
                    )
                ]
                if not matches:
                    result.blockers.append(f"Cinder service API identity missing: {service_id}")
                elif len(matches) > 1:
                    result.blockers.append(
                        f"Cinder service API identity ambiguous: {service_id}"
                    )
                elif service_id in service_rows:
                    api_host = _field(matches[0], "host")
                    if api_host != db_host:
                        result.blockers.append(f"Cinder service API/DB host mismatch: {service_id}")
                    for field in ("binary", "cluster_name"):
                        if _field(matches[0], field) != _field(db_service, field):
                            result.blockers.append(
                                f"Cinder service API/DB {field} mismatch: {service_id}"
                            )
                    if (
                        self._backend_name_from_host(api_host)
                        != self._backend_name_from_host(db_host)
                    ):
                        result.blockers.append(
                            f"Cinder service backend mismatch: {service_id}"
                        )
                    status = _field(matches[0], "status")
                    state = _field(matches[0], "state")
                    if (
                        not isinstance(status, str)
                        or status.lower() != "enabled"
                        or not isinstance(state, str)
                        or state.lower() != "up"
                        or _field(matches[0], "binary") != "cinder-volume"
                    ):
                        result.blockers.append(
                            f"Cinder service not ready: {service_id}"
                        )
                    service_node = nodes.get(f"cinder_service:{service_id}")
                    if service_node is not None:
                        api_observed: Dict[str, Any] = {}
                        api_cluster = _field(matches[0], "cluster_name")
                        api_binary = _field(matches[0], "binary")
                        api_host_components = _cinder_host_components(api_host)
                        db_host_components = _cinder_host_components(db_host)
                        api_cluster_components = _cluster_components(api_cluster)
                        db_cluster_components = _cluster_components(
                            _field(db_service, "cluster_name")
                        )
                        if (
                            api_host_components is None
                            or db_host_components is None
                            or api_cluster_components is None
                            or db_cluster_components is None
                        ):
                            result.blockers.append(
                                "Cinder host/backend/cluster facts invalid"
                            )
                        if (
                            api_host_components is not None
                            and api_host_components == db_host_components
                        ):
                            api_observed["host"] = _canonical_host(
                                api_host_components
                            )
                        if api_binary == "cinder-volume":
                            api_observed["binary"] = "cinder-volume"
                        if isinstance(status, str) and status.lower() == "enabled":
                            api_observed["status"] = "enabled"
                        if isinstance(state, str) and state.lower() == "up":
                            api_observed["state"] = "up"
                        if (
                            api_cluster_components is not None
                            and api_cluster_components == db_cluster_components
                        ):
                            api_observed["cluster_name"] = _canonical_cluster(
                                api_cluster_components
                            )
                        api_backend_name = self._backend_name_from_host(api_host)
                        if (
                            api_backend_name is not None
                            and api_backend_name
                            == _field(db_service, "backend_name")
                            and api_backend_name
                            == self._backend_name_from_cluster(api_cluster)
                        ):
                            api_observed["backend_name"] = api_backend_name
                        service_node.facts["api_observed"] = api_observed
                        service_node.evidence_ids[:] = _dedupe([
                            *service_node.evidence_ids,
                            *([service_evidence] if service_evidence else []),
                        ])
        else:
            result.blockers.append("Cinder service list payload invalid")

        self._validate_required_edges(result)
        result.blockers[:] = list(dict.fromkeys(result.blockers))
        result.unknowns[:] = list(dict.fromkeys(result.unknowns))
        return result

    def _optional_rows(self, table: str, filters: Mapping[str, Sequence[str]], result: CollectorResult):
        if table not in self.available_tables or not filters or not any(filters.values()):
            return []
        return self._db_rows(table, filters, result)

    def _db_rows(self, table: str, filters: Mapping[str, Sequence[str]], result: CollectorResult):
        if table not in self.available_tables:
            return []
        if not filters or not any(filters.values()):
            result.blockers.append(f"DB filter missing: cinder.{table}")
            return []
        safe_filters = {str(key): list(values) for key, values in filters.items() if values}
        source = getattr(self.client, "db_records", None)
        try:
            response = source(table, deepcopy(safe_filters)) if callable(source) else None
        except Exception:
            result.blockers.append(f"DB probe failed: cinder.{table}")
            return []
        evidence = None
        records = response
        if isinstance(response, tuple) and len(response) == 2:
            records, evidence = response
        expected = {
            "evidence_id": f"{self.side}-db:cinder.{table}",
            "schema": "cinder", "table": table, "filters": deepcopy(safe_filters),
        }
        if evidence != expected:
            result.blockers.append(f"DB evidence invalid: {table}")
        else:
            result.evidence.append({
                "evidence_id": expected["evidence_id"], "kind": "db-jsonl",
                "schema": "cinder", "table": table, "filters": deepcopy(safe_filters),
            })
        if not isinstance(records, list):
            result.blockers.append(f"DB facts missing or invalid: cinder.{table}")
            return []
        rows = []
        for index, record in enumerate(records):
            if not isinstance(record, Mapping) or set(record) != {"_schema", "_table", "row"} or record.get("_schema") != "cinder" or record.get("_table") != table or not isinstance(record.get("row"), Mapping):
                result.blockers.append(f"DB JSONL record invalid: {table}[{index}]")
                continue
            row = record["row"]
            if not any(row.get(field) in values for field, values in safe_filters.items()):
                result.blockers.append(f"DB row outside filter: {table}[{index}]")
                continue
            self._validate_ids(table, row, result)
            rows.append(_PolicyMapping(deepcopy(dict(row)), self._allow_fixture_aliases))
        return rows

    def _validate_ids(self, table: str, row: Mapping[str, Any], result: CollectorResult):
        for field in _TABLE_ID_FIELDS.get(table, ()):
            value = _field(row, field)
            if value in (None, ""):
                continue
            if _openstack_id(value, self._allow_fixture_aliases) is None:
                result.blockers.append(f"Cinder dependency UUID invalid: {table}.{field}")

    def _api(self, command: Sequence[str], evidence_id: str, result: CollectorResult):
        try:
            payload, evidence = self.client.json(command, evidence_id)
        except Exception:
            result.blockers.append(f"OpenStack API probe failed: {evidence_id}")
            return _PolicyMapping({}, self._allow_fixture_aliases), None
        actual_evidence_id = _field(evidence, "evidence_id", "id")
        if actual_evidence_id != evidence_id:
            result.blockers.append(f"OpenStack API evidence invalid: {evidence_id}")
            return _PolicyMapping(deepcopy(payload) if isinstance(payload, Mapping) else {}, self._allow_fixture_aliases), None
        result.evidence.append({
            "evidence_id": evidence_id, "kind": "openstack-json", "command": list(command),
        })
        if not isinstance(payload, (Mapping, list)):
            result.blockers.append(f"OpenStack API payload invalid: {evidence_id}")
            return _PolicyMapping({}, self._allow_fixture_aliases), evidence_id
        if isinstance(payload, Mapping):
            return _PolicyMapping(deepcopy(dict(payload)), self._allow_fixture_aliases), evidence_id
        return deepcopy(payload), evidence_id

    def _secret_metadata(self, key_id: str, result: CollectorResult):
        command = ["secret", "get", key_id, "-f", "json"]
        evidence_id = f"cinder-{self.side}-secret-get-{key_id}"
        try:
            payload, evidence = self.client.json(command, evidence_id)
        except Exception as error:
            status = getattr(error, "status_code", None)
            reason = getattr(error, "reason", None)
            if reason == "endpoint-missing":
                result.unknowns.append(f"encryption key service endpoint missing: {key_id}")
            elif status in {403, 404}:
                result.blockers.append(f"encryption key {key_id} metadata access returned {status}")
            else:
                result.unknowns.append(f"encryption key metadata probe failed: {key_id}")
            return _PolicyMapping({}, self._allow_fixture_aliases), None, True
        actual_evidence_id = _field(evidence, "evidence_id", "id")
        if actual_evidence_id != evidence_id or not isinstance(payload, Mapping):
            result.blockers.append(f"encryption key metadata evidence invalid: {key_id}")
            return _PolicyMapping({}, self._allow_fixture_aliases), None, True
        identities = []
        direct_identity = _field(payload, "id", "uuid")
        if direct_identity not in (None, ""):
            identities.append(
                _openstack_id(direct_identity, self._allow_fixture_aliases)
            )
        href = _field(payload, "secret_href", "secret_ref", "href")
        if href not in (None, ""):
            identities.append(
                _barbican_href_identity(
                    href, self._allow_fixture_aliases
                )
            )
        if not identities or any(identity != key_id for identity in identities):
            result.blockers.append(
                "encryption key metadata identity invalid"
            )
            return _PolicyMapping({}, self._allow_fixture_aliases), None, True
        if _field(payload, "status") != "ACTIVE":
            result.blockers.append("encryption key metadata state invalid")
            return _PolicyMapping({}, self._allow_fixture_aliases), None, True
        result.evidence.append({
            "evidence_id": evidence_id, "kind": "openstack-json", "command": command,
        })
        return _PolicyMapping(deepcopy(dict(payload)), self._allow_fixture_aliases), evidence_id, False

    def _attachment_ids(self, value: object, result: CollectorResult, volume_id: str) -> Set[str]:
        if not isinstance(value, list):
            result.blockers.append(f"volume attachments payload invalid: {volume_id}")
            return set()
        values = set()
        for item in value:
            candidate = _field(item, "id", "attachment_id") if isinstance(item, Mapping) else item
            identifier = _openstack_id(candidate, self._allow_fixture_aliases)
            if identifier is None:
                result.blockers.append(f"attachment UUID invalid for volume: {volume_id}")
            else:
                values.add(identifier)
        return values

    @staticmethod
    def _backend_from_host(value: object) -> Optional[str]:
        components = _cinder_host_components(value)
        if components is None:
            return None
        suffix = (
            f"#{components['pool']}" if "pool" in components else ""
        )
        return f"{components['backend_name']}{suffix}"

    @staticmethod
    def _backend_name_from_host(value: object) -> Optional[str]:
        components = _cinder_host_components(value)
        return components["backend_name"] if components is not None else None

    @staticmethod
    def _backend_name_from_cluster(value: object) -> Optional[str]:
        components = _cluster_components(value)
        return components["backend_name"] if components is not None else None

    @staticmethod
    def _validate_required_edges(result: CollectorResult):
        keys = {node.key for node in result.nodes}
        for edge in result.edges:
            if not edge.required:
                continue
            for key in (edge.source, edge.target):
                if key not in keys:
                    result.blockers.append(f"required dependency node missing: {key}")
