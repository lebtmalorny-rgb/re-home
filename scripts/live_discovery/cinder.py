from copy import deepcopy
import json
import re
import uuid
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from .contract import CollectorResult, DependencyEdge, ResourceNode


CORE_TABLES = ("volumes", "volume_attachment", "volume_types", "services")
OPTIONAL_TABLES = (
    "volume_type_extra_specs", "volume_type_qos_specs",
    "quality_of_service_specs", "encryption", "snapshots",
    "volume_metadata", "volume_glance_metadata", "volume_admin_metadata",
    "groups",
)

_FIXTURE_POLICY_TOKEN = object()
_FIXTURE_ALIAS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@#-]{0,127}$")
_BACKEND_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@#-]{0,254}$")
_SAFE_TEXT = re.compile(r"^[^\x00-\x1f\x7f]{0,1024}$")
_SENSITIVE = re.compile(
    r"password|passwd|(?:^|[_-])pwd(?:$|[_-])|token|secret|chap|"
    r"credential|connector|connection[_-]?(?:info|data)", re.IGNORECASE,
)

_TABLE_ID_FIELDS = {
    "volumes": (
        "id", "volume_type_id", "service_uuid", "encryption_key_id",
        "snapshot_id", "source_volid", "group_id", "consistencygroup_id",
    ),
    "volume_attachment": ("id", "volume_id", "instance_uuid"),
    "volume_types": ("id",),
    "volume_type_extra_specs": ("volume_type_id",),
    "volume_type_qos_specs": ("volume_type_id", "qos_specs_id"),
    "quality_of_service_specs": ("id",),
    "services": ("uuid",),
    "encryption": ("volume_type_id",),
    "snapshots": ("id", "volume_id", "group_snapshot_id"),
    "volume_metadata": ("volume_id",),
    "volume_glance_metadata": ("volume_id",),
    "volume_admin_metadata": ("volume_id",),
    "groups": ("id",),
}

_VOLUME_FIELDS = (
    "id", "display_name", "status", "size", "availability_zone",
    "bootable", "multiattach", "volume_type_id", "service_uuid", "host",
    "cluster_name", "encryption_key_id", "snapshot_id", "source_volid",
    "group_id", "consistencygroup_id", "storage_backend_id",
)
_API_VOLUME_FIELDS = (
    "id", "name", "status", "size", "availability_zone", "bootable",
    "multiattach", "volume_type_id", "type_id",
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


def _allowlisted(payload: object, fields: Sequence[str]) -> Dict[str, Any]:
    if not isinstance(payload, Mapping):
        return {}
    result: Dict[str, Any] = {}
    for field in fields:
        value = _field(payload, field)
        safe = _safe_value(value)
        if safe is not None:
            result[field] = safe
    return result


def _safe_key_values(rows: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    result = []
    for row in rows:
        key = _field(row, "key")
        value = _field(row, "value")
        if not isinstance(key, str) or not _SAFE_TEXT.fullmatch(key):
            continue
        safe_value = "[REDACTED]" if _SENSITIVE.search(key) else _safe_value(value)
        if safe_value is not None:
            result.append({"key": key, "value": safe_value})
    return result


def _is_deleted(row: Mapping[str, Any]) -> bool:
    return _field(row, "deleted") not in (None, False, 0, "0", "")


def _parse_mapping(value: object) -> Optional[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, Mapping) else None
    return None


def _connection_summary(value: object) -> Dict[str, Any]:
    payload = _parse_mapping(value) or {}
    driver = _field(payload, "driver_volume_type", "driver_type")
    driver_type = driver if isinstance(driver, str) and _FIXTURE_ALIAS.fullmatch(driver) else None
    data = _field(payload, "data")
    data = data if isinstance(data, Mapping) else {}
    target_count = 0
    for name in ("target_portals", "target_iqns", "targets", "target_wwn"):
        candidate = _field(data, name)
        if isinstance(candidate, (list, tuple)):
            target_count = max(target_count, len(candidate))
        elif isinstance(candidate, str) and candidate:
            target_count = max(target_count, 1)
    multipath = _field(data, "multipath")
    return {
        "driver_type": driver_type,
        "target_count": target_count,
        "multipath": multipath if isinstance(multipath, bool) else False,
    }


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
        extra_specs = self._optional_rows("volume_type_extra_specs", {"volume_type_id": type_ids}, result)
        type_qos = self._optional_rows("volume_type_qos_specs", {"volume_type_id": type_ids}, result)
        qos_ids = _dedupe(
            value for row in type_qos if (value := _row_id(row, "qos_specs_id")) is not None
        )
        qos = self._optional_rows("quality_of_service_specs", {"id": qos_ids}, result)
        service_ids = _dedupe(
            value for row in volume_rows
            if (value := _row_id(row, "service_uuid")) is not None
        )
        services = self._db_rows("services", {"uuid": service_ids}, result) if service_ids else []
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
        groups = self._optional_rows("groups", {"id": group_ids}, result)

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
            facts = _allowlisted(row, _ATTACHMENT_FIELDS)
            facts.update(_allowlisted(api, ("id", "volume_id", "server_id", "instance_uuid", "status", "attach_status", "attach_mode")))
            connection_info = _field(row, "connection_info")
            connector = _field(row, "connector")
            if (
                _field(row, "attach_status") in {"attached", "attaching"}
                and (
                    _parse_mapping(connection_info) is None
                    or _parse_mapping(connector) is None
                )
            ):
                result.blockers.append(
                    f"active attachment connection metadata invalid: {attachment_id}"
                )
            facts["connection_info"] = "[REDACTED]"
            facts["connector"] = "[REDACTED]"
            facts["connection_summary"] = _connection_summary(connection_info)
            add_node("volume_attachment", attachment_id, facts, [evidence_id] if evidence_id else [])

        encryption_type_ids = {
            value for row in encryptions
            if (value := _row_id(row, "volume_type_id")) is not None
        }
        type_rows = {_row_id(row, "id"): row for row in types if not _is_deleted(row)}
        service_rows = {_row_id(row, "uuid"): row for row in services if not _is_deleted(row)}
        group_row_ids = {_row_id(row, "id") for row in groups if not _is_deleted(row)}
        snapshot_rows = {_row_id(row, "id"): row for row in snapshots if not _is_deleted(row)}

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
            facts = _allowlisted(row, _VOLUME_FIELDS)
            facts.update(_allowlisted(api, _API_VOLUME_FIELDS))
            facts["normalizations"] = {
                "service_uuid": _row_id(row, "service_uuid"),
                "volume_type_id": _row_id(row, "volume_type_id"),
                "host": _safe_value(_field(row, "host")),
                "cluster_name": _safe_value(_field(row, "cluster_name")),
            }
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
                    type_facts.update(_allowlisted(type_api, _TYPE_FIELDS))
                    type_facts["extra_specs"] = _safe_key_values([
                        item for item in extra_specs if _row_id(item, "volume_type_id") == type_id
                    ])
                    type_qos_ids = {
                        _row_id(item, "qos_specs_id") for item in type_qos
                        if _row_id(item, "volume_type_id") == type_id
                    }
                    type_facts["qos_specs"] = [
                        _allowlisted(item, ("id", "name", "consumer"))
                        for item in qos if _row_id(item, "id") in type_qos_ids
                    ]
                    encryption_rows = [item for item in encryptions if _row_id(item, "volume_type_id") == type_id]
                    type_facts["encryption"] = [
                        _allowlisted(item, ("provider", "control_location", "key_size"))
                        for item in encryption_rows
                    ]
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
                    add_node("cinder_service", service_id, _allowlisted(service_row, _SERVICE_FIELDS))
                add_edge(volume.key, f"cinder_service:{service_id}", "managed_by")
            else:
                result.blockers.append(f"Cinder service UUID missing: {volume_id}")

            backend_id = _field(row, "storage_backend_id") or self._backend_from_host(_field(row, "host"))
            if isinstance(backend_id, str) and _BACKEND_ID.fullmatch(backend_id):
                add_node("storage_backend", backend_id, {
                    "host": _safe_value(_field(row, "host")),
                    "cluster_name": _safe_value(_field(row, "cluster_name")),
                })
                add_edge(volume.key, f"storage_backend:{backend_id}", "has_backing_backend")
            else:
                result.blockers.append(f"storage backend identifier invalid: {volume_id}")

            encrypted = type_id in encryption_type_ids
            key_id = _row_id(row, "encryption_key_id")
            if encrypted and key_id is None:
                result.blockers.append(f"encrypted volume {volume_id} has no key UUID")
            if key_id:
                key_api, key_evidence, failure = self._secret_metadata(key_id, result)
                key_facts = _allowlisted(key_api, ("status", "secret_type", "content_types"))
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
                    snapshot_facts.update(_allowlisted(snapshot_api, _SNAPSHOT_FIELDS))
                    add_node("snapshot", snapshot_id, snapshot_facts, [snapshot_evidence] if snapshot_evidence else [])
                add_edge(volume.key, f"snapshot:{snapshot_id}", "created_from_snapshot")
            for group_id in (_row_id(row, "group_id"), _row_id(row, "consistencygroup_id")):
                if group_id and group_id not in group_row_ids:
                    result.blockers.append(f"required volume group missing: {group_id}")

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
                if len(matches) != 1:
                    result.blockers.append(f"Cinder service API identity missing: {service_id}")
                elif service_id in service_rows:
                    api_host = _field(matches[0], "host")
                    if api_host != db_host:
                        result.blockers.append(f"Cinder service API/DB host mismatch: {service_id}")
                    add_node("cinder_service", service_id, _allowlisted(matches[0], ("host", "binary", "status", "state")), [service_evidence] if service_evidence else [])
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
            if status in {403, 404}:
                result.blockers.append(f"encryption key {key_id} metadata access returned {status}")
            elif reason == "endpoint-missing":
                result.unknowns.append(f"encryption key service endpoint missing: {key_id}")
            else:
                result.unknowns.append(f"encryption key metadata probe failed: {key_id}")
            return _PolicyMapping({}, self._allow_fixture_aliases), None, True
        actual_evidence_id = _field(evidence, "evidence_id", "id")
        if actual_evidence_id != evidence_id or not isinstance(payload, Mapping):
            result.blockers.append(f"encryption key metadata evidence invalid: {key_id}")
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
        if not isinstance(value, str) or "@" not in value:
            return None
        backend = value.split("@", 1)[1]
        return backend if _BACKEND_ID.fullmatch(backend) else None

    @staticmethod
    def _validate_required_edges(result: CollectorResult):
        keys = {node.key for node in result.nodes}
        for edge in result.edges:
            if not edge.required:
                continue
            for key in (edge.source, edge.target):
                if key not in keys:
                    result.blockers.append(f"required dependency node missing: {key}")
