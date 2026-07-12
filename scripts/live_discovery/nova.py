from copy import deepcopy
import json
import re
import uuid
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from .contract import (
    CheckResult,
    CollectorResult,
    DependencyEdge,
    ResourceNode,
)


DB_TABLES = (
    "host_mappings",
    "cell_mappings",
    "instance_mappings",
    "request_specs",
    "instances",
    "block_device_mapping",
    "instance_info_caches",
    "compute_nodes",
    "services",
)

DB_SCHEMAS = {
    "host_mappings": "nova_api",
    "cell_mappings": "nova_api",
    "instance_mappings": "nova_api",
    "request_specs": "nova_api",
    "instances": "nova",
    "block_device_mapping": "nova",
    "instance_info_caches": "nova",
    "compute_nodes": "nova",
    "services": "nova",
}

_MYSQL_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]{0,63}$")


def cell_database_schema(connection: object) -> Optional[str]:
    """Return only a validated schema name from a Nova cell connection URI."""
    if not isinstance(connection, str) or not connection or "%" in connection:
        return None
    try:
        parsed = urlsplit(connection)
    except ValueError:
        return None
    if not parsed.scheme.startswith("mysql") or not parsed.netloc:
        return None
    path = parsed.path.lstrip("/")
    if "/" in path or _MYSQL_IDENTIFIER.fullmatch(path) is None:
        return None
    return path

_SAFE_FLAVOR_FIELDS = (
    "id",
    "name",
    "vcpus",
    "ram",
    "disk",
    "ephemeral",
    "swap",
    "rxtx_factor",
    "is_public",
    "properties",
)

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


def _canonical_uuid(value: object) -> Optional[str]:
    if not isinstance(value, str):
        return None
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return None
    canonical = str(parsed)
    return canonical if value == canonical else None


def _is_deleted(row: Mapping[str, Any]) -> bool:
    deleted = row.get("deleted")
    return deleted not in (None, 0, "0", False, "")


def _evidence_id(evidence: object) -> Optional[str]:
    value = _field(evidence, "evidence_id", "id")
    return value if isinstance(value, str) and value else None


def _reference_id(value: object) -> Optional[str]:
    if isinstance(value, Mapping):
        candidate = _field(value, "id", "uuid")
        return str(candidate) if candidate not in (None, "") else None
    if isinstance(value, str) and value and value.upper() not in {"N/A", "NONE"}:
        parenthesized = re.search(r"\(([^()]+)\)\s*$", value)
        return parenthesized.group(1) if parenthesized else value
    return None


def _network_port_ids(value: object) -> Tuple[List[str], List[object], bool]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return [], [], False
    if not isinstance(value, list):
        return [], [], False
    identifiers = []
    invalid = []
    for item in value:
        if not isinstance(item, Mapping):
            return [], [], False
        identifier = _field(item, "id", "port_id")
        if identifier in (None, ""):
            return [], [], False
        canonical = _canonical_uuid(identifier)
        if canonical is not None:
            identifiers.append(canonical)
        else:
            invalid.append(identifier)
    return list(dict.fromkeys(identifiers)), invalid, True


class NovaCollector:
    def __init__(self, client, side: str, cell_schema: str = "nova") -> None:
        if _MYSQL_IDENTIFIER.fullmatch(cell_schema) is None:
            raise ValueError("Nova cell schema is invalid")
        self.client = client
        self.side = side
        self.cell_schema = cell_schema

    def _db_schema(self, table: str) -> str:
        return (
            self.cell_schema
            if DB_SCHEMAS[table] == "nova"
            else DB_SCHEMAS[table]
        )

    def collect(self, rehome_host: str) -> CollectorResult:
        result = CollectorResult(service="nova", side=self.side)
        if not isinstance(rehome_host, str) or not rehome_host:
            result.blockers.append("rehome host missing")
            return result

        live_tables = DB_TABLES
        if self.side != "source" or not getattr(
            self.client, "has_cell_mapping_evidence", False
        ):
            live_tables = tuple(table for table in DB_TABLES if table != "cell_mappings")
        rows = {table: self._db_rows(table, result) for table in live_tables}
        rows.setdefault("cell_mappings", [])
        nodes: Dict[str, ResourceNode] = {}
        edge_keys = set()

        def add_node(
            kind: str,
            identifier: object,
            facts: Optional[Mapping[str, Any]] = None,
            evidence_ids: Optional[Iterable[str]] = None,
        ) -> Optional[ResourceNode]:
            if identifier in (None, ""):
                return None
            node = ResourceNode(
                kind,
                str(identifier),
                self.side,
                deepcopy(dict(facts or {})),
                list(dict.fromkeys(evidence_ids or [])),
            )
            existing = nodes.get(node.key)
            if existing is None:
                nodes[node.key] = node
                result.nodes.append(node)
                return node
            existing.facts.update(node.facts)
            existing.evidence_ids[:] = list(
                dict.fromkeys([*existing.evidence_ids, *node.evidence_ids])
            )
            return existing

        def add_edge(source: str, target: str, relation: str, required: bool) -> None:
            key = (source, target, relation, required)
            if key in edge_keys:
                return
            edge_keys.add(key)
            result.edges.append(DependencyEdge(source, target, relation, required))

        host_node = add_node("compute_host", rehome_host, {"host": rehome_host})
        assert host_node is not None

        server_list, server_list_evidence = self._json(
            [
                "server", "list", "--all-projects", "--host", rehome_host,
                "--long", "-f", "json",
            ],
            f"nova-{self.side}-server-list-{rehome_host}",
            result,
        )
        service_list, service_evidence = self._json(
            ["compute", "service", "list", "--host", rehome_host, "-f", "json"],
            f"nova-{self.side}-compute-service-list-{rehome_host}",
            result,
        )
        hypervisor, hypervisor_evidence = self._json(
            ["hypervisor", "show", rehome_host, "-f", "json"],
            f"nova-{self.side}-hypervisor-show-{rehome_host}",
            result,
        )
        providers, provider_evidence = self._json(
            ["resource", "provider", "list", "--name", rehome_host, "-f", "json"],
            f"nova-{self.side}-resource-provider-list-{rehome_host}",
            result,
        )

        canonical_service = self._collect_service(
            rehome_host,
            service_list,
            rows["services"],
            service_evidence,
            result,
            add_node,
            add_edge,
        )
        compute_node = self._collect_compute_node(
            rehome_host,
            hypervisor,
            rows["compute_nodes"],
            canonical_service,
            hypervisor_evidence,
            result,
            add_node,
            add_edge,
        )
        del compute_node
        placement_node = self._collect_placement_provider(
            rehome_host,
            providers,
            provider_evidence,
            result,
            add_node,
            add_edge,
        )
        host_mapping = self._canonical_host_mapping(
            rehome_host, rows["host_mappings"], result
        )
        cell_mapping = (
            self._canonical_cell_mapping(host_mapping, rows["cell_mappings"], result)
            if self.side == "source" and getattr(
                self.client, "has_cell_mapping_evidence", False
            )
            else None
        )

        instance_entries = server_list if isinstance(server_list, list) else []
        if not isinstance(server_list, list):
            result.blockers.append("invalid server list payload")
        instance_counts: Dict[str, int] = {}
        instance_summaries: Dict[str, Mapping[str, Any]] = {}
        for entry in instance_entries:
            instance_uuid = _canonical_uuid(_field(entry, "id"))
            if instance_uuid is None:
                result.blockers.append(
                    f"instance UUID invalid: {_field(entry, 'id')!r}"
                )
                continue
            instance_counts[instance_uuid] = instance_counts.get(instance_uuid, 0) + 1
            instance_summaries.setdefault(instance_uuid, entry)

        for instance_uuid, count in instance_counts.items():
            if count > 1:
                result.blockers.append(f"instance UUID duplicate: {instance_uuid}")

        flavor_nodes: Dict[str, ResourceNode] = {}
        for instance_uuid, summary in instance_summaries.items():
            self._collect_instance(
                rehome_host,
                instance_uuid,
                summary,
                rows,
                host_mapping,
                cell_mapping,
                placement_node,
                flavor_nodes,
                result,
                add_node,
                add_edge,
            )

        identity_blockers = [
            blocker
            for blocker in result.blockers
            if any(
                marker in blocker
                for marker in (
                    "host mismatch",
                    "host mapping",
                    "canonical nova service",
                    "compute node",
                    "hypervisor",
                    "placement provider",
                    "instance UUID",
                    "instance mapping",
                    "instance DB row",
                    "cell mapping",
                )
            )
        ]
        result.checks.append(
            CheckResult(
                f"nova.{self.side}.host-identity",
                "BLOCKED" if identity_blockers else "PASS",
                identity_blockers[0]
                if identity_blockers
                else f"canonical Nova identity confirmed for {rehome_host}",
                resource_ids=[host_node.key],
            )
        )
        return result

    def _db_rows(
        self,
        table: str,
        result: CollectorResult,
    ) -> List[Mapping[str, Any]]:
        source = getattr(self.client, "db_records", None)
        uses_db_records = callable(source)
        records = source(table) if uses_db_records else None
        evidence = None
        if records is None:
            facts = getattr(self.client, "db_facts", None)
            if isinstance(facts, Mapping):
                records = facts.get(table)
        if isinstance(records, tuple) and len(records) == 2:
            records, evidence = records
        if uses_db_records:
            self._append_db_evidence(table, evidence, result)
        if records is None:
            result.blockers.append(f"DB facts missing: {table}")
            return []
        if not isinstance(records, list):
            result.blockers.append(f"DB facts invalid: {table}")
            return []

        rows = []
        for index, record in enumerate(records):
            if not isinstance(record, Mapping):
                result.blockers.append(f"DB JSONL record invalid: {table}[{index}]")
                continue
            if (
                record.get("_schema") != self._db_schema(table)
                or record.get("_table") != table
                or not isinstance(record.get("row"), Mapping)
            ):
                result.blockers.append(f"DB JSONL record invalid: {table}[{index}]")
                continue
            row = record["row"]
            rows.append(deepcopy(dict(row)))
        return rows

    def _append_db_evidence(
        self,
        table: str,
        evidence: object,
        result: CollectorResult,
    ) -> None:
        if not isinstance(evidence, Mapping) or not isinstance(
            evidence.get("evidence_id"), str
        ):
            result.blockers.append(f"DB evidence invalid: {table}")
            return
        result.evidence.append(
            {
                "evidence_id": evidence["evidence_id"],
                "kind": "db-jsonl",
                "schema": DB_SCHEMAS[table],
                "table": table,
            }
        )

    def _json(
        self,
        command: Sequence[str],
        evidence_id: str,
        result: CollectorResult,
    ) -> Tuple[Any, Optional[str]]:
        payload, evidence = self.client.json(command, evidence_id, required=True)
        if isinstance(evidence, Mapping):
            result.evidence.append(deepcopy(dict(evidence)))
        identifier = _evidence_id(evidence)
        return payload, identifier

    def _collect_service(
        self,
        rehome_host: str,
        api_services: object,
        db_services: List[Mapping[str, Any]],
        evidence_id: Optional[str],
        result: CollectorResult,
        add_node,
        add_edge,
    ) -> Optional[Mapping[str, Any]]:
        api_rows = api_services if isinstance(api_services, list) else []
        if not isinstance(api_services, list):
            result.blockers.append("invalid compute service list payload")
        api_canonical = [
            row
            for row in api_rows
            if _field(row, "binary") == "nova-compute"
            and _field(row, "host") == rehome_host
        ]
        db_canonical = [
            row
            for row in db_services
            if row.get("binary") == "nova-compute"
            and row.get("host") == rehome_host
            and not _is_deleted(row)
        ]
        wrong_hosts = [
            _field(row, "host")
            for row in api_rows
            if _field(row, "binary") == "nova-compute"
            and _field(row, "host") != rehome_host
        ]
        if wrong_hosts:
            result.blockers.append(
                f"nova service host mismatch: expected {rehome_host} got {wrong_hosts[0]}"
            )
        if not api_canonical or not db_canonical:
            result.blockers.append(f"canonical nova service missing: {rehome_host}")
            return None
        if len(api_canonical) != 1 or len(db_canonical) != 1:
            result.blockers.append(f"canonical nova service duplicate: {rehome_host}")
            return None

        api_row = api_canonical[0]
        db_row = db_canonical[0]
        if str(_field(api_row, "id")) != str(db_row.get("id")):
            result.blockers.append(f"canonical nova service identity mismatch: {rehome_host}")
            return None
        raw_identifier = db_row.get("uuid")
        if not raw_identifier:
            result.blockers.append(f"canonical nova service UUID missing: {rehome_host}")
            return None
        identifier = _canonical_uuid(raw_identifier)
        if identifier is None:
            result.blockers.append(
                f"canonical nova service UUID invalid: {rehome_host} "
                f"got {raw_identifier!r}"
            )
            return None
        facts = {
            "host": rehome_host,
            "binary": "nova-compute",
            "service_id": db_row.get("id"),
            "status": _field(api_row, "status"),
            "state": _field(api_row, "state"),
            "disabled": db_row.get("disabled"),
        }
        node = add_node(
            "nova_service",
            identifier,
            facts,
            [evidence_id] if evidence_id else [],
        )
        add_edge(
            f"compute_host:{rehome_host}",
            node.key,
            "has_nova_service",
            True,
        )
        return db_row

    def _collect_compute_node(
        self,
        rehome_host: str,
        hypervisor: object,
        compute_nodes: List[Mapping[str, Any]],
        service: Optional[Mapping[str, Any]],
        evidence_id: Optional[str],
        result: CollectorResult,
        add_node,
        add_edge,
    ) -> Optional[ResourceNode]:
        api_host = _field(hypervisor, "hypervisor_hostname", "host")
        api_identity = _field(hypervisor, "id", "uuid")
        if not isinstance(hypervisor, Mapping):
            result.blockers.append("invalid hypervisor show payload")
        elif api_host != rehome_host:
            result.blockers.append(
                f"hypervisor host mismatch: expected {rehome_host} got {api_host}"
            )
        if api_identity in (None, ""):
            result.blockers.append(f"hypervisor identity missing: {rehome_host}")
        service_id = service.get("id") if service else None
        canonical = [
            row
            for row in compute_nodes
            if not _is_deleted(row)
            and row.get("service_id") == service_id
            and (row.get("host") == rehome_host or row.get("hypervisor_hostname") == rehome_host)
        ]
        if not canonical:
            result.blockers.append(f"compute node missing: {rehome_host}")
            return None
        if len(canonical) != 1:
            result.blockers.append(f"compute node duplicate: {rehome_host}")
            return None
        row = canonical[0]
        raw_identifier = row.get("uuid")
        if not raw_identifier:
            result.blockers.append(f"compute node UUID missing: {rehome_host}")
            return None
        identifier = _canonical_uuid(raw_identifier)
        if identifier is None:
            result.blockers.append(
                f"compute node UUID invalid: {rehome_host} got {raw_identifier!r}"
            )
            return None
        if api_identity not in (None, ""):
            if (
                isinstance(api_identity, int)
                and not isinstance(api_identity, bool)
            ) or (isinstance(api_identity, str) and api_identity.isdigit()):
                if int(api_identity) != row.get("id"):
                    result.blockers.append(
                        f"hypervisor identity mismatch: {rehome_host} API "
                        f"{api_identity} DB {row.get('id')}"
                    )
            else:
                canonical_api_identity = _canonical_uuid(api_identity)
                if canonical_api_identity is None:
                    result.blockers.append(
                        f"hypervisor identity invalid: {rehome_host} got "
                        f"{api_identity!r}"
                    )
                elif canonical_api_identity != identifier:
                    result.blockers.append(
                        f"hypervisor identity mismatch: {rehome_host} API "
                        f"{canonical_api_identity} DB {identifier}"
                    )
        facts = {
            key: deepcopy(row.get(key))
            for key in (
                "host", "hypervisor_hostname", "service_id", "vcpus", "memory_mb",
            )
        }
        facts["status"] = _field(hypervisor, "status")
        facts["state"] = _field(hypervisor, "state")
        facts["api_identity"] = api_identity
        node = add_node(
            "compute_node",
            identifier,
            facts,
            [evidence_id] if evidence_id else [],
        )
        add_edge(
            f"compute_host:{rehome_host}", node.key, "has_compute_node", True
        )
        return node

    def _collect_placement_provider(
        self,
        rehome_host: str,
        providers: object,
        evidence_id: Optional[str],
        result: CollectorResult,
        add_node,
        add_edge,
    ) -> Optional[ResourceNode]:
        provider_rows = providers if isinstance(providers, list) else []
        if not isinstance(providers, list):
            result.blockers.append("invalid placement provider list payload")
        canonical = [row for row in provider_rows if _field(row, "name") == rehome_host]
        if not canonical:
            result.blockers.append(f"placement provider missing: {rehome_host}")
            return None
        if len(canonical) != 1:
            result.blockers.append(f"placement provider duplicate: {rehome_host}")
            return None
        row = canonical[0]
        raw_identifier = _field(row, "uuid", "id")
        if not raw_identifier:
            result.blockers.append(f"placement provider UUID missing: {rehome_host}")
            return None
        identifier = _canonical_uuid(raw_identifier)
        if identifier is None:
            result.blockers.append(
                f"placement provider UUID invalid: {rehome_host} got {raw_identifier!r}"
            )
            return None
        node = add_node(
            "placement_provider",
            identifier,
            {
                "name": rehome_host,
                "generation": _field(row, "generation"),
                "consumer_allocations": {},
            },
            [evidence_id] if evidence_id else [],
        )
        add_edge(
            f"compute_host:{rehome_host}",
            node.key,
            "has_placement_provider",
            True,
        )
        return node

    def _canonical_host_mapping(
        self,
        rehome_host: str,
        mappings: List[Mapping[str, Any]],
        result: CollectorResult,
    ) -> Optional[Mapping[str, Any]]:
        canonical = [row for row in mappings if row.get("host") == rehome_host]
        if not canonical:
            result.blockers.append(f"host mapping missing: {rehome_host}")
            return None
        if len(canonical) != 1:
            result.blockers.append(f"host mapping duplicate: {rehome_host}")
            return None
        if not canonical[0].get("cell_id"):
            result.blockers.append(f"host mapping cell missing: {rehome_host}")
            return None
        return canonical[0]

    def _canonical_cell_mapping(
        self,
        host_mapping: Optional[Mapping[str, Any]],
        mappings: List[Mapping[str, Any]],
        result: CollectorResult,
    ) -> Optional[Mapping[str, Any]]:
        if host_mapping is None:
            return None
        cell_id = host_mapping.get("cell_id")
        canonical = [
            row for row in mappings
            if row.get("id") == cell_id or row.get("uuid") == cell_id
        ]
        if len(canonical) != 1:
            result.blockers.append(
                "cell mapping missing" if not canonical else "cell mapping duplicate"
            )
            return None
        schema = canonical[0].get("database_schema")
        if not isinstance(schema, str):
            schema = cell_database_schema(canonical[0].get("database_connection"))
        if not isinstance(schema, str) or _MYSQL_IDENTIFIER.fullmatch(schema) is None:
            schema = None
        if schema is None:
            result.blockers.append("cell mapping database schema invalid")
            return None
        return {
            "id": cell_id,
            "uuid": canonical[0].get("uuid"),
            "schema": schema,
            "evidence_id": canonical[0].get("_evidence_id"),
        }

    def _collect_instance(
        self,
        rehome_host: str,
        instance_uuid: str,
        summary: Mapping[str, Any],
        rows: Mapping[str, List[Mapping[str, Any]]],
        host_mapping: Optional[Mapping[str, Any]],
        cell_mapping: Optional[Mapping[str, Any]],
        placement_node: Optional[ResourceNode],
        flavor_nodes: Dict[str, ResourceNode],
        result: CollectorResult,
        add_node,
        add_edge,
    ) -> None:
        summary_host = _field(summary, "host", "OS-EXT-SRV-ATTR:host")
        if summary_host != rehome_host:
            result.blockers.append(
                f"instance host mismatch: {instance_uuid} expected {rehome_host} "
                f"got {summary_host}"
            )

        server, server_evidence = self._json(
            ["server", "show", instance_uuid, "-f", "json"],
            f"nova-{self.side}-server-show-{instance_uuid}",
            result,
        )
        shown_uuid = _canonical_uuid(_field(server, "id"))
        if shown_uuid != instance_uuid:
            result.blockers.append(
                f"instance API identity mismatch: expected {instance_uuid} got {_field(server, 'id')}"
            )
        api_host = _field(server, "OS-EXT-SRV-ATTR:host", "host")
        if api_host != rehome_host:
            result.blockers.append(
                f"instance host mismatch: {instance_uuid} expected {rehome_host} got {api_host}"
            )

        db_instances = [
            row
            for row in rows["instances"]
            if row.get("uuid") == instance_uuid and not _is_deleted(row)
        ]
        if not db_instances:
            result.blockers.append(f"instance DB row missing: {instance_uuid}")
            db_instance: Mapping[str, Any] = {}
        elif len(db_instances) > 1:
            result.blockers.append(f"instance DB row duplicate: {instance_uuid}")
            db_instance = db_instances[0]
        else:
            db_instance = db_instances[0]
        db_host = db_instance.get("host")
        if db_instance and db_host != rehome_host:
            result.blockers.append(
                f"instance DB host mismatch: {instance_uuid} expected {rehome_host} got {db_host}"
            )

        mappings = [
            row
            for row in rows["instance_mappings"]
            if row.get("instance_uuid") == instance_uuid
        ]
        if not mappings:
            result.blockers.append(f"instance mapping missing: {instance_uuid}")
            mapping: Mapping[str, Any] = {}
        elif len(mappings) > 1:
            result.blockers.append(f"instance mapping duplicate: {instance_uuid}")
            mapping = mappings[0]
        else:
            mapping = mappings[0]
        cell_id = mapping.get("cell_id")
        if not cell_id:
            result.blockers.append(f"cell mapping missing: {instance_uuid}")
        elif host_mapping is not None and cell_id != host_mapping.get("cell_id"):
            result.blockers.append(f"cell mapping mismatch: {instance_uuid}")

        request_specs = [
            row
            for row in rows["request_specs"]
            if row.get("instance_uuid") == instance_uuid
        ]
        request_spec = request_specs[0] if request_specs else None
        if not request_specs:
            result.blockers.append(f"request spec missing: {instance_uuid}")
        elif len(request_specs) > 1:
            result.blockers.append(f"request spec duplicate: {instance_uuid}")

        project_id = _field(server, "project_id", "project id") or db_instance.get("project_id")
        user_id = _field(server, "user_id", "user id") or db_instance.get("user_id")
        flavor_id = _reference_id(_field(server, "flavor", "flavor_id"))
        if flavor_id is None:
            db_flavor = db_instance.get("flavor_id", db_instance.get("instance_type_id"))
            flavor_id = str(db_flavor) if db_flavor not in (None, "") else None
        image_id = _reference_id(_field(server, "image", "image_id"))
        if image_id is None and db_instance.get("image_ref"):
            image_id = str(db_instance["image_ref"])

        volumes = []
        for row in rows["block_device_mapping"]:
            if (
                row.get("instance_uuid") != instance_uuid
                or not row.get("volume_id")
                or _is_deleted(row)
            ):
                continue
            volume_id = _canonical_uuid(row["volume_id"])
            if volume_id is None:
                result.blockers.append(
                    f"volume UUID invalid: {instance_uuid} got {row['volume_id']!r}"
                )
                continue
            volumes.append(volume_id)
        volumes = list(dict.fromkeys(volumes))
        info_caches = [
            row
            for row in rows["instance_info_caches"]
            if row.get("instance_uuid") == instance_uuid
        ]
        ports = []
        if not info_caches:
            result.blockers.append(f"instance info cache missing: {instance_uuid}")
        elif len(info_caches) > 1:
            result.blockers.append(f"instance info cache duplicate: {instance_uuid}")
        elif _is_deleted(info_caches[0]):
            result.blockers.append(f"instance info cache deleted: {instance_uuid}")

        active_caches = [cache for cache in info_caches if not _is_deleted(cache)]
        for cache in active_caches:
            cache_ports, invalid_ports, valid_shape = _network_port_ids(
                cache.get("network_info")
            )
            if not valid_shape:
                result.blockers.append(
                    f"instance info cache malformed: {instance_uuid}"
                )
                continue
            ports.extend(cache_ports)
            result.blockers.extend(
                f"port UUID invalid: {instance_uuid} got {value!r}"
                for value in invalid_ports
            )
        ports = list(dict.fromkeys(ports))

        facts = {
            "name": _field(server, "name") or _field(summary, "name"),
            "status": _field(server, "status") or _field(summary, "status"),
            "host": api_host,
            "project_id": project_id,
            "user_id": user_id,
            "flavor_id": flavor_id,
            "image_id": image_id,
            "port_ids": ports,
            "volume_ids": volumes,
        }
        instance_node = add_node(
            "instance",
            instance_uuid,
            facts,
            [server_evidence] if server_evidence else [],
        )
        add_edge(
            f"compute_host:{rehome_host}", instance_node.key, "hosts", True
        )

        if project_id:
            project = add_node("project", project_id, {"id": project_id})
            add_edge(instance_node.key, project.key, "owned_by_project", True)
        else:
            result.blockers.append(f"instance project missing: {instance_uuid}")
        if user_id:
            user = add_node("user", user_id, {"id": user_id})
            add_edge(instance_node.key, user.key, "owned_by_user", True)
        else:
            result.blockers.append(f"instance user missing: {instance_uuid}")

        if flavor_id:
            flavor = flavor_nodes.get(flavor_id)
            if flavor is None:
                flavor_payload, flavor_evidence = self._json(
                    ["flavor", "show", flavor_id, "-f", "json"],
                    f"nova-{self.side}-flavor-show-{flavor_id}",
                    result,
                )
                shown_flavor = _reference_id(_field(flavor_payload, "id"))
                if shown_flavor != flavor_id:
                    result.blockers.append(
                        f"flavor identity mismatch: expected {flavor_id} got {shown_flavor}"
                    )
                flavor_facts = {
                    field: deepcopy(_field(flavor_payload, field))
                    for field in _SAFE_FLAVOR_FIELDS
                    if _field(flavor_payload, field) is not None
                }
                flavor = add_node(
                    "flavor",
                    flavor_id,
                    flavor_facts,
                    [flavor_evidence] if flavor_evidence else [],
                )
                flavor_nodes[flavor_id] = flavor
            add_edge(instance_node.key, flavor.key, "uses_flavor", True)
        else:
            result.blockers.append(f"instance flavor missing: {instance_uuid}")

        if image_id:
            image = add_node("image_ref", image_id, {"id": image_id})
            add_edge(instance_node.key, image.key, "references_image", True)
        if cell_id:
            cell_facts = {"cell_id": cell_id, "host": rehome_host}
            if cell_mapping is not None and cell_mapping.get("id") == cell_id:
                cell_facts["database_schema"] = cell_mapping["schema"]
                if cell_mapping.get("uuid"):
                    cell_facts["uuid"] = cell_mapping["uuid"]
            cell = add_node(
                "cell_mapping",
                cell_id,
                cell_facts,
                [cell_mapping["evidence_id"]]
                if cell_mapping is not None and cell_mapping.get("evidence_id")
                else [],
            )
            add_edge(instance_node.key, cell.key, "mapped_to_cell", True)
        if request_spec is not None:
            request = add_node(
                "request_spec",
                instance_uuid,
                request_spec,
            )
            add_edge(instance_node.key, request.key, "has_request_spec", True)

        for port_id in ports:
            add_edge(instance_node.key, f"port:{port_id}", "uses_port", True)
        for volume_id in volumes:
            add_edge(instance_node.key, f"volume:{volume_id}", "uses_volume", True)

        allocation, allocation_evidence = self._json(
            [
                "resource", "provider", "allocation", "show", instance_uuid,
                "-f", "json",
            ],
            f"nova-{self.side}-placement-allocation-show-{instance_uuid}",
            result,
        )
        if placement_node is not None:
            allocation_map = (
                allocation.get("allocations")
                if isinstance(allocation, Mapping)
                and isinstance(allocation.get("allocations"), Mapping)
                else allocation
            )
            provider_allocation_found = (
                isinstance(allocation_map, Mapping)
                and placement_node.id in allocation_map
            ) or (
                isinstance(allocation_map, list)
                and any(
                    _field(item, "resource_provider", "resource_provider_uuid", "uuid")
                    == placement_node.id
                    for item in allocation_map
                )
            )
            if not provider_allocation_found:
                result.blockers.append(
                    f"placement allocation missing: {instance_uuid} provider "
                    f"{placement_node.id}"
                )
            placement_node.facts["consumer_allocations"][instance_uuid] = deepcopy(allocation)
            if allocation_evidence:
                placement_node.evidence_ids[:] = list(
                    dict.fromkeys([*placement_node.evidence_ids, allocation_evidence])
                )
            add_edge(
                instance_node.key,
                placement_node.key,
                "allocated_on",
                True,
            )
