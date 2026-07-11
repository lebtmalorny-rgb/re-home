from copy import deepcopy
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from .contract import CheckResult, CollectorResult, DependencyEdge, ResourceNode


CORE_TABLES = (
    "ports",
    "ipallocations",
    "networks",
    "subnets",
    "networksegments",
    "ml2_port_bindings",
    "ml2_distributed_port_bindings",
    "ml2_port_binding_levels",
    "securitygroups",
    "securitygrouprules",
    "securitygroupportbindings",
)

OPTIONAL_TABLE_FAMILIES = {
    "allowed_address_pairs": ["allowedaddresspairs"],
    "dns_dhcp": ["portdnses", "dnsnameservers", "extradhcpopts"],
    "qos": [
        "qos_port_policy_bindings",
        "qos_network_policy_bindings",
        "qos_fip_policy_bindings",
        "qos_policies",
    ],
    "trunk": ["trunks", "subports"],
    "l3": [
        "routers",
        "routerports",
        "routerroutes",
        "floatingips",
        "portforwardings",
    ],
    "address_groups": [
        "address_groups",
        "address_associations",
        "addressgrouprbacs",
    ],
}

PORT_FACT_FIELDS = (
    "id", "network_id", "mac_address", "device_id", "device_owner",
    "admin_state_up", "status", "port_security_enabled", "binding_host_id",
    "binding_vif_type", "binding_vnic_type", "security_group_ids",
)
NETWORK_FACT_FIELDS = (
    "id", "name", "status", "admin_state_up", "shared", "mtu",
    "port_security_enabled", "provider_network_type",
    "provider_physical_network", "provider_segmentation_id",
)
TABLE_FACT_FIELDS = {
    "ports": PORT_FACT_FIELDS,
    "networks": NETWORK_FACT_FIELDS,
    "subnets": (
        "id", "network_id", "cidr", "gateway_ip", "ip_version",
        "enable_dhcp", "subnetpool_id",
    ),
    "networksegments": (
        "id", "network_id", "network_type", "physical_network",
        "segmentation_id", "segment_index", "is_dynamic",
    ),
    "ml2_port_bindings": (
        "port_id", "host", "vif_type", "vnic_type", "status",
    ),
    "ml2_distributed_port_bindings": (
        "port_id", "host", "vif_type", "vnic_type", "status",
    ),
    "ml2_port_binding_levels": (
        "port_id", "host", "level", "driver", "segment_id",
    ),
    "securitygroups": ("id", "name", "project_id", "stateful"),
    "securitygrouprules": (
        "id", "security_group_id", "direction", "ethertype", "protocol",
        "port_range_min", "port_range_max", "remote_ip_prefix",
        "remote_group_id", "remote_address_group_id",
    ),
    "allowedaddresspairs": ("port_id", "mac_address", "ip_address"),
    "portdnses": ("port_id", "dns_name", "current_dns_name"),
    "dnsnameservers": ("subnet_id", "address", "order"),
    "extradhcpopts": ("port_id", "opt_name", "opt_value", "ip_version"),
    "qos_policies": ("id", "name", "project_id", "shared", "is_default"),
    "trunks": ("id", "port_id", "name", "project_id", "status"),
    "subports": (
        "trunk_id", "port_id", "segmentation_type", "segmentation_id",
    ),
    "routers": ("id", "name", "project_id", "status", "admin_state_up"),
    "routerroutes": ("router_id", "destination", "nexthop"),
    "floatingips": (
        "id", "fixed_port_id", "router_id", "floating_network_id",
        "floating_ip_address", "fixed_ip_address", "project_id", "status",
    ),
    "portforwardings": (
        "id", "floatingip_id", "internal_port_id", "internal_ip_address",
        "internal_port", "external_port", "protocol",
    ),
    "address_groups": ("id", "name", "project_id"),
    "address_associations": ("address_group_id", "address"),
    "addressgrouprbacs": (
        "id", "object_id", "target_project", "action", "project_id",
    ),
}


def _field(payload: object, *names: str) -> Any:
    if not isinstance(payload, Mapping):
        return None
    for name in names:
        if name in payload:
            return payload[name]
    normalized = {
        str(key).lower().replace("-", "_").replace(" ", "_"): value
        for key, value in payload.items()
    }
    for name in names:
        value = normalized.get(name.lower().replace("-", "_").replace(" ", "_"))
        if value is not None:
            return value
    return None


def _identifiers(value: object) -> List[str]:
    if isinstance(value, str):
        return [value] if value else []
    if not isinstance(value, (list, tuple, set)):
        return []
    values = []
    for item in value:
        if isinstance(item, Mapping):
            item = _field(item, "id", "uuid")
        if isinstance(item, str) and item:
            values.append(item)
    return list(dict.fromkeys(values))


def _row_id(row: Mapping[str, Any], *names: str) -> Optional[str]:
    value = _field(row, *names)
    return str(value) if value not in (None, "") else None


def _schema_table_names(schema: object) -> Set[str]:
    tables = getattr(schema, "tables", schema)
    if isinstance(tables, Mapping) and isinstance(tables.get("tables"), Mapping):
        tables = tables["tables"]
    if not isinstance(tables, Mapping):
        return set()
    names = set()
    for name in tables:
        text = str(name)
        if text.startswith("neutron."):
            names.add(text.removeprefix("neutron."))
        elif "." not in text:
            names.add(text)
    return names


def _dedupe(values: Iterable[str]) -> List[str]:
    return list(dict.fromkeys(value for value in values if value))


def _allowlisted(payload: Mapping[str, Any], fields: Sequence[str]) -> Dict[str, Any]:
    facts = {}
    normalized = {
        str(key).lower().replace("-", "_").replace(" ", "_"): value
        for key, value in payload.items()
    }
    for field in fields:
        if field in payload:
            facts[field] = deepcopy(payload[field])
        elif field in normalized:
            facts[field] = deepcopy(normalized[field])
    return facts


def _table_facts(table: str, row: Mapping[str, Any]) -> Dict[str, Any]:
    return _allowlisted(row, TABLE_FACT_FIELDS.get(table, ()))


class NeutronCollector:
    def __init__(self, client, side: str, schema) -> None:
        self.client = client
        self.side = side
        self.schema = schema
        self.available_tables = _schema_table_names(schema)

    def collect(self, port_ids: Sequence[str]) -> CollectorResult:
        result = CollectorResult(service="neutron", side=self.side)
        selected_ports = _dedupe(
            str(value) for value in port_ids if isinstance(value, str) and value
        )
        if not selected_ports:
            result.blockers.append("Neutron port roots missing")
            return result

        rows, selected_ports = self._acquire_rows(selected_ports, result)

        nodes: Dict[str, ResourceNode] = {}
        edge_keys: Set[Tuple[str, str, str, bool]] = set()

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
                _dedupe(evidence_ids or []),
            )
            existing = nodes.get(node.key)
            if existing is None:
                nodes[node.key] = node
                result.nodes.append(node)
                return node
            existing.facts.update(node.facts)
            existing.evidence_ids[:] = _dedupe(
                [*existing.evidence_ids, *node.evidence_ids]
            )
            return existing

        def add_edge(
            source: str, target: str, relation: str, required: bool = True
        ) -> None:
            key = (source, target, relation, required)
            if key not in edge_keys:
                edge_keys.add(key)
                result.edges.append(DependencyEdge(source, target, relation, required))

        port_rows = [
            row for row in rows["ports"]
            if _row_id(row, "id", "port_id") in selected_ports
        ]
        by_port: Dict[str, List[Mapping[str, Any]]] = {
            port_id: [
                row for row in port_rows
                if _row_id(row, "id", "port_id") == port_id
            ]
            for port_id in selected_ports
        }
        network_ids: List[str] = []
        security_group_ids: List[str] = []
        api_security_groups_by_port: Dict[str, Set[str]] = {}

        for port_id in selected_ports:
            payload, evidence_id = self._api(
                ["port", "show", port_id, "-f", "json"],
                f"neutron-{self.side}-port-show-{port_id}",
                result,
            )
            api = payload if isinstance(payload, Mapping) else {}
            api_id = _row_id(api, "id")
            if api_id != port_id:
                result.blockers.append(f"port API UUID mismatch: {port_id}")
            matching_rows = by_port[port_id]
            if len(matching_rows) != 1:
                qualifier = "missing" if not matching_rows else "duplicate"
                result.blockers.append(f"Neutron DB port {qualifier}: {port_id}")
            db_port = matching_rows[0] if matching_rows else {}
            for field in ("network_id", "mac_address", "device_id", "device_owner"):
                api_value = _field(api, field)
                db_value = _field(db_port, field)
                if (
                    api_value not in (None, "")
                    and db_value not in (None, "")
                    and api_value != db_value
                ):
                    reason = (
                        f"port API/DB network mismatch: {port_id}"
                        if field == "network_id"
                        else f"port API/DB {field} mismatch: {port_id}"
                    )
                    result.blockers.append(reason)
            facts = _table_facts("ports", db_port)
            facts.update(_allowlisted(api, PORT_FACT_FIELDS))
            if "security_group_ids" in facts:
                facts["security_group_ids"] = _identifiers(
                    facts["security_group_ids"]
                )
            facts["api_id"] = api_id
            node = add_node("port", port_id, facts, [evidence_id] if evidence_id else [])
            assert node is not None
            network_id = _row_id(api, "network_id") or _row_id(facts, "network_id")
            if network_id:
                network_ids.append(network_id)
                add_edge(node.key, f"network:{network_id}", "uses_network")
            else:
                result.blockers.append(f"network UUID missing for port {port_id}")
            api_security_groups = set(
                _identifiers(
                    _field(api, "security_group_ids", "security_groups")
                )
            )
            api_security_groups_by_port[port_id] = api_security_groups
            security_group_ids.extend(api_security_groups)

        selected_port_set = set(selected_ports)
        ip_rows = [
            row for row in rows["ipallocations"]
            if _row_id(row, "port_id") in selected_port_set
        ]
        network_ids.extend(
            value for row in ip_rows
            if (value := _row_id(row, "network_id")) is not None
        )
        network_ids = _dedupe(network_ids)

        network_rows = [
            row for row in rows["networks"] if _row_id(row, "id") in network_ids
        ]
        for network_id in network_ids:
            payload, evidence_id = self._api(
                ["network", "show", network_id, "-f", "json"],
                f"neutron-{self.side}-network-show-{network_id}",
                result,
            )
            api = payload if isinstance(payload, Mapping) else {}
            matches = [row for row in network_rows if _row_id(row, "id") == network_id]
            if len(matches) != 1:
                qualifier = "missing" if not matches else "duplicate"
                result.blockers.append(f"Neutron DB network {qualifier}: {network_id}")
            facts = _table_facts("networks", matches[0]) if matches else {}
            facts.update(_allowlisted(api, NETWORK_FACT_FIELDS))
            facts["api_id"] = _row_id(api, "id")
            if facts["api_id"] != network_id:
                result.blockers.append(f"network API UUID mismatch: {network_id}")
            add_node(
                "network", network_id, facts,
                [evidence_id] if evidence_id else [],
            )

        subnet_ids = _dedupe(
            value for row in ip_rows
            if (value := _row_id(row, "subnet_id")) is not None
        )
        subnet_rows = [
            row for row in rows["subnets"]
            if _row_id(row, "id") in subnet_ids
            or _row_id(row, "network_id") in network_ids
        ]
        subnet_ids = _dedupe(
            [*subnet_ids, *(
                value for row in subnet_rows
                if (value := _row_id(row, "id")) is not None
            )]
        )
        for row in subnet_rows:
            subnet_id = _row_id(row, "id")
            subnet = add_node("subnet", subnet_id, _table_facts("subnets", row))
            if subnet is not None:
                network_id = _row_id(row, "network_id")
                if network_id:
                    add_edge(subnet.key, f"network:{network_id}", "belongs_to_network")
        for row in ip_rows:
            port_id = _row_id(row, "port_id")
            subnet_id = _row_id(row, "subnet_id")
            if port_id and subnet_id:
                add_edge(f"port:{port_id}", f"subnet:{subnet_id}", "has_fixed_ip")

        segment_rows = [
            row for row in rows["networksegments"]
            if _row_id(row, "network_id") in network_ids
        ]
        segment_ids = set()
        for row in segment_rows:
            segment_id = _row_id(row, "id", "segment_id")
            segment = add_node(
                "segment", segment_id, _table_facts("networksegments", row)
            )
            if segment is not None:
                segment_ids.add(segment.id)
                if _segment_signature(segment) is None:
                    result.blockers.append(
                        f"segment tuple invalid: {segment.id}"
                    )
                network_id = _row_id(row, "network_id")
                if network_id:
                    add_edge(f"network:{network_id}", segment.key, "has_segment")

        bindings_by_port: Dict[str, int] = {
            port_id: 0 for port_id in selected_ports
        }
        for table in ("ml2_port_bindings", "ml2_distributed_port_bindings"):
            for row in rows[table]:
                port_id = _row_id(row, "port_id")
                if port_id not in selected_port_set:
                    continue
                host = _row_id(row, "host") or "unbound"
                binding_id = f"{port_id}:{host}"
                binding = add_node(
                    "ml2_binding", binding_id,
                    {
                        **_table_facts(table, row),
                        "distributed": table.startswith("ml2_distributed"),
                    },
                )
                if binding is not None:
                    bindings_by_port[port_id] += 1
                    add_edge(f"port:{port_id}", binding.key, "has_ml2_binding")
                    if host != "unbound":
                        agent = add_node("network_agent", host, {"host": host})
                        if agent is not None:
                            add_edge(binding.key, agent.key, "scheduled_to_agent")
        for port_id, count in bindings_by_port.items():
            if count == 0:
                result.blockers.append(f"ML2 binding missing for port {port_id}")

        levels_by_port: Dict[str, int] = {port_id: 0 for port_id in selected_ports}
        for row in rows["ml2_port_binding_levels"]:
            port_id = _row_id(row, "port_id")
            if port_id not in selected_port_set:
                continue
            host = _row_id(row, "host") or "unbound"
            level = _field(row, "level")
            level_text = str(level) if level is not None else "unknown"
            binding_level = add_node(
                "binding_level", f"{port_id}:{host}:{level_text}",
                _table_facts("ml2_port_binding_levels", row),
            )
            if binding_level is None:
                continue
            levels_by_port[port_id] += 1
            add_edge(f"port:{port_id}", binding_level.key, "has_binding_level")
            segment_id = _row_id(row, "segment_id")
            if segment_id in segment_ids:
                add_edge(binding_level.key, f"segment:{segment_id}", "uses_segment")
            else:
                result.blockers.append(f"binding level segment missing for port {port_id}")
        for port_id, count in levels_by_port.items():
            if count == 0:
                result.blockers.append(f"binding level missing for port {port_id}")

        sg_binding_rows = [
            row for row in rows["securitygroupportbindings"]
            if _row_id(row, "port_id") in selected_port_set
        ]
        security_group_ids.extend(
            value for row in sg_binding_rows
            if (value := _row_id(row, "security_group_id")) is not None
        )
        security_group_ids = _dedupe(security_group_ids)
        db_security_groups_by_port = {
            port_id: {
                security_group_id
                for row in sg_binding_rows
                if _row_id(row, "port_id") == port_id
                and (security_group_id := _row_id(
                    row, "security_group_id"
                )) is not None
            }
            for port_id in selected_ports
        }
        for port_id in selected_ports:
            api_groups = api_security_groups_by_port.get(port_id, set())
            db_groups = db_security_groups_by_port[port_id]
            if api_groups and api_groups != db_groups:
                result.blockers.append(
                    f"security group API/DB binding mismatch: {port_id}"
                )
            for security_group_id in sorted(api_groups | db_groups):
                add_edge(
                    f"port:{port_id}",
                    f"security_group:{security_group_id}",
                    "uses_security_group",
                )
        rule_rows = [
            row for row in rows["securitygrouprules"]
            if _row_id(row, "security_group_id") in security_group_ids
        ]
        for row in rows["securitygroups"]:
            security_group_id = _row_id(row, "id")
            if security_group_id not in security_group_ids:
                continue
            facts = _table_facts("securitygroups", row)
            facts["rules"] = [
                _table_facts("securitygrouprules", rule) for rule in rule_rows
                if _row_id(rule, "security_group_id") == security_group_id
            ]
            add_node("security_group", security_group_id, facts)
        for row in sg_binding_rows:
            port_id = _row_id(row, "port_id")
            security_group_id = _row_id(row, "security_group_id")
            if port_id and security_group_id:
                add_edge(
                    f"port:{port_id}", f"security_group:{security_group_id}",
                    "uses_security_group",
                )

        self._expand_optional(
            result,
            rows,
            selected_port_set,
            set(network_ids),
            set(subnet_ids),
            rule_rows,
            add_node,
            add_edge,
        )
        self._validate_required_edges(result)
        return result

    def _acquire_rows(
        self,
        initial_port_ids: Sequence[str],
        result: CollectorResult,
    ) -> Tuple[Dict[str, List[Mapping[str, Any]]], List[str]]:
        all_tables = {
            *CORE_TABLES,
            *(
                table
                for family in OPTIONAL_TABLE_FAMILIES.values()
                for table in family
            ),
        }
        rows: Dict[str, List[Mapping[str, Any]]] = {
            table: [] for table in all_tables
        }
        for table in CORE_TABLES:
            if table not in self.available_tables:
                result.blockers.append(f"required Neutron table missing: {table}")

        completed_queries: Set[Tuple[str, Tuple[Tuple[str, Tuple[str, ...]], ...]]] = set()

        def fetch(table: str, filters: Mapping[str, Sequence[str]]) -> None:
            normalized = {
                column: _dedupe(str(value) for value in values if value not in (None, ""))
                for column, values in filters.items()
            }
            normalized = {
                column: values for column, values in normalized.items() if values
            }
            if table not in self.available_tables or not normalized:
                return
            query_key = (
                table,
                tuple(
                    (column, tuple(values))
                    for column, values in sorted(normalized.items())
                ),
            )
            if query_key in completed_queries:
                return
            completed_queries.add(query_key)
            for row in self._db_rows(table, normalized, result):
                if row not in rows[table]:
                    rows[table].append(row)

        active_ports = list(initial_port_ids)
        while True:
            fetch("trunks", {"port_id": active_ports})
            trunk_ids = _dedupe(
                trunk_id
                for row in rows["trunks"]
                if _row_id(row, "port_id") in active_ports
                and (trunk_id := _row_id(row, "id")) is not None
            )
            fetch("subports", {"trunk_id": trunk_ids})
            child_ports = _dedupe(
                child_port
                for row in rows["subports"]
                if _row_id(row, "trunk_id") in trunk_ids
                and (child_port := _row_id(row, "port_id")) is not None
            )
            expanded = _dedupe([*active_ports, *child_ports])
            if expanded == active_ports:
                break
            active_ports = expanded

        for table, filters in (
            ("ports", {"id": active_ports}),
            ("ipallocations", {"port_id": active_ports}),
            ("ml2_port_bindings", {"port_id": active_ports}),
            ("ml2_distributed_port_bindings", {"port_id": active_ports}),
            ("ml2_port_binding_levels", {"port_id": active_ports}),
            ("securitygroupportbindings", {"port_id": active_ports}),
            ("allowedaddresspairs", {"port_id": active_ports}),
            ("portdnses", {"port_id": active_ports}),
            ("extradhcpopts", {"port_id": active_ports}),
            ("qos_port_policy_bindings", {"port_id": active_ports}),
            ("routerports", {"port_id": active_ports}),
            ("portforwardings", {"internal_port_id": active_ports}),
        ):
            fetch(table, filters)

        network_ids = _dedupe(
            network_id
            for table in ("ports", "ipallocations")
            for row in rows[table]
            if (network_id := _row_id(row, "network_id")) is not None
        )
        subnet_ids = _dedupe(
            subnet_id
            for row in rows["ipallocations"]
            if (subnet_id := _row_id(row, "subnet_id")) is not None
        )
        for table, filters in (
            ("networks", {"id": network_ids}),
            ("subnets", {"id": subnet_ids}),
            ("networksegments", {"network_id": network_ids}),
            ("dnsnameservers", {"subnet_id": subnet_ids}),
            ("qos_network_policy_bindings", {"network_id": network_ids}),
        ):
            fetch(table, filters)

        security_group_ids = _dedupe(
            security_group_id
            for row in rows["securitygroupportbindings"]
            if (security_group_id := _row_id(row, "security_group_id")) is not None
        )
        fetch("securitygroups", {"id": security_group_ids})
        fetch("securitygrouprules", {"security_group_id": security_group_ids})

        floating_ip_ids = _dedupe(
            floating_ip_id
            for row in rows["portforwardings"]
            if (floating_ip_id := _row_id(
                row, "floatingip_id", "floating_ip_id"
            )) is not None
        )
        fetch(
            "floatingips",
            {"fixed_port_id": active_ports, "id": floating_ip_ids},
        )
        floating_ip_ids = _dedupe(
            [
                *floating_ip_ids,
                *(
                    floating_ip_id
                    for row in rows["floatingips"]
                    if (floating_ip_id := _row_id(row, "id")) is not None
                ),
            ]
        )
        fetch("qos_fip_policy_bindings", {"fip_id": floating_ip_ids})

        router_ids = _dedupe(
            router_id
            for table in ("routerports", "floatingips")
            for row in rows[table]
            if (router_id := _row_id(row, "router_id")) is not None
        )
        fetch("routers", {"id": router_ids})
        fetch("routerroutes", {"router_id": router_ids})

        qos_policy_ids = _dedupe(
            policy_id
            for table in (
                "qos_port_policy_bindings",
                "qos_network_policy_bindings",
                "qos_fip_policy_bindings",
            )
            for row in rows[table]
            if (policy_id := _row_id(row, "policy_id")) is not None
        )
        fetch("qos_policies", {"id": qos_policy_ids})

        address_group_ids = _dedupe(
            address_group_id
            for row in rows["securitygrouprules"]
            if (address_group_id := _row_id(
                row, "remote_address_group_id", "address_group_id"
            )) is not None
        )
        fetch("address_groups", {"id": address_group_ids})
        fetch("address_associations", {"address_group_id": address_group_ids})
        fetch("addressgrouprbacs", {"object_id": address_group_ids})
        return rows, active_ports

    @staticmethod
    def _validate_required_edges(result: CollectorResult) -> None:
        node_keys = {node.key for node in result.nodes}
        for edge in result.edges:
            if not edge.required:
                continue
            for key, label in ((edge.source, "source"), (edge.target, "node")):
                if key in node_keys:
                    continue
                reason = (
                    f"required dependency {label} missing: {key}"
                    if label == "source"
                    else f"required dependency node missing: {key}"
                )
                if reason not in result.blockers:
                    result.blockers.append(reason)

    def _db_rows(
        self,
        table: str,
        filters: Mapping[str, Sequence[str]],
        result: CollectorResult,
    ) -> List[Mapping[str, Any]]:
        source = getattr(self.client, "db_records", None)
        try:
            records = (
                source(table, deepcopy(dict(filters)))
                if callable(source)
                else None
            )
        except Exception:
            result.blockers.append(f"DB probe failed: neutron.{table}")
            return []
        evidence = None
        if isinstance(records, tuple) and len(records) == 2:
            records, evidence = records
        if not isinstance(records, list):
            result.blockers.append(f"DB facts missing or invalid: neutron.{table}")
            return []
        if callable(source):
            expected_evidence = {
                "evidence_id": f"{self.side}-db:neutron.{table}",
                "schema": "neutron",
                "table": table,
                "filters": deepcopy(dict(filters)),
            }
            if evidence != expected_evidence:
                result.blockers.append(f"DB evidence invalid: {table}")
            else:
                result.evidence.append(
                    {
                        "evidence_id": expected_evidence["evidence_id"],
                        "kind": "db-jsonl",
                        "schema": "neutron",
                        "table": table,
                        "filters": deepcopy(dict(filters)),
                    }
                )
        rows = []
        for index, record in enumerate(records):
            if not isinstance(record, Mapping):
                result.blockers.append(f"DB JSONL record invalid: {table}[{index}]")
                continue
            if (
                set(record) != {"_schema", "_table", "row"}
                or record.get("_schema") != "neutron"
                or record.get("_table") != table
                or not isinstance(record.get("row"), Mapping)
            ):
                result.blockers.append(f"DB JSONL record invalid: {table}[{index}]")
                continue
            row = record["row"]
            if not any(
                row.get(column) in values for column, values in filters.items()
            ):
                result.blockers.append(f"DB row outside filter: {table}[{index}]")
                continue
            rows.append(deepcopy(dict(row)))
        return rows

    def _api(
        self,
        command: Sequence[str],
        evidence_id: str,
        result: CollectorResult,
    ) -> Tuple[object, Optional[str]]:
        try:
            payload, evidence = self.client.json(command, evidence_id)
        except Exception:
            result.blockers.append(f"OpenStack API probe failed: {evidence_id}")
            return {}, None
        if not isinstance(payload, Mapping):
            result.blockers.append(f"OpenStack API payload invalid: {evidence_id}")
            return {}, None
        evidence_value = _field(evidence, "evidence_id", "id")
        if evidence_value != evidence_id:
            result.blockers.append(f"OpenStack API evidence invalid: {evidence_id}")
            return payload, None
        result.evidence.append(
            {
                "evidence_id": evidence_id,
                "kind": "openstack-json",
                "command": list(command),
            }
        )
        return payload, evidence_id

    def _expand_optional(
        self,
        result: CollectorResult,
        rows: Mapping[str, List[Mapping[str, Any]]],
        port_ids: Set[str],
        network_ids: Set[str],
        subnet_ids: Set[str],
        security_group_rules: Sequence[Mapping[str, Any]],
        add_node,
        add_edge,
    ) -> None:
        for row in rows.get("allowedaddresspairs", []):
            port_id = _row_id(row, "port_id")
            if port_id in port_ids:
                port = add_node("port", port_id)
                assert port is not None
                port.facts.setdefault("allowed_address_pairs", []).append(
                    _table_facts("allowedaddresspairs", row)
                )

        for table, owner_field, owner_ids, fact_name in (
            ("portdnses", "port_id", port_ids, "dns"),
            ("extradhcpopts", "port_id", port_ids, "extra_dhcp_options"),
            ("dnsnameservers", "subnet_id", subnet_ids, "dns_nameservers"),
        ):
            kind = "port" if owner_field == "port_id" else "subnet"
            for row in rows.get(table, []):
                owner_id = _row_id(row, owner_field)
                if owner_id in owner_ids:
                    owner = add_node(kind, owner_id)
                    assert owner is not None
                    owner.facts.setdefault(fact_name, []).append(
                        _table_facts(table, row)
                    )

        relevant_fips = {
            floating_ip_id
            for row in rows.get("floatingips", [])
            if _row_id(row, "fixed_port_id", "port_id") in port_ids
            and (floating_ip_id := _row_id(row, "id")) is not None
        }
        relevant_fips.update(
            floating_ip_id
            for row in rows.get("portforwardings", [])
            if _row_id(row, "internal_port_id") in port_ids
            and (floating_ip_id := _row_id(
                row, "floatingip_id", "floating_ip_id"
            )) is not None
        )

        qos_policy_ids = set()
        for table, owner_field, owner_ids, owner_kind in (
            ("qos_port_policy_bindings", "port_id", port_ids, "port"),
            ("qos_network_policy_bindings", "network_id", network_ids, "network"),
            ("qos_fip_policy_bindings", "fip_id", relevant_fips, "floating_ip"),
        ):
            for row in rows.get(table, []):
                owner_id = _row_id(row, owner_field)
                policy_id = _row_id(row, "policy_id")
                if owner_id in owner_ids and policy_id:
                    qos_policy_ids.add(policy_id)
                    add_edge(
                        f"{owner_kind}:{owner_id}", f"qos_policy:{policy_id}",
                        "uses_qos_policy",
                    )
        for row in rows.get("qos_policies", []):
            policy_id = _row_id(row, "id")
            if policy_id in qos_policy_ids:
                add_node(
                    "qos_policy", policy_id, _table_facts("qos_policies", row)
                )

        relevant_trunks = set()
        for row in rows.get("trunks", []):
            trunk_id = _row_id(row, "id")
            parent_port = _row_id(row, "port_id")
            if trunk_id and parent_port in port_ids:
                relevant_trunks.add(trunk_id)
                add_node("trunk", trunk_id, _table_facts("trunks", row))
                add_edge(f"port:{parent_port}", f"trunk:{trunk_id}", "is_trunk_parent")
        for row in rows.get("subports", []):
            trunk_id = _row_id(row, "trunk_id")
            port_id = _row_id(row, "port_id")
            if port_id in port_ids and trunk_id:
                relevant_trunks.add(trunk_id)
        for row in rows.get("trunks", []):
            trunk_id = _row_id(row, "id")
            if trunk_id in relevant_trunks:
                add_node("trunk", trunk_id, _table_facts("trunks", row))
        for row in rows.get("subports", []):
            trunk_id = _row_id(row, "trunk_id")
            port_id = _row_id(row, "port_id")
            if trunk_id in relevant_trunks and port_id in port_ids:
                add_edge(f"port:{port_id}", f"trunk:{trunk_id}", "is_trunk_subport")

        router_ids = set()
        for row in rows.get("routerports", []):
            port_id = _row_id(row, "port_id")
            router_id = _row_id(row, "router_id")
            if port_id in port_ids and router_id:
                router_ids.add(router_id)
                add_edge(f"port:{port_id}", f"router:{router_id}", "attached_to_router")
        floating_ip_rows = {
            floating_ip_id: row
            for row in rows.get("floatingips", [])
            if (floating_ip_id := _row_id(row, "id")) is not None
        }
        for row in rows.get("floatingips", []):
            port_id = _row_id(row, "fixed_port_id", "port_id")
            floating_ip_id = _row_id(row, "id")
            if floating_ip_id in relevant_fips:
                router_id = _row_id(row, "router_id")
                if router_id:
                    router_ids.add(router_id)
                add_node(
                    "floating_ip", floating_ip_id,
                    _table_facts("floatingips", row),
                )
                if port_id in port_ids:
                    add_edge(
                        f"port:{port_id}", f"floating_ip:{floating_ip_id}",
                        "has_floating_ip",
                    )
        for row in rows.get("portforwardings", []):
            port_id = _row_id(row, "internal_port_id")
            floating_ip_id = _row_id(row, "floatingip_id", "floating_ip_id")
            if port_id in port_ids and floating_ip_id:
                relevant_fips.add(floating_ip_id)
                floating_ip = None
                if floating_ip_id in floating_ip_rows:
                    floating_ip = add_node(
                        "floating_ip", floating_ip_id,
                        _table_facts(
                            "floatingips", floating_ip_rows[floating_ip_id]
                        ),
                    )
                    assert floating_ip is not None
                    floating_ip.facts.setdefault("port_forwardings", []).append(
                        _table_facts("portforwardings", row)
                    )
                else:
                    result.blockers.append(
                        f"floating IP row missing: {floating_ip_id}"
                    )
                add_edge(
                    f"port:{port_id}", f"floating_ip:{floating_ip_id}",
                    "has_port_forwarding",
                )
        router_row_ids = {
            router_id
            for row in rows.get("routers", [])
            if (router_id := _row_id(row, "id")) is not None
        }
        for row in rows.get("routers", []):
            router_id = _row_id(row, "id")
            if router_id in router_ids:
                add_node("router", router_id, _table_facts("routers", row))
        for row in rows.get("routerroutes", []):
            router_id = _row_id(row, "router_id")
            if router_id in router_ids and router_id in router_row_ids:
                router = add_node("router", router_id)
                assert router is not None
                router.facts.setdefault("routes", []).append(
                    _table_facts("routerroutes", row)
                )
        address_group_ids = {
            address_group_id
            for rule in security_group_rules
            if (address_group_id := _row_id(
                rule, "remote_address_group_id", "address_group_id"
            )) is not None
        }
        for rule in security_group_rules:
            security_group_id = _row_id(rule, "security_group_id")
            address_group_id = _row_id(
                rule, "remote_address_group_id", "address_group_id"
            )
            if security_group_id and address_group_id:
                add_edge(
                    f"security_group:{security_group_id}",
                    f"address_group:{address_group_id}",
                    "uses_address_group",
                )
        for row in rows.get("address_groups", []):
            address_group_id = _row_id(row, "id")
            if address_group_id in address_group_ids:
                facts = _table_facts("address_groups", row)
                facts["addresses"] = [
                    _table_facts("address_associations", association)
                    for association in rows.get("address_associations", [])
                    if _row_id(association, "address_group_id") == address_group_id
                ]
                facts["rbac_entries"] = [
                    _table_facts("addressgrouprbacs", rbac)
                    for rbac in rows.get("addressgrouprbacs", [])
                    if _row_id(rbac, "object_id", "address_group_id")
                    == address_group_id
                ]
                add_node("address_group", address_group_id, facts)


def _node_map(result: CollectorResult, kind: str) -> Dict[str, ResourceNode]:
    return {node.id: node for node in result.nodes if node.kind == kind}


def _port_network(result: CollectorResult, port_id: str) -> Optional[str]:
    prefix = "network:"
    for edge in result.edges:
        if (
            edge.source == f"port:{port_id}"
            and edge.relation == "uses_network"
            and edge.target.startswith(prefix)
        ):
            return edge.target.removeprefix(prefix)
    port = _node_map(result, "port").get(port_id)
    return _row_id(port.facts, "network_id") if port else None


def _port_segments(result: CollectorResult, port_id: str) -> List[ResourceNode]:
    level_keys = {
        edge.target for edge in result.edges
        if edge.source == f"port:{port_id}" and edge.relation == "has_binding_level"
    }
    segment_keys = {
        edge.target for edge in result.edges
        if edge.source in level_keys and edge.relation == "uses_segment"
    }
    segments = _node_map(result, "segment")
    return [
        segments[key.removeprefix("segment:")]
        for key in sorted(segment_keys)
        if key.startswith("segment:") and key.removeprefix("segment:") in segments
    ]


def _segment_signature(
    node: ResourceNode,
) -> Optional[Tuple[str, Optional[str], Optional[int]]]:
    network_type = _field(node.facts, "network_type")
    physical_network = _field(node.facts, "physical_network")
    segmentation_id = _field(node.facts, "segmentation_id")
    if not isinstance(network_type, str) or not network_type:
        return None
    if physical_network is not None and (
        not isinstance(physical_network, str) or not physical_network
    ):
        return None
    if segmentation_id is not None and (
        not isinstance(segmentation_id, int)
        or isinstance(segmentation_id, bool)
        or segmentation_id <= 0
    ):
        return None

    if network_type == "flat":
        valid = isinstance(physical_network, str) and segmentation_id is None
    elif network_type == "vlan":
        valid = (
            isinstance(physical_network, str)
            and isinstance(segmentation_id, int)
            and segmentation_id <= 4094
        )
    elif network_type in {"vxlan", "geneve"}:
        valid = (
            physical_network is None
            and isinstance(segmentation_id, int)
            and segmentation_id <= 16777215
        )
    elif network_type == "gre":
        valid = (
            physical_network is None
            and isinstance(segmentation_id, int)
            and segmentation_id <= 4294967295
        )
    elif network_type == "local":
        valid = physical_network is None and segmentation_id is None
    else:
        valid = False
    if not valid:
        return None
    return network_type, physical_network, segmentation_id


def _runtime_nodes_for_port(
    runtime: CollectorResult, kind: str, port_id: str
) -> List[ResourceNode]:
    keys = {
        edge.source for edge in runtime.edges
        if edge.target == f"port:{port_id}" and edge.relation == "maps_to_port"
    }
    return [node for node in runtime.nodes if node.kind == kind and node.key in keys]


def compare_neutron_results(
    source: CollectorResult,
    target: CollectorResult,
    source_runtime: CollectorResult,
    target_runtime: CollectorResult,
    network_backend: str,
) -> CollectorResult:
    result = CollectorResult(service="neutron-readiness", side="target")
    source_ports = _node_map(source, "port")
    target_ports = _node_map(target, "port")
    target_networks = _node_map(target, "network")
    target_segments = list(_node_map(target, "segment").values())

    def check(
        check_id: str,
        status: str,
        reason: str,
        resource_ids: Optional[Iterable[str]] = None,
    ) -> None:
        result.checks.append(
            CheckResult(check_id, status, reason, list(resource_ids or []))
        )
        if status == "BLOCKED" and reason not in result.blockers:
            result.blockers.append(reason)
        if status == "UNKNOWN" and reason not in result.unknowns:
            result.unknowns.append(reason)

    for blocker in [
        *source.blockers,
        *target.blockers,
        *source_runtime.blockers,
        *target_runtime.blockers,
    ]:
        if blocker not in result.blockers:
            result.blockers.append(blocker)
    for unknown in [
        *source.unknowns,
        *target.unknowns,
        *source_runtime.unknowns,
        *target_runtime.unknowns,
    ]:
        if unknown not in result.unknowns:
            result.unknowns.append(unknown)

    for port_id, source_port in source_ports.items():
        target_port = target_ports.get(port_id)
        target_api_id = target_port.facts.get("api_id") if target_port else None
        if target_port is None:
            check(
                f"neutron.port.{port_id}", "BLOCKED",
                f"target port missing: {port_id}", [source_port.key],
            )
            continue
        if target_api_id != port_id:
            check(
                f"neutron.port.{port_id}", "BLOCKED",
                f"target port UUID mismatch: {port_id}",
                [source_port.key, target_port.key],
            )
        else:
            check(
                f"neutron.port.{port_id}", "PASS",
                f"target port UUID matches: {port_id}", [source_port.key],
            )

        network_id = _port_network(source, port_id)
        target_port_network = _row_id(target_port.facts, "network_id")
        if network_id and target_port_network != network_id:
            check(
                f"neutron.port-network.{port_id}", "BLOCKED",
                f"target port network mismatch for port {port_id}",
                [source_port.key, target_port.key],
            )
        target_network = target_networks.get(network_id or "")
        if not network_id or target_network is None:
            check(
                f"neutron.network.{port_id}", "BLOCKED",
                f"target network missing for port {port_id}",
                [source_port.key],
            )
        elif target_network.facts.get("api_id") != network_id:
            check(
                f"neutron.network.{port_id}", "BLOCKED",
                f"target network UUID mismatch for port {port_id}",
                [source_port.key, target_network.key],
            )
        else:
            check(
                f"neutron.network.{port_id}", "PASS",
                f"target network UUID matches for port {port_id}",
                [source_port.key, target_network.key],
            )

        source_segments = _port_segments(source, port_id)
        source_signature_list = [
            _segment_signature(segment) for segment in source_segments
        ]
        signatures = {
            signature for signature in source_signature_list
            if signature is not None
        }
        matches_by_signature = {
            signature: [
                segment for segment in target_segments
                if _row_id(segment.facts, "network_id") == network_id
                and _segment_signature(segment) == signature
            ]
            for signature in signatures
        }
        segment_matches = [
            segment
            for matches in matches_by_signature.values()
            for segment in matches
        ]
        if not source_segments:
            check(
                f"neutron.segment.{port_id}", "UNKNOWN",
                f"source segment unknown for port {port_id}", [source_port.key],
            )
        elif any(signature is None for signature in source_signature_list):
            check(
                f"neutron.segment.{port_id}", "BLOCKED",
                f"source segment tuple invalid for port {port_id}",
                [source_port.key, *(node.key for node in source_segments)],
            )
        elif len(signatures) != len(source_signature_list):
            check(
                f"neutron.segment.{port_id}", "BLOCKED",
                f"source segment ambiguous for port {port_id}",
                [source_port.key, *(node.key for node in source_segments)],
            )
        elif any(not matches for matches in matches_by_signature.values()):
            check(
                f"neutron.segment.{port_id}", "BLOCKED",
                f"target segment missing for port {port_id}", [source_port.key],
            )
        elif any(len(matches) != 1 for matches in matches_by_signature.values()):
            check(
                f"neutron.segment.{port_id}", "BLOCKED",
                f"target segment ambiguous for port {port_id}",
                [source_port.key, *(node.key for node in segment_matches)],
            )
        else:
            check(
                f"neutron.segment.{port_id}", "PASS",
                f"unique target segment matches for port {port_id}",
                [source_port.key, *(node.key for node in segment_matches)],
            )

        if network_backend == "ovs":
            _compare_ovs_port(
                port_id, source_runtime, target_runtime, check
            )
        elif network_backend == "ovn":
            _compare_ovn_port(
                port_id, source_runtime, target_runtime, check
            )
        else:
            check(
                f"neutron.backend.{port_id}", "UNKNOWN",
                f"unsupported network backend: {network_backend}",
                [source_port.key],
            )
    return result


def _compare_ovs_port(port_id, source_runtime, target_runtime, check) -> None:
    source_ports = _runtime_nodes_for_port(source_runtime, "ovs_port", port_id)
    target_ports = _runtime_nodes_for_port(target_runtime, "ovs_port", port_id)
    source_interfaces = _runtime_nodes_for_port(
        source_runtime, "runtime_interface", port_id
    )
    target_interfaces = _runtime_nodes_for_port(
        target_runtime, "runtime_interface", port_id
    )
    if not source_ports:
        check(
            f"neutron.ovs-source-port.{port_id}", "UNKNOWN",
            f"source OVS port evidence missing for port {port_id}",
            [f"port:{port_id}"],
        )
        return
    if not target_ports:
        check(
            f"neutron.ovs-port.{port_id}", "BLOCKED",
            f"target OVS port missing for port {port_id}", [f"port:{port_id}"],
        )
        return
    if not source_interfaces or not target_interfaces:
        check(
            f"neutron.ovs-bridge.{port_id}", "UNKNOWN",
            f"OVS bridge evidence missing for port {port_id}", [f"port:{port_id}"],
        )
        return

    def pairs(
        ports: Sequence[ResourceNode], interfaces: Sequence[ResourceNode]
    ) -> Dict[str, Set[Tuple[object, str]]]:
        interface_bridges = {
            node.id: _field(node.facts, "source", "bridge")
            for node in interfaces
        }
        return {
            "ovs_port": {
                (
                    _field(node.facts, "bridge", "source")
                    or interface_bridges.get(node.id),
                    node.id,
                )
                for node in ports
            },
            "runtime_interface": {
                (_field(node.facts, "source", "bridge"), node.id)
                for node in interfaces
            },
        }

    source_pairs = pairs(source_ports, source_interfaces)
    target_pairs = pairs(target_ports, target_interfaces)
    if any(
        not pair_set or any(bridge in (None, "") for bridge, _ in pair_set)
        for pair_set in [*source_pairs.values(), *target_pairs.values()]
    ):
        check(
            f"neutron.ovs-pairs.{port_id}", "UNKNOWN",
            f"OVS bridge evidence missing for port {port_id}", [f"port:{port_id}"],
        )
        return
    if source_pairs != target_pairs:
        check(
            f"neutron.ovs-pairs.{port_id}", "BLOCKED",
            f"target OVS dataplane mismatch for port {port_id}",
            [f"port:{port_id}"],
        )
        return
    check(
        f"neutron.ovs.{port_id}", "PASS",
        f"target OVS bridge and port match for port {port_id}",
        [f"port:{port_id}", *(node.key for node in target_ports)],
    )


def _compare_ovn_port(port_id, source_runtime, target_runtime, check) -> None:
    source_bindings = _runtime_nodes_for_port(source_runtime, "ovn_binding", port_id)
    target_bindings = _runtime_nodes_for_port(target_runtime, "ovn_binding", port_id)
    if not source_bindings:
        check(
            f"neutron.ovn-source-binding.{port_id}", "UNKNOWN",
            f"source OVN logical binding evidence missing for port {port_id}",
            [f"port:{port_id}"],
        )
        return
    if not target_bindings:
        check(
            f"neutron.ovn-binding.{port_id}", "BLOCKED",
            f"target OVN logical binding missing for port {port_id}",
            [f"port:{port_id}"],
        )
        return
    target_chassis = {
        _field(node.facts, "chassis") for node in target_bindings
        if _field(node.facts, "chassis") not in (None, "", [], {})
    }
    if not target_chassis:
        check(
            f"neutron.ovn-chassis.{port_id}", "BLOCKED",
            f"target OVN chassis missing for port {port_id}",
            [f"port:{port_id}", *(node.key for node in target_bindings)],
        )
        return
    source_chassis = {
        _field(node.facts, "chassis") for node in source_bindings
        if _field(node.facts, "chassis") not in (None, "", [], {})
    }
    if not source_chassis:
        check(
            f"neutron.ovn-source-chassis.{port_id}", "UNKNOWN",
            f"source OVN chassis missing for port {port_id}",
            [f"port:{port_id}", *(node.key for node in source_bindings)],
        )
        return
    if source_chassis and source_chassis.isdisjoint(target_chassis):
        check(
            f"neutron.ovn-chassis.{port_id}", "BLOCKED",
            f"target OVN chassis mismatch for port {port_id}",
            [f"port:{port_id}", *(node.key for node in target_bindings)],
        )
        return
    check(
        f"neutron.ovn.{port_id}", "PASS",
        f"target OVN logical binding and chassis match for port {port_id}",
        [f"port:{port_id}", *(node.key for node in target_bindings)],
    )
