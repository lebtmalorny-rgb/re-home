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

        rows: Dict[str, List[Mapping[str, Any]]] = {}
        for table in CORE_TABLES:
            if table not in self.available_tables:
                result.blockers.append(f"required Neutron table missing: {table}")
                rows[table] = []
            else:
                rows[table] = self._db_rows(table, result)
        for family_tables in OPTIONAL_TABLE_FAMILIES.values():
            for table in family_tables:
                if table in self.available_tables:
                    rows[table] = self._db_rows(table, result)

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
            facts = deepcopy(dict(matching_rows[0])) if matching_rows else {}
            facts.update(deepcopy(dict(api)))
            facts["api_id"] = api_id
            node = add_node("port", port_id, facts, [evidence_id] if evidence_id else [])
            assert node is not None
            network_id = _row_id(api, "network_id") or _row_id(facts, "network_id")
            if network_id:
                network_ids.append(network_id)
                add_edge(node.key, f"network:{network_id}", "uses_network")
            else:
                result.blockers.append(f"network UUID missing for port {port_id}")
            security_group_ids.extend(
                _identifiers(_field(api, "security_group_ids", "security_groups"))
            )

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
            facts = deepcopy(dict(matches[0])) if matches else {}
            facts.update(deepcopy(dict(api)))
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
            subnet = add_node("subnet", subnet_id, row)
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
            segment = add_node("segment", segment_id, row)
            if segment is not None:
                segment_ids.add(segment.id)
                network_id = _row_id(row, "network_id")
                if network_id:
                    add_edge(f"network:{network_id}", segment.key, "has_segment")

        for table in ("ml2_port_bindings", "ml2_distributed_port_bindings"):
            for row in rows[table]:
                port_id = _row_id(row, "port_id")
                if port_id not in selected_port_set:
                    continue
                host = _row_id(row, "host") or "unbound"
                binding_id = f"{port_id}:{host}"
                binding = add_node(
                    "ml2_binding", binding_id,
                    {**deepcopy(dict(row)), "distributed": table.startswith("ml2_distributed")},
                )
                if binding is not None:
                    add_edge(f"port:{port_id}", binding.key, "has_ml2_binding")
                    if host != "unbound":
                        agent = add_node("network_agent", host, {"host": host})
                        if agent is not None:
                            add_edge(binding.key, agent.key, "scheduled_to_agent")

        levels_by_port: Dict[str, int] = {port_id: 0 for port_id in selected_ports}
        for row in rows["ml2_port_binding_levels"]:
            port_id = _row_id(row, "port_id")
            if port_id not in selected_port_set:
                continue
            host = _row_id(row, "host") or "unbound"
            level = _field(row, "level")
            level_text = str(level) if level is not None else "unknown"
            binding_level = add_node(
                "binding_level", f"{port_id}:{host}:{level_text}", row
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
        rule_rows = [
            row for row in rows["securitygrouprules"]
            if _row_id(row, "security_group_id") in security_group_ids
        ]
        for row in rows["securitygroups"]:
            security_group_id = _row_id(row, "id")
            if security_group_id not in security_group_ids:
                continue
            facts = deepcopy(dict(row))
            facts["rules"] = [
                deepcopy(dict(rule)) for rule in rule_rows
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
            rows,
            selected_port_set,
            set(network_ids),
            set(subnet_ids),
            rule_rows,
            add_node,
            add_edge,
        )
        return result

    def _db_rows(
        self, table: str, result: CollectorResult
    ) -> List[Mapping[str, Any]]:
        source = getattr(self.client, "db_records", None)
        records = source(table) if callable(source) else None
        evidence = None
        if records is None:
            facts = getattr(self.client, "db_facts", None)
            records = facts.get(table) if isinstance(facts, Mapping) else None
        if isinstance(records, tuple) and len(records) == 2:
            records, evidence = records
        if not isinstance(records, list):
            result.blockers.append(f"DB facts missing or invalid: neutron.{table}")
            return []
        if callable(source):
            if not isinstance(evidence, Mapping) or not isinstance(
                evidence.get("evidence_id"), str
            ):
                result.blockers.append(f"DB evidence invalid: {table}")
            else:
                result.evidence.append(
                    {
                        "evidence_id": f"{self.side}-db:neutron.{table}",
                        "kind": "db-jsonl",
                        "schema": "neutron",
                        "table": table,
                    }
                )
        rows = []
        for index, record in enumerate(records):
            if not isinstance(record, Mapping):
                result.blockers.append(f"DB JSONL record invalid: {table}[{index}]")
                continue
            if {"_schema", "_table", "row"}.intersection(record):
                if (
                    record.get("_schema") != "neutron"
                    or record.get("_table") != table
                    or not isinstance(record.get("row"), Mapping)
                ):
                    result.blockers.append(f"DB JSONL record invalid: {table}[{index}]")
                    continue
                row = record["row"]
            else:
                row = record
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
        result.evidence.append(deepcopy(dict(evidence)))
        evidence_value = _field(evidence, "evidence_id", "id")
        return payload, str(evidence_value) if evidence_value else None

    def _expand_optional(
        self,
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
                    deepcopy(dict(row))
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
                    owner.facts.setdefault(fact_name, []).append(deepcopy(dict(row)))

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
                add_node("qos_policy", policy_id, row)

        relevant_trunks = set()
        for row in rows.get("trunks", []):
            trunk_id = _row_id(row, "id")
            parent_port = _row_id(row, "port_id")
            if trunk_id and parent_port in port_ids:
                relevant_trunks.add(trunk_id)
                add_node("trunk", trunk_id, row)
                add_edge(f"port:{parent_port}", f"trunk:{trunk_id}", "is_trunk_parent")
        for row in rows.get("subports", []):
            trunk_id = _row_id(row, "trunk_id")
            port_id = _row_id(row, "port_id")
            if port_id in port_ids and trunk_id:
                relevant_trunks.add(trunk_id)
        for row in rows.get("trunks", []):
            trunk_id = _row_id(row, "id")
            if trunk_id in relevant_trunks:
                add_node("trunk", trunk_id, row)
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
        for row in rows.get("floatingips", []):
            port_id = _row_id(row, "fixed_port_id", "port_id")
            floating_ip_id = _row_id(row, "id")
            if floating_ip_id in relevant_fips:
                router_id = _row_id(row, "router_id")
                if router_id:
                    router_ids.add(router_id)
                add_node("floating_ip", floating_ip_id, row)
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
                floating_ip = add_node("floating_ip", floating_ip_id)
                assert floating_ip is not None
                floating_ip.facts.setdefault("port_forwardings", []).append(
                    deepcopy(dict(row))
                )
                add_edge(
                    f"port:{port_id}", f"floating_ip:{floating_ip_id}",
                    "has_port_forwarding",
                )
        for row in rows.get("routers", []):
            router_id = _row_id(row, "id")
            if router_id in router_ids:
                add_node("router", router_id, row)
        for row in rows.get("routerroutes", []):
            router_id = _row_id(row, "router_id")
            if router_id in router_ids:
                router = add_node("router", router_id)
                assert router is not None
                router.facts.setdefault("routes", []).append(deepcopy(dict(row)))
        address_group_ids = {
            address_group_id
            for rule in security_group_rules
            if (address_group_id := _row_id(
                rule, "remote_address_group_id", "address_group_id"
            )) is not None
        }
        for row in rows.get("address_groups", []):
            address_group_id = _row_id(row, "id")
            if address_group_id in address_group_ids:
                facts = deepcopy(dict(row))
                facts["addresses"] = [
                    deepcopy(dict(association))
                    for association in rows.get("address_associations", [])
                    if _row_id(association, "address_group_id") == address_group_id
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


def _segment_signature(node: ResourceNode) -> Tuple[object, object, object]:
    return (
        _field(node.facts, "network_type"),
        _field(node.facts, "physical_network"),
        _field(node.facts, "segmentation_id"),
    )


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

    for blocker in [*source.blockers, *target.blockers]:
        if blocker not in result.blockers:
            result.blockers.append(blocker)
    for unknown in [*source.unknowns, *target.unknowns]:
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
        signatures = {_segment_signature(segment) for segment in source_segments}
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
    source_bridges = {
        _field(node.facts, "source", "bridge")
        for node in [*source_ports, *source_interfaces]
        if _field(node.facts, "source", "bridge") not in (None, "")
    }
    target_bridges = {
        _field(node.facts, "source", "bridge")
        for node in [*target_ports, *target_interfaces]
        if _field(node.facts, "source", "bridge") not in (None, "")
    }
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
    if not source_bridges or not target_bridges:
        check(
            f"neutron.ovs-bridge.{port_id}", "UNKNOWN",
            f"OVS bridge evidence missing for port {port_id}", [f"port:{port_id}"],
        )
        return
    if source_bridges.isdisjoint(target_bridges):
        check(
            f"neutron.ovs-bridge.{port_id}", "BLOCKED",
            f"target OVS bridge mismatch for port {port_id}", [f"port:{port_id}"],
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
