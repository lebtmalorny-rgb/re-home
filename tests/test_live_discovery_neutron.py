from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
FIXTURES = ROOT / "tests" / "fixtures" / "live_discovery"

from live_discovery.contract import CollectorResult, DependencyEdge, ResourceNode
from live_discovery.neutron import NeutronCollector, compare_neutron_results


class FixtureClient:
    _fixture_only = True

    def __init__(self, fixture):
        self.fixture = deepcopy(fixture)
        self.responses = {
            tuple(item["command"]): deepcopy(item["payload"])
            for item in fixture["openstack"]
        }
        self.queried_tables = []
        self.queries = []
        self.commands = []

    def json(self, command, evidence_id, required=True):
        del required
        self.commands.append(deepcopy(command))
        key = tuple(command)
        if key not in self.responses:
            raise AssertionError(f"unexpected OpenStack command: {command}")
        return deepcopy(self.responses[key]), {"id": evidence_id}

    def db_records(self, table, filters=None):
        self.queried_tables.append(table)
        normalized_filters = deepcopy(filters)
        self.queries.append((table, normalized_filters))
        table_rows = deepcopy(self.fixture.get("tables", {}).get(table, []))
        if filters:
            table_rows = [
                row for row in table_rows
                if any(
                    row.get(column) in values
                    for column, values in filters.items()
                )
            ]
        rows = [
            {"_schema": "neutron", "_table": table, "row": deepcopy(row)}
            for row in table_rows
        ]
        return rows, {
            "evidence_id": f"{self.fixture.get('side', 'source')}-db:neutron.{table}",
            "schema": "neutron",
            "table": table,
            "filters": normalized_filters,
        }


def schema_from_fixture(fixture):
    return {f"neutron.{table}": {} for table in fixture["schema_tables"]}


UUID_ALIASES = {
    alias: f"00000000-0000-0000-0000-{index:012d}"
    for index, alias in enumerate(
        (
            "port-1", "network-1", "instance-1", "subnet-1", "segment-1",
            "sg-1", "rule-1", "address-group-1", "qos-1", "trunk-1",
            "router-1", "fip-1", "network-external", "pf-1",
        ),
        start=1,
    )
}


def canonical_uuid_fixture(fixture):
    def replace(value):
        if isinstance(value, str):
            return UUID_ALIASES.get(value, value)
        if isinstance(value, list):
            return [replace(item) for item in value]
        if isinstance(value, dict):
            return {key: replace(item) for key, item in value.items()}
        return value

    return replace(deepcopy(fixture))


def collect_from_fixture(fixture, port_ids):
    client = FixtureClient(fixture)
    result = NeutronCollector.for_fixture(
        client, fixture.get("side", "source"), schema_from_fixture(fixture)
    ).collect(port_ids)
    return result


def runtime_from_fixture(fixture):
    result = CollectorResult(service="runtime", side=fixture.get("side", "source"))
    runtime = fixture.get("runtime", {})
    for item in runtime.get("nodes", []):
        result.nodes.append(
            ResourceNode(item["kind"], item["id"], result.side, item.get("facts", {}))
        )
    for item in runtime.get("edges", []):
        result.edges.append(
            DependencyEdge(
                item["source"], item["target"], item["relation"],
                item.get("required", True),
            )
        )
    return result


def compare_source_target(source_fixture, target_fixture, backend=None):
    source = collect_from_fixture(source_fixture, ["port-1"])
    target = collect_from_fixture(target_fixture, ["port-1"])
    return compare_neutron_results(
        source,
        target,
        runtime_from_fixture(source_fixture),
        runtime_from_fixture(target_fixture),
        backend or target_fixture["network_backend"],
    )


class NeutronCollectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_fixture = json.loads(
            (FIXTURES / "neutron-ovs-source.json").read_text(encoding="utf-8")
        )
        cls.ovs_target_fixture = json.loads(
            (FIXTURES / "neutron-ovs-target.json").read_text(encoding="utf-8")
        )
        cls.ovn_target_fixture = json.loads(
            (FIXTURES / "neutron-ovn-target.json").read_text(encoding="utf-8")
        )

    def test_ovs_port_requires_binding_level_and_matching_segment(self):
        result = collect_from_fixture(self.source_fixture, ["port-1"])
        required = {
            (edge.source, edge.target, edge.relation)
            for edge in result.edges if edge.required
        }

        self.assertIn(
            ("port:port-1", "binding_level:port-1:compute-023:0", "has_binding_level"),
            required,
        )
        self.assertIn(
            ("binding_level:port-1:compute-023:0", "segment:segment-1", "uses_segment"),
            required,
        )

    def test_missing_target_segment_blocks(self):
        target_without_segment = deepcopy(self.ovs_target_fixture)
        target_without_segment["tables"]["networksegments"] = []

        result = compare_source_target(self.source_fixture, target_without_segment)

        self.assertIn("target segment missing for port port-1", result.blockers)

    def test_optional_rows_expand_only_active_uuid_scoped_dependencies(self):
        fixture = deepcopy(self.source_fixture)
        fixture["tables"]["qos_policies"].append({"id": "qos-unrelated", "name": "other"})
        fixture["tables"]["floatingips"].append({"id": "fip-unrelated", "fixed_port_id": "port-9"})

        result = collect_from_fixture(fixture, ["port-1"])
        keys = {node.key for node in result.nodes}

        self.assertIn("qos_policy:qos-1", keys)
        self.assertIn("trunk:trunk-1", keys)
        self.assertIn("router:router-1", keys)
        self.assertIn("floating_ip:fip-1", keys)
        self.assertIn("address_group:address-group-1", keys)
        self.assertNotIn("qos_policy:qos-unrelated", keys)
        self.assertNotIn("floating_ip:fip-unrelated", keys)

    def test_missing_security_group_node_blocks_required_edge(self):
        fixture = deepcopy(self.source_fixture)
        fixture["tables"]["securitygroups"] = []

        result = collect_from_fixture(fixture, ["port-1"])

        self.assertIn(
            "required dependency node missing: security_group:sg-1",
            result.blockers,
        )

    def test_api_security_group_without_db_binding_blocks(self):
        fixture = deepcopy(self.source_fixture)
        fixture["tables"]["securitygroupportbindings"] = []

        result = collect_from_fixture(fixture, ["port-1"])

        self.assertIn(
            "security group API/DB binding mismatch: port-1",
            result.blockers,
        )

    def test_db_security_group_without_api_binding_blocks(self):
        fixture = deepcopy(self.source_fixture)
        fixture["openstack"][0]["payload"]["security_group_ids"] = []

        result = collect_from_fixture(fixture, ["port-1"])

        self.assertIn(
            "security group API/DB binding mismatch: port-1",
            result.blockers,
        )

    def test_malformed_api_security_group_identifier_fails_closed(self):
        fixture = deepcopy(self.source_fixture)
        fixture["openstack"][0]["payload"]["security_group_ids"] = [
            "sg-identifier-secret malformed"
        ]

        result = collect_from_fixture(fixture, ["port-1"])
        serialized = json.dumps(result.to_dict())

        self.assertIn(
            "security group API identifiers invalid: port-1",
            result.blockers,
        )
        self.assertNotIn("sg-identifier-secret", serialized)

    def test_malformed_selected_port_root_fails_before_acquisition(self):
        client = FixtureClient(self.source_fixture)

        result = NeutronCollector(
            client, "source", schema_from_fixture(self.source_fixture)
        ).collect(["port-root-secret malformed"])

        self.assertIn("Neutron port roots invalid", result.blockers)
        self.assertEqual([], client.queries)
        self.assertEqual([], client.commands)
        self.assertNotIn("port-root-secret", json.dumps(result.to_dict()))

    def test_production_rejects_short_fixture_alias_before_acquisition(self):
        client = FixtureClient(self.source_fixture)

        result = NeutronCollector(
            client, "source", schema_from_fixture(self.source_fixture)
        ).collect(["port-1"])

        self.assertIn("Neutron port roots invalid", result.blockers)
        self.assertEqual([], client.queries)
        self.assertEqual([], client.commands)
        self.assertNotIn("port-1", json.dumps(result.to_dict()))

    def test_fixture_aliases_require_explicit_fixture_only_factory(self):
        result = NeutronCollector.for_fixture(
            FixtureClient(self.source_fixture),
            "source",
            schema_from_fixture(self.source_fixture),
        ).collect(["port-1"])

        self.assertFalse(any("port roots invalid" in item for item in result.blockers))
        with self.assertRaises(ValueError):
            NeutronCollector.for_fixture(
                object(), "source", schema_from_fixture(self.source_fixture)
            )

    def test_readiness_rejects_alias_results_without_fixture_marker(self):
        source = collect_from_fixture(self.source_fixture, ["port-1"])
        target = collect_from_fixture(self.ovs_target_fixture, ["port-1"])
        if hasattr(source, "_fixture_aliases"):
            del source._fixture_aliases
        if hasattr(target, "_fixture_aliases"):
            del target._fixture_aliases

        result = compare_neutron_results(
            source,
            target,
            runtime_from_fixture(self.source_fixture),
            runtime_from_fixture(self.ovs_target_fixture),
            "ovs",
        )

        self.assertIn(
            "source Neutron ports unavailable after identifier validation",
            result.unknowns,
        )
        self.assertIn(
            "target Neutron resource identifier invalid: port",
            result.blockers,
        )
        self.assertNotIn("port-1", json.dumps(result.to_dict()))

    def test_readiness_reports_all_source_ports_discarded(self):
        source = CollectorResult(service="neutron", side="source")
        source.nodes.append(
            ResourceNode(
                "port", "all-source-port-secret", "source",
                {"network_id": "all-source-network-secret"},
            )
        )

        result = compare_neutron_results(
            source,
            CollectorResult(service="neutron", side="target"),
            CollectorResult(service="runtime", side="source"),
            CollectorResult(service="runtime", side="target"),
            "ovs",
        )

        self.assertIn(
            "source Neutron ports unavailable after identifier validation",
            result.unknowns,
        )
        self.assertNotIn("all-source-port-secret", json.dumps(result.to_dict()))
        self.assertNotIn("all-source-network-secret", json.dumps(result.to_dict()))

    def test_readiness_reports_partially_discarded_source_and_target_nodes(self):
        port_id = UUID_ALIASES["port-1"]
        network_id = UUID_ALIASES["network-1"]
        source = CollectorResult(service="neutron", side="source")
        source.nodes.extend(
            [
                ResourceNode(
                    "port", port_id, "source",
                    {"api_id": port_id, "network_id": network_id},
                ),
                ResourceNode("port", "partial-source-secret", "source"),
            ]
        )
        source.edges.append(
            DependencyEdge(
                f"port:{port_id}", f"network:{network_id}",
                "uses_network", True,
            )
        )
        target = CollectorResult(service="neutron", side="target")
        target.nodes.extend(
            [
                ResourceNode(
                    "port", port_id, "target",
                    {"api_id": port_id, "network_id": network_id},
                ),
                ResourceNode("port", "partial-target-port-secret", "target"),
                ResourceNode(
                    "network", network_id, "target", {"api_id": network_id}
                ),
                ResourceNode(
                    "network", "partial-target-network-secret", "target"
                ),
            ]
        )

        result = compare_neutron_results(
            source,
            target,
            CollectorResult(service="runtime", side="source"),
            CollectorResult(service="runtime", side="target"),
            None,
        )
        serialized = json.dumps(result.to_dict())

        self.assertIn(
            "source Neutron resource identifier invalid: port",
            result.unknowns,
        )
        self.assertIn(
            "target Neutron resource identifier invalid: port",
            result.blockers,
        )
        self.assertIn(
            "target Neutron resource identifier invalid: network",
            result.blockers,
        )
        self.assertNotIn("partial-source-secret", serialized)
        self.assertNotIn("partial-target-port-secret", serialized)
        self.assertNotIn("partial-target-network-secret", serialized)

    def test_production_accepts_canonical_uuid_dependency_graph(self):
        fixture = canonical_uuid_fixture(self.source_fixture)
        port_id = UUID_ALIASES["port-1"]

        result = NeutronCollector(
            FixtureClient(fixture), "source", schema_from_fixture(fixture)
        ).collect([port_id])

        self.assertEqual([], result.blockers)
        self.assertIn(f"port:{port_id}", {node.key for node in result.nodes})
        self.assertNotIn("port-1", json.dumps(result.to_dict()))
        uuid_node_kinds = {
            "port", "network", "subnet", "segment", "security_group",
            "qos_policy", "trunk", "floating_ip", "router", "address_group",
        }
        canonical_uuid = r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$"
        for node in result.nodes:
            if node.kind in uuid_node_kinds:
                self.assertRegex(node.id, canonical_uuid)

    def test_production_excludes_malformed_dependency_ids(self):
        cases = (
            ("segment", "networksegments", "id", "segment-id-secret"),
            ("qos", "qos_port_policy_bindings", "policy_id", "qos-id-secret"),
            ("router", "routerports", "router_id", "router-id-secret"),
        )
        for name, table, field, secret in cases:
            with self.subTest(name=name):
                fixture = canonical_uuid_fixture(self.source_fixture)
                fixture["tables"][table][0][field] = secret
                port_id = UUID_ALIASES["port-1"]

                result = NeutronCollector(
                    FixtureClient(fixture), "source", schema_from_fixture(fixture)
                ).collect([port_id])

                self.assertNotIn(secret, json.dumps(result.to_dict()))

    def test_production_excludes_malformed_rbac_target_project_id(self):
        fixture = canonical_uuid_fixture(self.source_fixture)
        fixture["tables"]["addressgrouprbacs"] = [
            {
                "id": "00000000-0000-0000-0000-000000000015",
                "object_id": UUID_ALIASES["address-group-1"],
                "target_project": "target-project-id-secret",
                "action": "access_as_shared",
            }
        ]

        result = NeutronCollector(
            FixtureClient(fixture), "source", schema_from_fixture(fixture)
        ).collect([UUID_ALIASES["port-1"]])

        self.assertNotIn("target-project-id-secret", json.dumps(result.to_dict()))

    def test_active_dependency_families_block_present_invalid_uuids(self):
        cases = (
            ("core-port", "ports", "device_id", None),
            ("core-port-alias", "ports", "port_id", None),
            ("core-ip", "ipallocations", "subnet_id", None),
            ("segment", "networksegments", "id", None),
            ("segment-alias", "networksegments", "segment_id", None),
            ("binding", "ml2_port_binding_levels", "segment_id", None),
            (
                "security-group", "securitygroupportbindings",
                "security_group_id", None,
            ),
            (
                "security-rule", "securitygrouprules",
                "remote_address_group_id", None,
            ),
            (
                "security-rule-alias", "securitygrouprules",
                "address_group_id", None,
            ),
            ("qos", "qos_port_policy_bindings", "policy_id", None),
            ("trunk", "trunks", "id", None),
            (
                "subport", "subports", "trunk_id",
                {
                    "port_id": UUID_ALIASES["port-1"],
                    "segmentation_type": "vlan", "segmentation_id": 42,
                },
            ),
            ("router", "routerports", "router_id", None),
            ("floating-ip", "floatingips", "router_id", None),
            ("floating-ip-alias", "floatingips", "port_id", None),
            ("port-forwarding", "portforwardings", "floatingip_id", None),
            (
                "rbac", "addressgrouprbacs", "id",
                {
                    "object_id": UUID_ALIASES["address-group-1"],
                    "target_project": "*", "action": "access_as_shared",
                },
            ),
        )
        for family, table, field, seed in cases:
            with self.subTest(family=family, table=table, field=field):
                fixture = canonical_uuid_fixture(self.source_fixture)
                sentinel = f"{family}-dependency-secret"
                if seed is None:
                    row = fixture["tables"][table][0]
                else:
                    row = deepcopy(seed)
                    fixture["tables"][table].append(row)
                row[field] = sentinel

                result = NeutronCollector(
                    FixtureClient(fixture), "source", schema_from_fixture(fixture)
                ).collect([UUID_ALIASES["port-1"]])
                serialized = json.dumps(result.to_dict())

                self.assertIn(
                    f"Neutron dependency UUID invalid: {table}.{field}",
                    result.blockers,
                )
                self.assertNotIn(sentinel, serialized)

    def test_active_api_dependency_fields_use_sanitized_table_field_blockers(self):
        cases = (
            (0, "ports", "id"),
            (0, "ports", "network_id"),
            (0, "ports", "device_id"),
            (1, "networks", "id"),
        )
        for response_index, table, field in cases:
            with self.subTest(table=table, field=field):
                fixture = canonical_uuid_fixture(self.source_fixture)
                sentinel = f"api-{table}-{field}-secret"
                fixture["openstack"][response_index]["payload"][field] = sentinel

                result = NeutronCollector(
                    FixtureClient(fixture), "source", schema_from_fixture(fixture)
                ).collect([UUID_ALIASES["port-1"]])
                serialized = json.dumps(result.to_dict())

                self.assertIn(
                    f"Neutron dependency UUID invalid: {table}.{field}",
                    result.blockers,
                )
                self.assertNotIn(sentinel, serialized)

    def test_missing_qos_policy_node_blocks_required_edge(self):
        fixture = deepcopy(self.source_fixture)
        fixture["tables"]["qos_policies"] = []

        result = collect_from_fixture(fixture, ["port-1"])

        self.assertIn(
            "required dependency node missing: qos_policy:qos-1",
            result.blockers,
        )

    def test_binding_level_does_not_replace_required_ml2_binding(self):
        fixture = deepcopy(self.source_fixture)
        fixture["tables"]["ml2_port_bindings"] = []

        result = collect_from_fixture(fixture, ["port-1"])

        self.assertIn("ML2 binding missing for port port-1", result.blockers)

    def test_missing_segment_node_blocks_binding_level_dependency(self):
        fixture = deepcopy(self.source_fixture)
        fixture["tables"]["networksegments"] = []

        result = collect_from_fixture(fixture, ["port-1"])

        self.assertIn("binding level segment missing for port port-1", result.blockers)

    def test_binding_level_is_normalized_before_node_id_and_facts(self):
        cases = (
            ("dict", {"token": "binding-level-dict-secret"}),
            ("list", ["binding-level-list-secret"]),
            ("missing", None),
            ("negative", -1),
            ("too-large", 256),
        )
        for name, value in cases:
            with self.subTest(name=name):
                fixture = deepcopy(self.source_fixture)
                level_row = fixture["tables"]["ml2_port_binding_levels"][0]
                if name == "missing":
                    level_row.pop("level")
                else:
                    level_row["level"] = value

                result = collect_from_fixture(fixture, ["port-1"])
                serialized = json.dumps(result.to_dict())

                self.assertIn("binding level invalid for port port-1", result.blockers)
                self.assertFalse(
                    any(node.kind == "binding_level" for node in result.nodes)
                )
                self.assertNotIn("binding-level-dict-secret", serialized)
                self.assertNotIn("binding-level-list-secret", serialized)

    def test_malformed_supplied_ml2_hosts_fail_closed(self):
        cases = (
            (
                "binding-dict", "ml2_port_bindings",
                {"token": "binding-host-secret"},
                "ML2 binding host invalid for port port-1", "ml2_binding",
            ),
            (
                "binding-whitespace", "ml2_port_bindings", "   ",
                "ML2 binding host invalid for port port-1", "ml2_binding",
            ),
            (
                "level-list", "ml2_port_binding_levels",
                ["level-host-secret"],
                "binding level host invalid for port port-1", "binding_level",
            ),
            (
                "level-malformed", "ml2_port_binding_levels", "compute/023",
                "binding level host invalid for port port-1", "binding_level",
            ),
        )
        for name, table, value, reason, node_kind in cases:
            with self.subTest(name=name):
                fixture = deepcopy(self.source_fixture)
                fixture["tables"][table][0]["host"] = value

                result = collect_from_fixture(fixture, ["port-1"])
                serialized = json.dumps(result.to_dict())

                self.assertIn(reason, result.blockers)
                self.assertFalse(any(node.kind == node_kind for node in result.nodes))
                self.assertNotIn("binding-host-secret", serialized)
                self.assertNotIn("level-host-secret", serialized)

    def test_missing_or_empty_ml2_hosts_are_explicit_unbound(self):
        cases = (
            ("ml2_port_bindings", "ml2_binding", "port-1:unbound"),
            (
                "ml2_port_binding_levels", "binding_level",
                "port-1:unbound:0",
            ),
        )
        for table, node_kind, expected_id in cases:
            for supplied in (False, True):
                with self.subTest(table=table, supplied=supplied):
                    fixture = deepcopy(self.source_fixture)
                    row = fixture["tables"][table][0]
                    if supplied:
                        row["host"] = ""
                    else:
                        row.pop("host")

                    result = collect_from_fixture(fixture, ["port-1"])

                    self.assertIn(
                        expected_id,
                        {
                            node.id for node in result.nodes
                            if node.kind == node_kind
                        },
                    )

    def test_missing_router_node_blocks_required_edge(self):
        fixture = deepcopy(self.source_fixture)
        fixture["tables"]["routers"] = []

        result = collect_from_fixture(fixture, ["port-1"])

        self.assertIn(
            "required dependency node missing: router:router-1",
            result.blockers,
        )

    def test_missing_floating_ip_node_blocks_port_forwarding_dependency(self):
        fixture = deepcopy(self.source_fixture)
        fixture["tables"]["floatingips"] = []

        result = collect_from_fixture(fixture, ["port-1"])

        self.assertIn("floating IP row missing: fip-1", result.blockers)

    def test_missing_address_group_node_blocks_security_group_dependency(self):
        fixture = deepcopy(self.source_fixture)
        fixture["tables"]["address_groups"] = []

        result = collect_from_fixture(fixture, ["port-1"])

        self.assertIn(
            "required dependency node missing: address_group:address-group-1",
            result.blockers,
        )

    def test_trunk_parent_recursively_expands_child_core_dependencies(self):
        fixture = deepcopy(self.source_fixture)
        fixture["openstack"].append(
            {
                "command": ["port", "show", "port-2", "-f", "json"],
                "payload": {
                    "id": "port-2", "network_id": "network-1",
                    "mac_address": "fa:16:3e:65:43:21",
                    "device_owner": "trunk:subport",
                    "binding_host_id": "compute-023",
                    "binding_vif_type": "ovs",
                },
            }
        )
        fixture["tables"]["ports"].append(
            {
                "id": "port-2", "network_id": "network-1",
                "mac_address": "fa:16:3e:65:43:21",
                "device_owner": "trunk:subport",
            }
        )
        fixture["tables"]["ipallocations"].append(
            {
                "port_id": "port-2", "network_id": "network-1",
                "subnet_id": "subnet-1", "ip_address": "192.0.2.20",
            }
        )
        fixture["tables"]["ml2_port_bindings"].append(
            {"port_id": "port-2", "host": "compute-023", "vif_type": "ovs"}
        )
        fixture["tables"]["ml2_port_binding_levels"].append(
            {
                "port_id": "port-2", "host": "compute-023", "level": 0,
                "driver": "openvswitch", "segment_id": "segment-1",
            }
        )
        fixture["tables"]["subports"].append(
            {
                "trunk_id": "trunk-1", "port_id": "port-2",
                "segmentation_type": "vlan", "segmentation_id": 42,
            }
        )

        result = collect_from_fixture(fixture, ["port-1"])
        required = {(edge.source, edge.target) for edge in result.edges if edge.required}

        self.assertIn("port:port-2", {node.key for node in result.nodes})
        self.assertIn(
            ("port:port-2", "binding_level:port-2:compute-023:0"), required
        )
        self.assertIn(
            ("binding_level:port-2:compute-023:0", "segment:segment-1"), required
        )

    def test_selected_trunk_child_acquires_parent_and_scoped_dependencies(self):
        fixture = deepcopy(self.source_fixture)
        fixture["openstack"].append(
            {
                "command": ["port", "show", "port-2", "-f", "json"],
                "payload": {
                    "id": "port-2", "network_id": "network-1",
                    "mac_address": "fa:16:3e:65:43:21",
                    "device_owner": "trunk:subport",
                    "binding_host_id": "compute-023",
                    "binding_vif_type": "ovs",
                    "security_group_ids": [],
                },
            }
        )
        fixture["tables"]["ports"].append(
            {
                "id": "port-2", "network_id": "network-1",
                "mac_address": "fa:16:3e:65:43:21",
                "device_owner": "trunk:subport",
            }
        )
        fixture["tables"]["ipallocations"].append(
            {
                "port_id": "port-2", "network_id": "network-1",
                "subnet_id": "subnet-1", "ip_address": "192.0.2.20",
            }
        )
        fixture["tables"]["ml2_port_bindings"].append(
            {"port_id": "port-2", "host": "compute-023", "vif_type": "ovs"}
        )
        fixture["tables"]["ml2_port_binding_levels"].append(
            {
                "port_id": "port-2", "host": "compute-023", "level": 0,
                "driver": "openvswitch", "segment_id": "segment-1",
            }
        )
        fixture["tables"]["subports"].append(
            {
                "trunk_id": "trunk-1", "port_id": "port-2",
                "segmentation_type": "vlan", "segmentation_id": 42,
            }
        )
        client = FixtureClient(fixture)

        result = NeutronCollector.for_fixture(
            client, "source", schema_from_fixture(fixture)
        ).collect(["port-2"])
        keys = {node.key for node in result.nodes}

        self.assertIn(("subports", {"port_id": ["port-2"]}), client.queries)
        self.assertIn("trunk:trunk-1", keys)
        self.assertIn("port:port-1", keys)
        self.assertIn("port:port-2", keys)
        self.assertIn("ml2_binding:port-1:compute-023", keys)
        self.assertIn("ml2_binding:port-2:compute-023", keys)

    def test_address_group_rbac_is_attached_only_for_active_group(self):
        fixture = deepcopy(self.source_fixture)
        fixture["tables"]["addressgrouprbacs"] = [
            {
                "id": "rbac-1", "object_id": "address-group-1",
                "target_project": "project-2", "action": "access_as_shared",
            },
            {
                "id": "rbac-unrelated", "object_id": "address-group-9",
                "target_project": "project-9", "action": "access_as_shared",
            },
        ]

        result = collect_from_fixture(fixture, ["port-1"])
        group = next(
            node for node in result.nodes
            if node.kind == "address_group" and node.id == "address-group-1"
        )

        self.assertIn("rbac_entries", group.facts)
        self.assertEqual(["rbac-1"], [row["id"] for row in group.facts["rbac_entries"]])

    def test_fip_qos_and_port_forwarding_expand_from_selected_internal_port(self):
        fixture = deepcopy(self.source_fixture)
        fixture["tables"]["floatingips"][0]["fixed_port_id"] = None
        fixture["tables"]["qos_policies"].append(
            {"id": "qos-fip", "name": "fip-gold"}
        )
        fixture["tables"]["qos_fip_policy_bindings"].append(
            {"fip_id": "fip-1", "policy_id": "qos-fip"}
        )

        result = collect_from_fixture(fixture, ["port-1"])
        keys = {node.key for node in result.nodes}
        edges = {(edge.source, edge.target) for edge in result.edges}

        self.assertIn("floating_ip:fip-1", keys)
        floating_ip = next(
            node for node in result.nodes
            if node.kind == "floating_ip" and node.id == "fip-1"
        )

        self.assertIn("qos_policy:qos-fip", keys)
        self.assertIn(("floating_ip:fip-1", "qos_policy:qos-fip"), edges)
        self.assertEqual("pf-1", floating_ip.facts["port_forwardings"][0]["id"])

    def test_absent_optional_family_is_not_queried_or_blocked(self):
        fixture = deepcopy(self.ovs_target_fixture)
        client = FixtureClient(fixture)

        result = NeutronCollector.for_fixture(
            client, "target", schema_from_fixture(fixture)
        ).collect(["port-1"])

        self.assertNotIn("qos_policies", client.queried_tables)
        self.assertFalse(any("qos_policies" in item for item in result.blockers))

    def test_directional_schema_mapping_shape_exposes_neutron_tables(self):
        fixture = deepcopy(self.ovs_target_fixture)
        client = FixtureClient(fixture)
        schema = {
            "tables": {
                f"neutron.{table}": [] for table in fixture["schema_tables"]
            }
        }

        result = NeutronCollector.for_fixture(
            client, "target", schema
        ).collect(["port-1"])

        self.assertFalse(
            any("required Neutron table missing" in item for item in result.blockers)
        )

    def test_db_queries_are_acquired_with_explicit_active_root_filters(self):
        client = FixtureClient(self.source_fixture)

        result = NeutronCollector.for_fixture(
            client, "source", schema_from_fixture(self.source_fixture)
        ).collect(["port-1"])
        queries = {table: filters for table, filters in client.queries}

        self.assertEqual([], result.blockers)
        self.assertEqual({"id": ["port-1"]}, queries["ports"])
        self.assertEqual({"port_id": ["port-1"]}, queries["ipallocations"])
        self.assertEqual({"id": ["network-1"]}, queries["networks"])
        self.assertEqual({"network_id": ["network-1"]}, queries["networksegments"])
        self.assertEqual({"id": ["sg-1"]}, queries["securitygroups"])
        self.assertEqual({"id": ["qos-1"]}, queries["qos_policies"])
        self.assertTrue(all(filters for _, filters in client.queries))

    def test_bare_db_mapping_is_rejected_as_non_jsonl_envelope(self):
        class BareRecordClient(FixtureClient):
            def db_records(self, table, filters=None):
                records, evidence = super().db_records(table, filters)
                if table == "ports":
                    records = [record["row"] for record in records]
                return records, evidence

        client = BareRecordClient(self.source_fixture)

        result = NeutronCollector.for_fixture(
            client, "source", schema_from_fixture(self.source_fixture)
        ).collect(["port-1"])

        self.assertIn("DB JSONL record invalid: ports[0]", result.blockers)

    def test_jsonl_envelope_with_extra_metadata_is_rejected(self):
        class ExtraEnvelopeClient(FixtureClient):
            def db_records(self, table, filters=None):
                records, evidence = super().db_records(table, filters)
                if table == "ports" and records:
                    records[0]["source"] = "untrusted"
                return records, evidence

        result = NeutronCollector.for_fixture(
            ExtraEnvelopeClient(self.source_fixture),
            "source",
            schema_from_fixture(self.source_fixture),
        ).collect(["port-1"])

        self.assertIn("DB JSONL record invalid: ports[0]", result.blockers)

    def test_arbitrary_db_evidence_is_rejected(self):
        class ArbitraryEvidenceClient(FixtureClient):
            def db_records(self, table, filters=None):
                records, evidence = super().db_records(table, filters)
                if table == "ports":
                    evidence["password"] = "db-evidence-secret"
                return records, evidence

        result = NeutronCollector.for_fixture(
            ArbitraryEvidenceClient(self.source_fixture),
            "source",
            schema_from_fixture(self.source_fixture),
        ).collect(["port-1"])

        self.assertIn("DB evidence invalid: ports", result.blockers)
        self.assertNotIn("db-evidence-secret", json.dumps(result.to_dict()))

    def test_db_probe_failure_returns_blocker_instead_of_empty_success(self):
        class FailingDbClient(FixtureClient):
            def db_records(self, table, filters=None):
                if table == "ports":
                    raise RuntimeError("database-password-secret")
                return super().db_records(table, filters)

        result = NeutronCollector.for_fixture(
            FailingDbClient(self.source_fixture),
            "source",
            schema_from_fixture(self.source_fixture),
        ).collect(["port-1"])

        self.assertIn("DB probe failed: neutron.ports", result.blockers)
        self.assertNotIn("database-password-secret", json.dumps(result.to_dict()))

    def test_node_facts_and_evidence_exclude_unallowlisted_secrets(self):
        fixture = deepcopy(self.source_fixture)
        fixture["openstack"][0]["payload"].update(
            {
                "password": "api-password", "token": "api-token",
                "fixed_ips": [
                    {"ip_address": "192.0.2.10", "token": "nested-api-token"}
                ],
                "security_group_ids": [
                    {"id": "sg-1", "token": "nested-sg-token"}
                ],
            }
        )
        fixture["tables"]["ports"][0].update(
            {"connection_info": "db-connection-secret", "auth_token": "db-token"}
        )
        fixture["tables"]["ml2_port_bindings"][0]["profile"] = {
            "token": "nested-db-token"
        }

        class SecretEvidenceClient(FixtureClient):
            def json(self, command, evidence_id, required=True):
                payload, evidence = super().json(command, evidence_id, required)
                evidence["token"] = "api-evidence-token"
                return payload, evidence

        result = NeutronCollector.for_fixture(
            SecretEvidenceClient(fixture), "source", schema_from_fixture(fixture)
        ).collect(["port-1"])
        serialized = json.dumps(result.to_dict())

        for secret in (
            "api-password", "api-token", "db-connection-secret", "db-token",
            "api-evidence-token", "nested-api-token", "nested-db-token",
            "nested-sg-token",
        ):
            self.assertNotIn(secret, serialized)

    def test_allowlisted_fields_reject_nested_container_values(self):
        fixture = deepcopy(self.source_fixture)
        fixture["openstack"][0]["payload"]["device_id"] = {
            "token": "nested-device-secret"
        }
        fixture["openstack"][0]["payload"]["id"] = {
            "token": "nested-id-secret"
        }
        fixture["openstack"][1]["payload"]["name"] = [
            {"password": "nested-network-secret"}
        ]
        fixture["tables"]["networksegments"][0]["network_type"] = {
            "password": "nested-segment-secret"
        }
        fixture["tables"]["qos_policies"][0]["name"] = [
            {"token": "nested-qos-secret"}
        ]

        result = collect_from_fixture(fixture, ["port-1"])
        serialized = json.dumps(result.to_dict())

        for secret in (
            "nested-device-secret", "nested-network-secret",
            "nested-segment-secret", "nested-qos-secret", "nested-id-secret",
        ):
            self.assertNotIn(secret, serialized)

    def test_api_db_port_network_mismatch_blocks_before_merge(self):
        fixture = deepcopy(self.source_fixture)
        fixture["tables"]["ports"][0]["network_id"] = "network-db-other"

        result = collect_from_fixture(fixture, ["port-1"])

        self.assertIn("port API/DB network mismatch: port-1", result.blockers)

    def test_one_sided_missing_port_identity_fields_block_symmetrically(self):
        cases = (
            ("api", "network_id", "port API/DB network mismatch: port-1"),
            ("db", "network_id", "port API/DB network mismatch: port-1"),
            ("api", "device_id", "port API/DB device_id mismatch: port-1"),
            ("db", "device_id", "port API/DB device_id mismatch: port-1"),
        )
        for side, field, reason in cases:
            with self.subTest(side=side, field=field):
                fixture = deepcopy(self.source_fixture)
                if side == "api":
                    fixture["openstack"][0]["payload"].pop(field)
                else:
                    fixture["tables"]["ports"][0].pop(field)

                result = collect_from_fixture(fixture, ["port-1"])

                self.assertIn(reason, result.blockers)

    def test_equal_malformed_api_db_identity_values_still_block(self):
        cases = (
            ("network_id", {"token": "identity-network-secret"}),
            ("device_id", ["identity-device-secret"]),
            ("device_owner", "compute nova"),
            ("mac_address", "not-a-mac"),
        )
        for field, value in cases:
            with self.subTest(field=field):
                fixture = deepcopy(self.source_fixture)
                fixture["openstack"][0]["payload"][field] = deepcopy(value)
                fixture["tables"]["ports"][0][field] = deepcopy(value)

                result = collect_from_fixture(fixture, ["port-1"])
                serialized = json.dumps(result.to_dict())
                reason_field = "network" if field == "network_id" else field

                self.assertIn(
                    f"port API/DB {reason_field} mismatch: port-1",
                    result.blockers,
                )
                self.assertNotIn("identity-network-secret", serialized)
                self.assertNotIn("identity-device-secret", serialized)

    def test_target_requires_exact_port_and_network_uuid(self):
        target = deepcopy(self.ovs_target_fixture)
        target["openstack"][0]["payload"]["id"] = "port-other"

        result = compare_source_target(self.source_fixture, target)

        self.assertIn("target port UUID mismatch: port-1", result.blockers)

    def test_target_port_must_reference_exact_source_network_uuid(self):
        target = deepcopy(self.ovs_target_fixture)
        target["openstack"][0]["payload"]["network_id"] = "network-other"

        result = compare_source_target(self.source_fixture, target)

        self.assertIn("target port network mismatch for port port-1", result.blockers)

    def test_unique_segment_tuple_and_ovs_dataplane_are_ready(self):
        result = compare_source_target(self.source_fixture, self.ovs_target_fixture)

        self.assertEqual([], result.blockers)
        self.assertTrue(result.checks)
        self.assertTrue(all(check.status == "PASS" for check in result.checks))

    def test_duplicate_matching_target_segment_blocks(self):
        target = deepcopy(self.ovs_target_fixture)
        duplicate = deepcopy(target["tables"]["networksegments"][0])
        duplicate["id"] = "target-segment-duplicate"
        target["tables"]["networksegments"].append(duplicate)

        result = compare_source_target(self.source_fixture, target)

        self.assertIn("target segment ambiguous for port port-1", result.blockers)

    def test_each_source_segment_signature_requires_one_target_match(self):
        source = deepcopy(self.source_fixture)
        source["tables"]["networksegments"].append(
            {
                "id": "segment-2", "network_id": "network-1",
                "network_type": "vlan", "physical_network": "physnet1",
                "segmentation_id": 202,
            }
        )
        source["tables"]["ml2_port_binding_levels"].append(
            {
                "port_id": "port-1", "host": "compute-023", "level": 1,
                "driver": "openvswitch", "segment_id": "segment-2",
            }
        )
        target = deepcopy(self.ovs_target_fixture)
        duplicate = deepcopy(target["tables"]["networksegments"][0])
        duplicate["id"] = "target-segment-duplicate"
        target["tables"]["networksegments"].append(duplicate)

        result = compare_source_target(source, target)

        self.assertTrue(
            any(
                reason in result.blockers
                for reason in (
                    "target segment missing for port port-1",
                    "target segment ambiguous for port port-1",
                )
            )
        )

    def test_duplicate_source_segment_tuple_blocks(self):
        source = deepcopy(self.source_fixture)
        duplicate = deepcopy(source["tables"]["networksegments"][0])
        duplicate["id"] = "segment-source-duplicate"
        source["tables"]["networksegments"].append(duplicate)
        source["tables"]["ml2_port_binding_levels"].append(
            {
                "port_id": "port-1", "host": "compute-023", "level": 1,
                "driver": "openvswitch", "segment_id": "segment-source-duplicate",
            }
        )

        result = compare_source_target(source, self.ovs_target_fixture)

        self.assertIn("source segment ambiguous for port port-1", result.blockers)

    def test_malformed_matching_segment_tuples_block(self):
        invalid_values = (
            {"network_type": ""},
            {"physical_network": []},
            {"segmentation_id": "101"},
            {"physical_network": "physnet1"},
            {"segmentation_id": 0},
        )

        for mutation in invalid_values:
            with self.subTest(mutation=mutation):
                source = deepcopy(self.source_fixture)
                target = deepcopy(self.ovs_target_fixture)
                source["tables"]["networksegments"][0].update(mutation)
                target["tables"]["networksegments"][0].update(mutation)

                result = compare_source_target(source, target)

                self.assertTrue(
                    any("segment tuple invalid" in item for item in result.blockers),
                    result.blockers,
                )

    def test_missing_source_ovs_port_evidence_is_unknown(self):
        source = deepcopy(self.source_fixture)
        source["runtime"]["nodes"] = [
            node for node in source["runtime"]["nodes"]
            if node["kind"] != "ovs_port"
        ]
        source["runtime"]["edges"] = [
            edge for edge in source["runtime"]["edges"]
            if not edge["source"].startswith("ovs_port:")
        ]

        result = compare_source_target(source, self.ovs_target_fixture)

        self.assertIn("source OVS port evidence missing for port port-1", result.unknowns)

    def test_target_runtime_blockers_and_unknowns_propagate(self):
        source = collect_from_fixture(self.source_fixture, ["port-1"])
        target = collect_from_fixture(self.ovs_target_fixture, ["port-1"])
        source_runtime = runtime_from_fixture(self.source_fixture)
        target_runtime = runtime_from_fixture(self.ovs_target_fixture)
        target_runtime.blockers.append("target OVS probe failed")
        target_runtime.unknowns.append("target OVS bridge unknown")

        result = compare_neutron_results(
            source, target, source_runtime, target_runtime, "ovs"
        )

        self.assertIn("target OVS probe failed", result.blockers)
        self.assertIn("target OVS bridge unknown", result.unknowns)

    def test_ovs_pairs_do_not_match_values_across_node_kinds(self):
        source = deepcopy(self.source_fixture)
        target = deepcopy(self.ovs_target_fixture)
        source["runtime"]["nodes"][0]["facts"]["source"] = "br-interface"
        source["runtime"]["nodes"][1]["facts"]["bridge"] = "br-port"
        target["runtime"]["nodes"][0]["facts"]["source"] = "br-port"
        target["runtime"]["nodes"][1]["facts"]["bridge"] = "br-interface"

        result = compare_source_target(source, target)

        self.assertIn("target OVS dataplane mismatch for port port-1", result.blockers)

    def test_malformed_ovs_container_values_fail_closed_without_exception(self):
        cases = (
            ("source", 0, "source", ["br-int"], "unknowns"),
            ("source", 1, "bridge", {"name": "br-int"}, "unknowns"),
            ("target", 0, "source", ["br-int"], "blockers"),
            ("target", 1, "bridge", {"name": "br-int"}, "blockers"),
        )
        for side, node_index, field, value, outcome in cases:
            with self.subTest(side=side, field=field, value=value):
                source = deepcopy(self.source_fixture)
                target = deepcopy(self.ovs_target_fixture)
                fixture = source if side == "source" else target
                fixture["runtime"]["nodes"][node_index]["facts"][field] = value

                result = compare_source_target(source, target)

                reasons = getattr(result, outcome)
                self.assertIn(
                    f"{side} OVS dataplane evidence malformed for port port-1",
                    reasons,
                )

    def test_malformed_ovs_scalar_strings_fail_closed(self):
        cases = (
            (0, "source", "   "),
            (0, "source", "br int"),
            (1, "bridge", "br/int"),
        )
        for node_index, field, value in cases:
            with self.subTest(field=field, value=value):
                target = deepcopy(self.ovs_target_fixture)
                target["runtime"]["nodes"][node_index]["facts"][field] = value

                result = compare_source_target(self.source_fixture, target)

                self.assertIn(
                    "target OVS dataplane evidence malformed for port port-1",
                    result.blockers,
                )

    def test_malformed_ovs_port_and_interface_names_fail_closed(self):
        for node_index, value in ((0, "tap/port-1"), (1, "tap port-1")):
            with self.subTest(node_index=node_index, value=value):
                target = deepcopy(self.ovs_target_fixture)
                node = target["runtime"]["nodes"][node_index]
                old_id = node["id"]
                old_key = f"{node['kind']}:{old_id}"
                node["id"] = value
                for edge in target["runtime"]["edges"]:
                    if edge["source"] == old_key:
                        edge["source"] = f"{node['kind']}:{value}"

                result = compare_source_target(self.source_fixture, target)

                self.assertIn(
                    "target OVS dataplane evidence malformed for port port-1",
                    result.blockers,
                )

    def test_ovn_logical_binding_and_chassis_are_ready(self):
        source = deepcopy(self.source_fixture)
        source["runtime"] = deepcopy(self.ovn_target_fixture["runtime"])

        result = compare_source_target(source, self.ovn_target_fixture)

        self.assertEqual([], result.blockers)
        self.assertTrue(any("ovn" in check.check_id for check in result.checks))

    def test_missing_ovn_chassis_blocks(self):
        source = deepcopy(self.source_fixture)
        source["runtime"] = deepcopy(self.ovn_target_fixture["runtime"])
        target = deepcopy(self.ovn_target_fixture)
        target["runtime"]["nodes"][0]["facts"]["chassis"] = ""

        result = compare_source_target(source, target)

        self.assertIn("target OVN chassis missing for port port-1", result.blockers)

    def test_missing_source_ovn_binding_evidence_is_unknown(self):
        source = deepcopy(self.source_fixture)
        source["runtime"] = {"nodes": [], "edges": []}

        result = compare_source_target(source, self.ovn_target_fixture)

        self.assertIn(
            "source OVN logical binding evidence missing for port port-1",
            result.unknowns,
        )

    def test_missing_source_ovn_chassis_evidence_is_unknown(self):
        source = deepcopy(self.source_fixture)
        source["runtime"] = deepcopy(self.ovn_target_fixture["runtime"])
        source["runtime"]["nodes"][0]["facts"]["chassis"] = ""

        result = compare_source_target(source, self.ovn_target_fixture)

        self.assertIn("source OVN chassis missing for port port-1", result.unknowns)

    def test_malformed_ovn_container_values_fail_closed_without_exception(self):
        cases = (
            ("source", "logical_port", {"id": "port-1"}, "unknowns"),
            ("source", "chassis", ["compute-023"], "unknowns"),
            ("target", "logical_port", {"id": "port-1"}, "blockers"),
            ("target", "chassis", ["compute-023"], "blockers"),
        )
        for side, field, value, outcome in cases:
            with self.subTest(side=side, field=field, value=value):
                source = deepcopy(self.source_fixture)
                source["runtime"] = deepcopy(self.ovn_target_fixture["runtime"])
                target = deepcopy(self.ovn_target_fixture)
                fixture = source if side == "source" else target
                fixture["runtime"]["nodes"][0]["facts"][field] = value

                result = compare_source_target(source, target)

                reasons = getattr(result, outcome)
                self.assertIn(
                    f"{side} OVN binding evidence malformed for port port-1",
                    reasons,
                )

    def test_malformed_ovn_scalar_strings_fail_closed(self):
        cases = (
            ("logical_port", "   "),
            ("logical_port", "port 1"),
            ("chassis", "   "),
            ("chassis", "compute/023"),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                source = deepcopy(self.source_fixture)
                source["runtime"] = deepcopy(self.ovn_target_fixture["runtime"])
                target = deepcopy(self.ovn_target_fixture)
                target["runtime"]["nodes"][0]["facts"][field] = value

                result = compare_source_target(source, target)

                self.assertIn(
                    "target OVN binding evidence malformed for port port-1",
                    result.blockers,
                )

    def test_matching_malformed_ovn_node_and_logical_port_fail_closed(self):
        source = deepcopy(self.source_fixture)
        source["runtime"] = deepcopy(self.ovn_target_fixture["runtime"])
        target = deepcopy(self.ovn_target_fixture)
        target["runtime"]["nodes"][0]["id"] = "port 1"
        target["runtime"]["nodes"][0]["facts"]["logical_port"] = "port 1"
        target["runtime"]["edges"][0]["source"] = "ovn_binding:port 1"

        result = compare_source_target(source, target)

        self.assertIn(
            "target OVN binding evidence malformed for port port-1",
            result.blockers,
        )

    def test_invalid_or_unsupported_backend_is_sanitized_unknown(self):
        cases = (
            None,
            {"token": "backend-dict-secret"},
            ["backend-list-secret"],
            "   ",
            "backend-string-secret",
        )
        for backend in cases:
            with self.subTest(backend=backend):
                result = compare_neutron_results(
                    collect_from_fixture(self.source_fixture, ["port-1"]),
                    collect_from_fixture(self.ovs_target_fixture, ["port-1"]),
                    runtime_from_fixture(self.source_fixture),
                    runtime_from_fixture(self.ovs_target_fixture),
                    backend,
                )
                serialized = json.dumps(result.to_dict())

                self.assertIn("network backend unsupported or invalid", result.unknowns)
                self.assertNotIn("backend-dict-secret", serialized)
                self.assertNotIn("backend-list-secret", serialized)
                self.assertNotIn("backend-string-secret", serialized)
                self.assertTrue(
                    any(check.status == "UNKNOWN" for check in result.checks)
                )


if __name__ == "__main__":
    unittest.main()
