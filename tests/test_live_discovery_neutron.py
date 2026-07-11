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
    def __init__(self, fixture):
        self.fixture = deepcopy(fixture)
        self.responses = {
            tuple(item["command"]): deepcopy(item["payload"])
            for item in fixture["openstack"]
        }
        self.queried_tables = []
        self.queries = []

    def json(self, command, evidence_id, required=True):
        del required
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


def collect_from_fixture(fixture, port_ids):
    client = FixtureClient(fixture)
    result = NeutronCollector(
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

        result = NeutronCollector(
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

        result = NeutronCollector(client, "target", schema).collect(["port-1"])

        self.assertFalse(
            any("required Neutron table missing" in item for item in result.blockers)
        )

    def test_db_queries_are_acquired_with_explicit_active_root_filters(self):
        client = FixtureClient(self.source_fixture)

        result = NeutronCollector(
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

        result = NeutronCollector(
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

        result = NeutronCollector(
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

        result = NeutronCollector(
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

        result = NeutronCollector(
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

        result = NeutronCollector(
            SecretEvidenceClient(fixture), "source", schema_from_fixture(fixture)
        ).collect(["port-1"])
        serialized = json.dumps(result.to_dict())

        for secret in (
            "api-password", "api-token", "db-connection-secret", "db-token",
            "api-evidence-token", "nested-api-token", "nested-db-token",
            "nested-sg-token",
        ):
            self.assertNotIn(secret, serialized)

    def test_api_db_port_network_mismatch_blocks_before_merge(self):
        fixture = deepcopy(self.source_fixture)
        fixture["tables"]["ports"][0]["network_id"] = "network-db-other"

        result = collect_from_fixture(fixture, ["port-1"])

        self.assertIn("port API/DB network mismatch: port-1", result.blockers)

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

    def test_unsupported_backend_is_explicit_unknown(self):
        result = compare_source_target(
            self.source_fixture, self.ovs_target_fixture, backend="linuxbridge"
        )

        self.assertIn("unsupported network backend: linuxbridge", result.unknowns)
        self.assertTrue(any(check.status == "UNKNOWN" for check in result.checks))


if __name__ == "__main__":
    unittest.main()
