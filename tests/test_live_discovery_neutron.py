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

    def json(self, command, evidence_id, required=True):
        del required
        key = tuple(command)
        if key not in self.responses:
            raise AssertionError(f"unexpected OpenStack command: {command}")
        return deepcopy(self.responses[key]), {"id": evidence_id}

    def db_records(self, table):
        self.queried_tables.append(table)
        rows = [
            {"_schema": "neutron", "_table": table, "row": deepcopy(row)}
            for row in self.fixture.get("tables", {}).get(table, [])
        ]
        return rows, {"evidence_id": f"db-neutron-{table}"}


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

    def test_unsupported_backend_is_explicit_unknown(self):
        result = compare_source_target(
            self.source_fixture, self.ovs_target_fixture, backend="linuxbridge"
        )

        self.assertIn("unsupported network backend: linuxbridge", result.unknowns)
        self.assertTrue(any(check.status == "UNKNOWN" for check in result.checks))


if __name__ == "__main__":
    unittest.main()
