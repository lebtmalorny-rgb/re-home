from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from live_discovery.contract import (
    CheckResult,
    CollectorResult,
    DependencyEdge,
    ResourceNode,
)
from live_discovery.graph import assemble_graph, validate_graph


def collector(service="nova", side="source", *, nodes=None, edges=None, checks=None):
    return CollectorResult(
        service=service,
        side=side,
        nodes=list(nodes or []),
        edges=list(edges or []),
        checks=list(checks or []),
    )


class LiveDiscoveryGraphTests(unittest.TestCase):
    def test_node_identity_includes_side_kind_and_id(self):
        source = collector(nodes=[ResourceNode("port", "same-id", "source", {"v": 1})])
        target = collector(
            "neutron", "target",
            nodes=[ResourceNode("port", "same-id", "target", {"v": 2})],
        )

        graph = assemble_graph([target, source])

        self.assertEqual(
            [("source", "port", "same-id"), ("target", "port", "same-id")],
            [(node["side"], node["kind"], node["id"]) for node in graph["nodes"]],
        )
        self.assertEqual("nova", graph["nodes"][0]["provenance"]["service"])

    def test_required_edge_resolves_only_on_its_collector_side(self):
        source = collector(
            nodes=[ResourceNode("instance", "vm-1", "source")],
            edges=[DependencyEdge("instance:vm-1", "volume:vol-1", "uses", True)],
        )
        target = collector(
            "cinder", "target", nodes=[ResourceNode("volume", "vol-1", "target")]
        )

        checks = validate_graph(assemble_graph([source, target]))

        self.assertTrue(any(
            check.status == "UNKNOWN"
            and "required edge target is unresolved" in check.reason
            and check.resource_ids == ["source:volume:vol-1"]
            for check in checks
        ))

    def test_optional_dangling_edge_is_warning_not_unknown(self):
        result = collector(
            nodes=[ResourceNode("volume", "vol-1", "source")],
            edges=[DependencyEdge("volume:vol-1", "snapshot:old", "historical", False)],
        )

        checks = validate_graph(assemble_graph([result]))

        dangling = [check for check in checks if "edge target is unresolved" in check.reason]
        self.assertEqual(["WARN"], [check.status for check in dangling])

    def test_only_explicitly_typed_external_reference_policy_resolves(self):
        node = ResourceNode("volume", "vol-1", "source")
        approved = collector(
            "cinder",
            nodes=[node],
            edges=[DependencyEdge(
                "volume:vol-1", "external_ref:keystone_secret/key-1",
                "uses_external_secret", True,
            )],
        )
        rejected = collector(
            "cinder",
            nodes=[deepcopy(node)],
            edges=[DependencyEdge(
                "volume:vol-1", "external_ref:keystone_secret/key-1",
                "unreviewed_relation", True,
            )],
        )

        approved_checks = validate_graph(assemble_graph([approved]))
        rejected_checks = validate_graph(assemble_graph([rejected]))

        self.assertFalse(any("edge target is unresolved" in check.reason for check in approved_checks))
        self.assertTrue(any("edge target is unresolved" in check.reason for check in rejected_checks))

    def test_identical_duplicates_coalesce(self):
        node = ResourceNode("port", "port-1", "source", {"mac": "aa"}, ["ev-1"])
        edge = DependencyEdge("port:port-1", "network:net-1", "uses", False)
        check = CheckResult("neutron.source.port", "PASS", "port is valid", ["port:port-1"])
        result = collector("neutron", nodes=[node, deepcopy(node)], edges=[edge, deepcopy(edge)], checks=[check, deepcopy(check)])

        graph = assemble_graph([result])
        checks = validate_graph(graph)

        self.assertEqual(1, len(graph["nodes"]))
        self.assertEqual(1, len(graph["edges"]))
        self.assertEqual(1, len(graph["checks"]))
        self.assertFalse(any("conflicting" in item.reason for item in checks))

    def test_duplicate_node_with_conflicting_facts_is_blocker_without_raw_values(self):
        first = ResourceNode("port", "port-1", "source", {"mac": "aa"})
        second = ResourceNode("port", "port-1", "source", {"mac": "do-not-serialize"})

        graph = assemble_graph([collector("neutron", nodes=[first, second])])
        checks = validate_graph(graph)

        self.assertTrue(any(
            item.status == "BLOCKED" and "node has conflicting facts" in item.reason
            for item in checks
        ))
        self.assertNotIn("do-not-serialize", json.dumps(graph, sort_keys=True))

    def test_conflicting_edge_requiredness_is_blocker(self):
        nodes = [
            ResourceNode("port", "port-1", "source"),
            ResourceNode("network", "net-1", "source"),
        ]
        edges = [
            DependencyEdge("port:port-1", "network:net-1", "uses", True),
            DependencyEdge("port:port-1", "network:net-1", "uses", False),
        ]

        checks = validate_graph(assemble_graph([collector("neutron", nodes=nodes, edges=edges)]))

        self.assertTrue(any(
            item.status == "BLOCKED" and "edge has conflicting requiredness" in item.reason
            for item in checks
        ))

    def test_duplicate_check_id_with_conflicting_status_reason_or_provenance_blocks(self):
        first = collector(
            "neutron", checks=[CheckResult("shared.id", "PASS", "same")]
        )
        second = collector(
            "cinder", checks=[CheckResult("shared.id", "UNKNOWN", "different")]
        )

        checks = validate_graph(assemble_graph([first, second]))

        self.assertTrue(any(
            item.status == "BLOCKED" and "check has conflicting definition" in item.reason
            for item in checks
        ))

    def test_conflicting_node_provenance_blocks(self):
        node = ResourceNode("project", "project-1", "source", {"id": "project-1"})

        checks = validate_graph(assemble_graph([
            collector("nova", nodes=[node]),
            collector("neutron", nodes=[deepcopy(node)]),
        ]))

        self.assertTrue(any(
            item.status == "BLOCKED" and "node has conflicting provenance" in item.reason
            for item in checks
        ))

    def test_collector_blockers_and_unknowns_become_checks(self):
        result = collector("cinder")
        result.blockers.append("backend identity mismatch")
        result.unknowns.append("backend capacity probe unavailable")

        checks = validate_graph(assemble_graph([result]))

        self.assertTrue(any(item.status == "BLOCKED" and item.reason == "backend identity mismatch" for item in checks))
        self.assertTrue(any(item.status == "UNKNOWN" and item.reason == "backend capacity probe unavailable" for item in checks))

    def test_malformed_and_deep_facts_do_not_crash_or_leak_values(self):
        deeply_nested = {"safe": []}
        cursor = deeply_nested["safe"]
        for _ in range(30):
            child = []
            cursor.append(child)
            cursor = child
        deeply_nested["password"] = "super-secret-value"
        malformed = ResourceNode("port", "port-1", "source", deeply_nested)

        graph = assemble_graph([collector("neutron", nodes=[malformed])])
        checks = validate_graph(graph)

        self.assertTrue(any(
            item.status == "BLOCKED" and "node payload is malformed" in item.reason
            for item in checks
        ))
        self.assertNotIn("super-secret-value", json.dumps(graph, sort_keys=True))

    def test_explicitly_redacted_sensitive_fact_is_preserved(self):
        node = ResourceNode(
            "volume_attachment",
            "attachment-1",
            "source",
            {
                "connection_info": "[REDACTED]",
                "connector": "[REDACTED]",
                "connection_summary": {"driver_volume_type": "rbd"},
            },
        )

        graph = assemble_graph([collector("cinder", nodes=[node])])

        self.assertEqual(1, len(graph["nodes"]))
        self.assertEqual("[REDACTED]", graph["nodes"][0]["facts"]["connection_info"])

    def test_unhashable_and_invalid_graph_payloads_return_checks_instead_of_crashing(self):
        graph = {
            "nodes": [{"side": [], "kind": "port", "id": {"secret": "x"}}],
            "edges": [{"side": "source", "source": {}, "target": [], "relation": "uses", "required": True}],
            "checks": "not-a-list",
            "collectors": [],
            "assembly_checks": [],
        }

        checks = validate_graph(graph)

        self.assertTrue(checks)
        self.assertTrue(any(check.status == "BLOCKED" for check in checks))
        self.assertNotIn("secret", " ".join(check.reason for check in checks).lower())

    def test_output_is_deterministic_under_collector_and_item_permutations(self):
        nodes = [
            ResourceNode("network", "net-1", "source", {"segments": [2, 1]}),
            ResourceNode("port", "port-1", "source", {"tags": ["b", "a"]}),
        ]
        edges = [DependencyEdge("port:port-1", "network:net-1", "uses", True)]
        checks = [CheckResult("neutron.source.ready", "PASS", "ready")]
        one = collector("neutron", nodes=nodes, edges=edges, checks=checks)
        two = collector("cinder", nodes=[ResourceNode("volume", "vol-1", "source")])

        left = assemble_graph([one, two])
        reversed_one = collector(
            "neutron", nodes=list(reversed(nodes)), edges=list(reversed(edges)), checks=list(reversed(checks))
        )
        right = assemble_graph([two, reversed_one])

        self.assertEqual(left, right)
        self.assertEqual(
            [item.to_dict() for item in validate_graph(left)],
            [item.to_dict() for item in validate_graph(right)],
        )

    def test_malformed_items_and_failure_reason_permutations_are_deterministic(self):
        valid = ResourceNode("port", "port-1", "source")
        malformed = ResourceNode("port", "bad", "target")
        left_result = collector("neutron", nodes=[valid, malformed])
        left_result.blockers = ["z blocker", "a blocker"]
        right_result = collector("neutron", nodes=[malformed, valid])
        right_result.blockers = ["a blocker", "z blocker"]

        self.assertEqual(
            assemble_graph([left_result]),
            assemble_graph([right_result]),
        )

    def test_bounded_generator_input_is_supported(self):
        result = collector(nodes=[ResourceNode("instance", "vm-1", "source")])

        graph = assemble_graph(item for item in [result])

        self.assertEqual(1, len(graph["nodes"]))

    def test_graph_hash_tampering_is_blocked_after_shape_validation(self):
        graph = assemble_graph([
            collector(nodes=[ResourceNode("instance", "vm-1", "source")])
        ])
        graph["nodes"][0]["facts"] = {"changed": True}

        checks = validate_graph(graph)

        self.assertTrue(any(
            check.status == "BLOCKED" and "graph integrity hash mismatch" in check.reason
            for check in checks
        ))

    def test_direct_graph_with_malformed_node_provenance_is_blocked(self):
        graph = assemble_graph([
            collector(nodes=[ResourceNode("instance", "vm-1", "source")])
        ])
        graph["nodes"][0]["provenance"] = {"service": "nova", "side": "target"}

        checks = validate_graph(graph)

        self.assertTrue(any(
            check.status == "BLOCKED" and "stored graph node is malformed" in check.reason
            for check in checks
        ))

    def test_secret_bearing_check_identifiers_are_not_serialized(self):
        unsafe = CheckResult(
            "token=do-not-serialize",
            "BLOCKED",
            "probe blocked",
            ["port:token=do-not-serialize"],
            ["password=do-not-serialize"],
        )

        graph = assemble_graph([collector("neutron", checks=[unsafe])])

        self.assertNotIn("do-not-serialize", json.dumps(graph, sort_keys=True))
        self.assertTrue(any(
            item["status"] == "BLOCKED" and item["reason"] == "check payload is malformed"
            for item in graph["assembly_checks"]
        ))

    def test_unhashable_check_status_is_blocked_in_assembly_and_validation(self):
        graph = assemble_graph([collector(
            checks=[CheckResult("bad", [], "bad")]
        )])
        self.assertTrue(any(
            item["reason"] == "check payload is malformed"
            for item in graph["assembly_checks"]
        ))

        valid = assemble_graph([collector(
            checks=[CheckResult("nova.source.ready", "PASS", "ready")]
        )])
        valid["checks"][0]["status"] = []
        checks = validate_graph(valid)
        self.assertTrue(any(
            item.status == "BLOCKED" and "stored graph check is malformed" in item.reason
            for item in checks
        ))

    def test_secret_bearing_identifiers_are_omitted_in_every_graph_position(self):
        sentinel = "secret-token"
        cases = []
        cases.append(CollectorResult(service=sentinel, side="source"))
        cases.append(CollectorResult(service="nova", side=sentinel))
        cases.append(collector(nodes=[ResourceNode(sentinel, "node-1", "source")]))
        cases.append(collector(nodes=[ResourceNode("instance", sentinel, "source")]))
        cases.append(collector(
            nodes=[ResourceNode("instance", "vm-1", "source")],
            edges=[DependencyEdge(sentinel, "instance:vm-1", "uses", True)],
        ))
        cases.append(collector(
            nodes=[ResourceNode("instance", "vm-1", "source")],
            edges=[DependencyEdge("instance:vm-1", sentinel, "uses", True)],
        ))
        cases.append(collector(
            nodes=[ResourceNode("instance", "vm-1", "source")],
            edges=[DependencyEdge("instance:vm-1", "instance:vm-1", sentinel, True)],
        ))
        cases.append(collector(checks=[CheckResult(sentinel, "BLOCKED", "blocked")]))
        cases.append(collector(checks=[CheckResult(
            "safe", "BLOCKED", "blocked", [sentinel], []
        )]))
        cases.append(collector(checks=[CheckResult(
            "safe", "BLOCKED", "blocked", [], [sentinel]
        )]))

        for result in cases:
            with self.subTest(result=result.service):
                graph = assemble_graph([result])
                self.assertNotIn(sentinel, json.dumps(graph, sort_keys=True))
                self.assertTrue(any(
                    item["status"] == "BLOCKED"
                    for item in graph["assembly_checks"]
                ))

    def test_unknown_top_level_and_nested_graph_fields_are_blocked(self):
        base = assemble_graph([collector(
            nodes=[ResourceNode("instance", "vm-1", "source")],
            edges=[DependencyEdge("instance:vm-1", "instance:vm-1", "self", False)],
            checks=[CheckResult("nova.source.ready", "PASS", "ready")],
        )])
        mutations = []
        top = deepcopy(base)
        top["unknown"] = "secret-token"
        mutations.append(top)
        for section in ("nodes", "edges", "checks", "collectors"):
            graph = deepcopy(base)
            graph[section][0]["unknown"] = "secret-token"
            mutations.append(graph)
        provenance = deepcopy(base)
        provenance["nodes"][0]["provenance"]["unknown"] = "secret-token"
        mutations.append(provenance)
        assembly_check = deepcopy(base)
        assembly_check["assembly_checks"] = [{
            **CheckResult("assembly", "BLOCKED", "blocked").to_dict(),
            "unknown": "secret-token",
        }]
        mutations.append(assembly_check)

        for graph in mutations:
            with self.subTest():
                checks = validate_graph(graph)
                self.assertTrue(any(item.status == "BLOCKED" for item in checks))
                self.assertNotIn(
                    "secret-token",
                    json.dumps([item.to_dict() for item in checks], sort_keys=True),
                )

    def test_direct_graph_with_malformed_check_provenance_is_blocked(self):
        graph = assemble_graph([collector(
            checks=[CheckResult("nova.source.ready", "PASS", "ready")]
        )])
        graph["checks"][0]["provenance"] = {"service": "nova", "side": "target"}

        checks = validate_graph(graph)

        self.assertTrue(any(
            check.status == "BLOCKED" and "stored graph check is malformed" in check.reason
            for check in checks
        ))

    def test_masakari_and_drs_collectors_are_rejected(self):
        for service in ("masakari", "drs"):
            with self.subTest(service=service):
                checks = validate_graph(assemble_graph([collector(service)]))
                self.assertTrue(any(
                    item.status == "BLOCKED" and "collector is outside discovery scope" in item.reason
                    for item in checks
                ))


if __name__ == "__main__":
    unittest.main()
