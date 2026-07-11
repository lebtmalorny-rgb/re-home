from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from live_discovery.contract import CheckResult, CollectorResult, ResourceNode
from live_discovery.graph import REQUIRED_COLLECTORS, assemble_graph, validate_graph
from live_discovery.verdict import compute_verdict


def clean_mapping():
    return {
        "schema_version": "openstack-rehome-directional-schema-mapping/v1alpha1",
        "source_profile": "keystack",
        "target_profile": "vanilla-openstack-2025.1-epoxy",
        "tables": {},
        "blockers": [],
    }


def complete_graph(*, status="PASS", reason="all required facts are ready"):
    results = []
    for side, service in REQUIRED_COLLECTORS:
        nodes = [ResourceNode(f"{service}_evidence", f"{side}-{service}", side)]
        checks = []
        if (side, service) == ("source", "nova"):
            nodes.append(ResourceNode("instance", "instance-1", "source"))
            checks.append(CheckResult("nova.source.ready", status, reason))
        results.append(CollectorResult(service=service, side=side, nodes=nodes, checks=checks))
    return assemble_graph(results)


class LiveDiscoveryVerdictTests(unittest.TestCase):
    def test_runtime_capabilities_are_a_required_target_collector(self):
        self.assertIn(("target", "runtime-capabilities"), REQUIRED_COLLECTORS)

    def test_unknown_is_fail_closed(self):
        graph = complete_graph()
        verdict = compute_verdict(
            graph, [CheckResult("probe", "UNKNOWN", "timeout")], clean_mapping()
        )
        self.assertEqual("UNKNOWN", verdict["verdict"])
        self.assertEqual(2, verdict["exit_code"])

    def test_blocked_has_precedence_over_unknown_and_warning(self):
        checks = [
            CheckResult("warn", "WARN", "historical image"),
            CheckResult("unknown", "UNKNOWN", "store probe unavailable"),
            CheckResult("blocked", "BLOCKED", "target segment missing"),
        ]

        verdict = compute_verdict(complete_graph(), checks, clean_mapping())

        self.assertEqual("BLOCKED", verdict["verdict"])
        self.assertEqual(3, verdict["exit_code"])

    def test_warning_maps_to_ready_with_warnings_and_exit_zero(self):
        verdict = compute_verdict(
            complete_graph(), [CheckResult("warn", "WARN", "historical image")], clean_mapping()
        )

        self.assertEqual("READY_WITH_WARNINGS", verdict["verdict"])
        self.assertEqual(0, verdict["exit_code"])
        self.assertEqual(1, verdict["counts"]["WARN"])
        self.assertEqual(["historical image"], verdict["reasons"]["WARN"])

    def test_ready_has_exact_counts_and_sorted_reasons(self):
        verdict = compute_verdict(complete_graph(), [], clean_mapping())

        self.assertEqual("READY", verdict["verdict"])
        self.assertEqual(0, verdict["exit_code"])
        self.assertEqual({"PASS": 1, "WARN": 0, "UNKNOWN": 0, "BLOCKED": 0}, verdict["counts"])
        self.assertEqual({"PASS": ["all required facts are ready"], "WARN": [], "UNKNOWN": [], "BLOCKED": []}, verdict["reasons"])

    def test_mapping_blocker_is_always_blocked(self):
        mapping = clean_mapping()
        mapping["blockers"] = ["nova.instances.vendor_field"]

        verdict = compute_verdict(complete_graph(), [], mapping)

        self.assertEqual("BLOCKED", verdict["verdict"])
        self.assertEqual(3, verdict["exit_code"])
        self.assertTrue(any("schema mapping blocker" in reason for reason in verdict["reasons"]["BLOCKED"]))

    def test_blocking_mapping_classifications_are_blocked(self):
        for classification in ("BLOCKED", "SEMANTIC_MISMATCH", "TARGET_VALUE_REQUIRED"):
            with self.subTest(classification=classification):
                mapping = clean_mapping()
                mapping["tables"] = {
                    "nova.instances": [{"column": "field", "classification": classification}]
                }
                verdict = compute_verdict(complete_graph(), [], mapping)
                self.assertEqual("BLOCKED", verdict["verdict"])

    def test_reviewed_source_only_mapping_is_warning(self):
        mapping = clean_mapping()
        mapping["tables"] = {
            "nova.instances": [{"column": "vendor_field", "classification": "SOURCE_ONLY_IGNORED"}]
        }

        verdict = compute_verdict(complete_graph(), [], mapping)

        self.assertEqual("READY_WITH_WARNINGS", verdict["verdict"])

    def test_duplicate_mapping_column_is_blocked(self):
        mapping = clean_mapping()
        mapping["tables"] = {
            "nova.instances": [
                {"column": "host", "classification": "COMMON_COMPATIBLE"},
                {"column": "host", "classification": "NORMALIZATION_REQUIRED"},
            ]
        }

        verdict = compute_verdict(complete_graph(), [], mapping)

        self.assertEqual("BLOCKED", verdict["verdict"])
        self.assertTrue(any(
            "mapping column is duplicated" in reason
            for reason in verdict["reasons"]["BLOCKED"]
        ))

    def test_missing_or_malformed_mapping_fails_closed(self):
        self.assertEqual(
            "UNKNOWN", compute_verdict(complete_graph(), [], None)["verdict"]
        )
        malformed = clean_mapping()
        malformed["tables"] = {"nova.instances": {"password": "do-not-leak"}}
        verdict = compute_verdict(complete_graph(), [], malformed)
        self.assertEqual("BLOCKED", verdict["verdict"])
        self.assertNotIn("do-not-leak", json.dumps(verdict, sort_keys=True))

    def test_missing_duplicate_and_empty_required_collectors_are_unknown(self):
        for mutation in ("missing", "duplicate", "empty"):
            with self.subTest(mutation=mutation):
                results = []
                for side, service in REQUIRED_COLLECTORS:
                    nodes = [ResourceNode(f"{service}_evidence", f"{side}-{service}", side)]
                    checks = []
                    if (side, service) == ("source", "nova"):
                        nodes.append(ResourceNode("instance", "instance-1", side))
                        checks.append(CheckResult("nova.source.ready", "PASS", "ready"))
                    if mutation == "missing" and (side, service) == ("target", "glance"):
                        continue
                    if mutation == "empty" and (side, service) == ("target", "glance"):
                        nodes = []
                    result = CollectorResult(service=service, side=side, nodes=nodes, checks=checks)
                    results.append(result)
                    if mutation == "duplicate" and (side, service) == ("target", "glance"):
                        results.append(deepcopy(result))
                verdict = compute_verdict(assemble_graph(results), [], clean_mapping())
                self.assertEqual("UNKNOWN", verdict["verdict"])

    def test_collector_blocker_and_unknown_propagate_with_precedence(self):
        unknown_graph = complete_graph()
        # Reassemble so the collector state is represented in provenance.
        results = []
        for side, service in REQUIRED_COLLECTORS:
            nodes = [ResourceNode(f"{service}_evidence", f"{side}-{service}", side)]
            checks = []
            result = CollectorResult(service=service, side=side, nodes=nodes, checks=checks)
            if (side, service) == ("source", "nova"):
                result.nodes.append(ResourceNode("instance", "instance-1", side))
                result.checks.append(CheckResult("nova.source.ready", "PASS", "ready"))
            if (side, service) == ("target", "glance"):
                result.unknowns.append("Glance probe unavailable")
            results.append(result)
        unknown_graph = assemble_graph(results)
        self.assertEqual("UNKNOWN", compute_verdict(unknown_graph, [], clean_mapping())["verdict"])

        results[-1].blockers.append("Glance store mismatch")
        blocked = compute_verdict(assemble_graph(results), [], clean_mapping())
        self.assertEqual("BLOCKED", blocked["verdict"])

    def test_no_instances_or_no_checks_is_unknown(self):
        results = []
        for side, service in REQUIRED_COLLECTORS:
            nodes = [ResourceNode(f"{service}_evidence", f"{side}-{service}", side)]
            checks = []
            if (side, service) == ("source", "nova"):
                checks.append(CheckResult("nova.source.ready", "PASS", "ready"))
            results.append(CollectorResult(service=service, side=side, nodes=nodes, checks=checks))
        graph = assemble_graph(results)
        self.assertEqual("UNKNOWN", compute_verdict(graph, [], clean_mapping())["verdict"])

        results = []
        for side, service in REQUIRED_COLLECTORS:
            nodes = [ResourceNode(f"{service}_evidence", f"{side}-{service}", side)]
            if (side, service) == ("source", "nova"):
                nodes.append(ResourceNode("instance", "instance-1", side))
            results.append(CollectorResult(service=service, side=side, nodes=nodes))
        self.assertEqual(
            "UNKNOWN", compute_verdict(assemble_graph(results), [], clean_mapping())["verdict"]
        )

    def test_conflicting_duplicate_check_ids_block(self):
        checks = [
            CheckResult("same", "PASS", "one"),
            CheckResult("same", "UNKNOWN", "two"),
        ]

        verdict = compute_verdict(complete_graph(), checks, clean_mapping())

        self.assertEqual("BLOCKED", verdict["verdict"])
        self.assertTrue(any("conflicting check definition" in reason for reason in verdict["reasons"]["BLOCKED"]))

    def test_permutations_produce_identical_verdict(self):
        checks = [
            CheckResult("z", "WARN", "z reason"),
            CheckResult("a", "PASS", "a reason"),
        ]
        mapping = clean_mapping()
        mapping["tables"] = {
            "z.table": [{"column": "z", "classification": "NORMALIZATION_REQUIRED"}],
            "a.table": [{"column": "a", "classification": "COMMON_COMPATIBLE"}],
        }
        reversed_mapping = deepcopy(mapping)
        reversed_mapping["tables"] = dict(reversed(list(mapping["tables"].items())))

        left = compute_verdict(complete_graph(), checks, mapping)
        right = compute_verdict(complete_graph(), list(reversed(checks)), reversed_mapping)

        self.assertEqual(left, right)

    def test_secret_bearing_malformed_reasons_are_redacted(self):
        checks = [
            CheckResult("bad", "BLOCKED", "password=do-not-serialize"),
            CheckResult(
                "token=do-not-serialize", "BLOCKED", "probe blocked",
                ["port:token=do-not-serialize"], ["password=do-not-serialize"],
            ),
        ]
        mapping = clean_mapping()
        mapping["blockers"] = ["token=also-do-not-serialize"]

        verdict = compute_verdict(complete_graph(), checks, mapping)
        serialized = json.dumps(verdict, sort_keys=True)

        self.assertNotIn("do-not-serialize", serialized)
        self.assertIn("[REDACTED]", serialized)


if __name__ == "__main__":
    unittest.main()
