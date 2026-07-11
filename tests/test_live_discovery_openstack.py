from pathlib import Path
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from live_discovery.openstack import OpenStackClient, collect_target_profile
from live_discovery.runner import CommandEvidence, ProbeFailed


class FakeRunner:
    def __init__(self):
        self.commands = []

    def run(self, argv, evidence_id, sensitive_stdout=False):
        self.commands.append(list(argv))
        return type(
            "Evidence",
            (),
            {
                "stdout": '{"id":"server-1"}',
                "to_dict": lambda self: {"id": evidence_id},
            },
        )()


class NoCommandClient:
    class Runner:
        def run(self, argv, evidence_id, sensitive_stdout=False):
            raise AssertionError(f"unexpected command: {argv}")

    runner = Runner()

    def json(self, command, evidence_id, required=True):
        raise AssertionError(f"unexpected OpenStack command: {command}")


class OpenStackClientTests(unittest.TestCase):
    def test_kolla_client_builds_argv_without_shell(self):
        runner = FakeRunner()
        client = OpenStackClient(
            runner,
            "kolla-admin",
            "kolla_toolbox",
            "/tmp/clouds.yaml",
        )

        payload, evidence = client.json(
            ["server", "show", "server-1", "-f", "json"],
            "server-show",
        )

        self.assertEqual("server-1", payload["id"])
        self.assertEqual({"id": "server-show"}, evidence)
        self.assertEqual(
            [
                "docker",
                "exec",
                "-e",
                "OS_CLIENT_CONFIG_FILE=/tmp/clouds.yaml",
                "kolla_toolbox",
                "openstack",
                "--os-cloud",
            ],
            runner.commands[0][:7],
        )

    def test_client_appends_json_format_only_when_absent(self):
        runner = FakeRunner()
        client = OpenStackClient(runner, "cloud", "toolbox", "/clouds.yaml")

        client.json(["server", "list"], "implicit-format")
        client.json(["server", "list", "--format=json"], "explicit-format")

        self.assertEqual(["-f", "json"], runner.commands[0][-2:])
        self.assertEqual(1, runner.commands[1].count("--format=json"))
        self.assertNotIn("-f", runner.commands[1])

    def test_client_wraps_invalid_json_as_probe_failure(self):
        class InvalidJsonRunner:
            def run(self, argv, evidence_id, sensitive_stdout=False):
                return CommandEvidence(evidence_id, list(argv), 0, "not-json", "")

        client = OpenStackClient(
            InvalidJsonRunner(),
            "cloud",
            "toolbox",
            "/clouds.yaml",
        )

        with self.assertRaises(ProbeFailed) as raised:
            client.json(["server", "list"], "invalid-output")

        self.assertEqual("invalid-json", raised.exception.reason)
        self.assertIsInstance(raised.exception.evidence, CommandEvidence)

    def test_client_propagates_command_probe_failure(self):
        failure_evidence = CommandEvidence(
            "failed-command",
            ["openstack", "server", "list"],
            2,
            "",
            "permission denied",
        )

        class FailingRunner:
            def run(self, argv, evidence_id, sensitive_stdout=False):
                raise ProbeFailed(failure_evidence)

        client = OpenStackClient(
            FailingRunner(),
            "cloud",
            "toolbox",
            "/clouds.yaml",
        )

        with self.assertRaises(ProbeFailed) as raised:
            client.json(["server", "list"], "failed-command", required=False)

        self.assertIs(failure_evidence, raised.exception.evidence)


class TargetProfileTests(unittest.TestCase):
    def setUp(self):
        fixture_path = (
            ROOT
            / "tests"
            / "fixtures"
            / "live_discovery"
            / "openstack-command-results.json"
        )
        self.fixture = json.loads(fixture_path.read_text(encoding="utf-8"))

    def fresh_manage_outputs(self):
        outputs = deepcopy(self.fixture["manage_outputs"])
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        for artifact in outputs["online_migration_evidence"].values():
            artifact["timestamp"] = timestamp
        return outputs

    def collect(self, manage_outputs=None, image_inspects=None):
        return collect_target_profile(
            NoCommandClient(),
            self.fresh_manage_outputs() if manage_outputs is None else manage_outputs,
            (
                deepcopy(self.fixture["image_inspects"])
                if image_inspects is None
                else image_inspects
            ),
        )

    def test_collects_canonical_epoxy_profile_and_operator_evidence(self):
        result = self.collect()

        self.assertEqual("target-profile", result.service)
        self.assertEqual("target", result.side)
        self.assertEqual([], result.blockers)
        profile = result.nodes[0].facts
        self.assertEqual("2025.1", profile["release"])
        self.assertEqual("vanilla", profile["distribution"])
        self.assertEqual("b30f573d3377", profile["nova_api_db_version"])
        self.assertEqual("b30f573d3377", profile["nova_cell_db_version"])
        self.assertEqual(
            ["2025.1-expand", "2025.1-contract"],
            profile["neutron_heads"],
        )
        self.assertEqual("2025.1", profile["cinder_db_version"])
        self.assertEqual("2025.1", profile["glance_db_version"])
        self.assertEqual(
            "quay.io/openstack.kolla/nova-api:2025.1-ubuntu-noble",
            profile["container_images"]["nova_api"],
        )
        self.assertEqual(
            {"nova", "cinder"},
            set(profile["online_migration_evidence"]),
        )
        migration_checks = {
            check.check_id: check.status
            for check in result.checks
            if "online-data-migrations" in check.check_id
        }
        self.assertEqual(
            {
                "target.nova.online-data-migrations": "PASS",
                "target.cinder.online-data-migrations": "PASS",
            },
            migration_checks,
        )
        self.assertEqual(2, len(result.evidence))

    def test_noncanonical_distribution_or_release_adds_blocker(self):
        for field, value in (("distribution", "keystack"), ("release", "2024.2")):
            with self.subTest(field=field):
                outputs = self.fresh_manage_outputs()
                outputs[field] = value

                result = self.collect(outputs)

                self.assertTrue(
                    any(field in blocker for blocker in result.blockers),
                    result.blockers,
                )

    def test_missing_or_stale_online_migration_evidence_is_unknown(self):
        missing = self.fresh_manage_outputs()
        del missing["online_migration_evidence"]["nova"]
        missing_result = self.collect(missing)

        stale = self.fresh_manage_outputs()
        stale_timestamp = datetime.now(timezone.utc) - timedelta(days=2)
        stale["online_migration_evidence"]["cinder"]["timestamp"] = (
            stale_timestamp.isoformat().replace("+00:00", "Z")
        )
        stale_result = self.collect(stale)

        self.assertIn("nova online migration evidence missing", missing_result.unknowns)
        self.assertIn("cinder online migration evidence stale", stale_result.unknowns)
        self.assertEqual(
            "UNKNOWN",
            next(
                check.status
                for check in missing_result.checks
                if check.check_id == "target.nova.online-data-migrations"
            ),
        )
        self.assertEqual(
            "UNKNOWN",
            next(
                check.status
                for check in stale_result.checks
                if check.check_id == "target.cinder.online-data-migrations"
            ),
        )

    def test_nonzero_online_migration_evidence_is_blocked(self):
        outputs = self.fresh_manage_outputs()
        outputs["online_migration_evidence"]["nova"]["returncode"] = 1

        result = self.collect(outputs)

        self.assertIn("nova online migration evidence returncode is not 0", result.blockers)
        self.assertEqual(
            "BLOCKED",
            next(
                check.status
                for check in result.checks
                if check.check_id == "target.nova.online-data-migrations"
            ),
        )

    def test_irrelevant_or_future_online_migration_evidence_is_unknown(self):
        irrelevant = self.fresh_manage_outputs()
        irrelevant["online_migration_evidence"]["nova"]["command"] = [
            "nova-manage",
            "db",
            "version",
        ]
        irrelevant_result = self.collect(irrelevant)

        future = self.fresh_manage_outputs()
        future_timestamp = datetime.now(timezone.utc) + timedelta(hours=1)
        future["online_migration_evidence"]["cinder"]["timestamp"] = (
            future_timestamp.isoformat().replace("+00:00", "Z")
        )
        future_result = self.collect(future)

        self.assertIn(
            "nova online migration evidence command invalid",
            irrelevant_result.unknowns,
        )
        self.assertIn(
            "cinder online migration evidence timestamp is in the future",
            future_result.unknowns,
        )

    def test_missing_required_profile_facts_are_unknown(self):
        outputs = self.fresh_manage_outputs()
        del outputs["nova_api_db_version"]

        result = self.collect(outputs, {"nova_api": {"Config": {}}})

        self.assertIn("target profile fact nova_api_db_version missing", result.unknowns)
        self.assertIn("target container image nova_api missing", result.unknowns)


if __name__ == "__main__":
    unittest.main()
