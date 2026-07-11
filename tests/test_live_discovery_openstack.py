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
                return CommandEvidence(
                    evidence_id,
                    [*argv, "invalid-json-argv-secret"],
                    0,
                    "invalid-json-stdout-secret",
                    "invalid-json-stderr-secret",
                )

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
        serialized = str(raised.exception.evidence.to_dict())
        self.assertNotIn("invalid-json-argv-secret", serialized)
        self.assertNotIn("invalid-json-stdout-secret", serialized)
        self.assertNotIn("invalid-json-stderr-secret", serialized)
        self.assertEqual(["[REDACTED]"], raised.exception.evidence.argv)
        self.assertEqual("[REDACTED]", raised.exception.evidence.stdout)
        self.assertEqual("[REDACTED]", raised.exception.evidence.stderr)
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)

    def test_client_sanitizes_command_probe_failure(self):
        failure_evidence = CommandEvidence(
            "failed-command",
            ["openstack", "server", "show", "failure-argv-secret"],
            2,
            "failure-stdout-secret",
            "failure-stderr-secret",
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

        self.assertIsNot(failure_evidence, raised.exception.evidence)
        serialized = str(raised.exception.evidence.to_dict())
        self.assertNotIn("failure-argv-secret", serialized)
        self.assertNotIn("failure-stdout-secret", serialized)
        self.assertNotIn("failure-stderr-secret", serialized)
        self.assertEqual(["[REDACTED]"], raised.exception.evidence.argv)
        self.assertEqual("[REDACTED]", raised.exception.evidence.stdout)
        self.assertEqual("[REDACTED]", raised.exception.evidence.stderr)
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)

    def test_client_preserves_only_allowlisted_http_failure_status(self):
        failure_evidence = CommandEvidence(
            "barbican-failure",
            ["openstack", "secret", "get", "secret-uuid"],
            1,
            "",
            "ForbiddenException: 403 Client Error token=must-not-leak",
        )

        class FailingRunner:
            def run(self, argv, evidence_id, sensitive_stdout=False):
                raise ProbeFailed(failure_evidence)

        client = OpenStackClient(FailingRunner(), "cloud", "toolbox", "/clouds.yaml")
        with self.assertRaises(ProbeFailed) as raised:
            client.json(["secret", "get", "secret-uuid"], "barbican-failure")

        self.assertEqual(403, raised.exception.status_code)
        self.assertNotIn("must-not-leak", str(raised.exception.__dict__))
        self.assertEqual("[REDACTED]", raised.exception.evidence.stderr)

    def test_client_classifies_missing_endpoint_without_raw_error(self):
        failure_evidence = CommandEvidence(
            "barbican-endpoint",
            ["openstack", "secret", "get", "secret-uuid"],
            1,
            "",
            "public endpoint for key-manager service in RegionOne not found token=must-not-leak",
        )

        class FailingRunner:
            def run(self, argv, evidence_id, sensitive_stdout=False):
                raise ProbeFailed(failure_evidence)

        client = OpenStackClient(FailingRunner(), "cloud", "toolbox", "/clouds.yaml")
        with self.assertRaises(ProbeFailed) as raised:
            client.json(["secret", "get", "secret-uuid"], "barbican-endpoint")

        self.assertEqual("endpoint-missing", raised.exception.reason)
        self.assertNotIn("must-not-leak", str(raised.exception.__dict__))
        self.assertEqual("[REDACTED]", raised.exception.evidence.stderr)

    def test_missing_endpoint_takes_precedence_over_cooccurring_404(self):
        failure_evidence = CommandEvidence(
            "barbican-endpoint-404",
            ["openstack", "secret", "get", "secret-uuid"],
            1,
            "",
            "404: public endpoint for key-manager service not found token=must-not-leak",
        )

        class FailingRunner:
            def run(self, argv, evidence_id, sensitive_stdout=False):
                raise ProbeFailed(failure_evidence)

        client = OpenStackClient(FailingRunner(), "cloud", "toolbox", "/clouds.yaml")
        with self.assertRaises(ProbeFailed) as raised:
            client.json(["secret", "get", "secret-uuid"], "barbican-endpoint-404")
        self.assertEqual("endpoint-missing", raised.exception.reason)
        self.assertFalse(hasattr(raised.exception, "status_code"))
        self.assertNotIn("must-not-leak", str(raised.exception.__dict__))

    def test_client_sanitizes_raw_stdout_and_stderr_from_evidence(self):
        class SecretEvidenceRunner:
            def run(self, argv, evidence_id, sensitive_stdout=False):
                return CommandEvidence(
                    evidence_id,
                    list(argv),
                    0,
                    '{"id":"server-1","secret":"stdout-secret"}',
                    "stderr-secret",
                )

        client = OpenStackClient(
            SecretEvidenceRunner(),
            "cloud",
            "toolbox",
            "/clouds.yaml",
        )

        payload, evidence = client.json(["server", "show", "server-1"], "secret")

        self.assertEqual("stdout-secret", payload["secret"])
        self.assertNotIn("stdout-secret", str(evidence))
        self.assertNotIn("stderr-secret", str(evidence))
        self.assertEqual("[REDACTED]", evidence["stdout"])
        self.assertEqual("[REDACTED]", evidence["stderr"])


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

    def test_irrelevant_stale_or_future_nonzero_evidence_is_unknown(self):
        stale_timestamp = datetime.now(timezone.utc) - timedelta(days=2)
        future_timestamp = datetime.now(timezone.utc) + timedelta(hours=1)
        cases = (
            (
                "irrelevant",
                {"command": ["nova-manage", "db", "version"]},
                "nova online migration evidence command invalid",
            ),
            (
                "stale",
                {"timestamp": stale_timestamp.isoformat().replace("+00:00", "Z")},
                "nova online migration evidence stale",
            ),
            (
                "future",
                {"timestamp": future_timestamp.isoformat().replace("+00:00", "Z")},
                "nova online migration evidence timestamp is in the future",
            ),
        )

        for name, changes, expected_reason in cases:
            with self.subTest(name=name):
                outputs = self.fresh_manage_outputs()
                artifact = outputs["online_migration_evidence"]["nova"]
                artifact["returncode"] = 1
                artifact.update(changes)

                result = self.collect(outputs)
                check = next(
                    item
                    for item in result.checks
                    if item.check_id == "target.nova.online-data-migrations"
                )

                self.assertEqual("UNKNOWN", check.status)
                self.assertEqual(expected_reason, check.reason)
                self.assertNotIn(
                    "nova online migration evidence returncode is not 0",
                    result.blockers,
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

    def test_profile_allowlists_migration_services_and_artifact_fields(self):
        outputs = self.fresh_manage_outputs()
        outputs["online_migration_evidence"]["nova"].update(
            {
                "auth_token": "nova-secret-token",
                "stdout": "nova-secret-stdout",
                "stderr": "nova-secret-stderr",
            }
        )
        outputs["online_migration_evidence"]["unknown-service"] = {
            "evidence_id": "unknown-secret-evidence",
            "command": ["unknown-manage", "db", "online_data_migrations"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "returncode": 0,
            "password": "unknown-secret-password",
        }

        result = self.collect(outputs)

        profile_evidence = result.nodes[0].facts["online_migration_evidence"]
        self.assertEqual({"nova", "cinder"}, set(profile_evidence))
        self.assertEqual(
            {"evidence_id", "command", "timestamp", "returncode"},
            set(profile_evidence["nova"]),
        )
        serialized = json.dumps(result.to_dict(), sort_keys=True)
        for secret in (
            "nova-secret-token",
            "nova-secret-stdout",
            "nova-secret-stderr",
            "unknown-secret-evidence",
            "unknown-secret-password",
        ):
            self.assertNotIn(secret, serialized)

    def test_profile_omits_secret_bearing_invalid_command(self):
        outputs = self.fresh_manage_outputs()
        outputs["online_migration_evidence"]["nova"]["command"].append(
            "--password=command-secret"
        )

        result = self.collect(outputs)

        artifact = result.nodes[0].facts["online_migration_evidence"]["nova"]
        self.assertNotIn("command", artifact)
        self.assertNotIn("command-secret", json.dumps(result.to_dict()))
        check = next(
            item
            for item in result.checks
            if item.check_id == "target.nova.online-data-migrations"
        )
        self.assertEqual("UNKNOWN", check.status)
        self.assertEqual("nova online migration evidence command invalid", check.reason)


if __name__ == "__main__":
    unittest.main()
