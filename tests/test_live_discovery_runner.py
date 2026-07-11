from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from live_discovery.runner import MutationRejected, ProbeFailed, ReadOnlyRunner


class LiveDiscoveryRunnerTests(unittest.TestCase):
    def test_rejects_mutating_openstack_command_before_subprocess(self):
        runner = ReadOnlyRunner()
        with self.assertRaisesRegex(MutationRejected, "server set"):
            runner.run(["openstack", "server", "set", "instance-1"], "bad-command")

    def test_required_failure_raises_with_evidence(self):
        runner = ReadOnlyRunner()
        with self.assertRaises(ProbeFailed) as raised:
            runner.run(["false"], "required-failure")
        self.assertNotEqual(0, raised.exception.evidence.returncode)

    def test_sensitive_stdout_is_redacted(self):
        runner = ReadOnlyRunner()
        evidence = runner.run(["printf", "secret-token"], "token", sensitive_stdout=True)
        self.assertEqual("[REDACTED]", evidence.stdout)

    def test_rejects_mutation_nested_in_docker_exec(self):
        runner = ReadOnlyRunner()
        with self.assertRaisesRegex(MutationRejected, "server set"):
            runner.run(
                ["docker", "exec", "kolla_toolbox", "openstack", "server", "set", "instance-1"],
                "nested-mutation",
            )

    def test_mysql_requires_select_only_sql_entrypoint(self):
        runner = ReadOnlyRunner()
        with self.assertRaisesRegex(MutationRejected, "run_sql"):
            runner.run(["mysql", "--batch"], "unvalidated-mysql")
        with self.assertRaisesRegex(MutationRejected, "INSERT"):
            runner.run_sql(["mysql", "--batch"], "INSERT INTO nova.instances VALUES (1);", "insert")


if __name__ == "__main__":
    unittest.main()
