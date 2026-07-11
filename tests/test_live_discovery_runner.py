from pathlib import Path
import sys
import unittest
from unittest.mock import patch

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

    @patch("live_discovery.runner.subprocess.run")
    def test_rejects_mutating_non_openstack_commands_before_subprocess(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = ""
        run.return_value.stderr = ""
        runner = ReadOnlyRunner()
        commands = [
            ["nova-manage", "db", "sync"],
            ["cinder-manage", "db", "sync"],
            ["rbd", "create", "volume-1"],
            ["ovs-vsctl", "set", "Interface", "tap-1", "external_ids:x=y"],
        ]

        for command in commands:
            with self.subTest(command=command):
                with self.assertRaises(MutationRejected):
                    runner.run(command, "non-openstack-mutation")
        run.assert_not_called()

    @patch("live_discovery.runner.subprocess.run")
    def test_rejects_mutating_non_openstack_command_nested_in_docker_exec(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = ""
        run.return_value.stderr = ""
        runner = ReadOnlyRunner()
        with self.assertRaisesRegex(MutationRejected, "db sync"):
            runner.run(
                ["docker", "exec", "nova_api", "nova-manage", "db", "sync"],
                "nested-nova-manage-mutation",
            )
        run.assert_not_called()

    @patch("live_discovery.runner.subprocess.run")
    def test_run_sql_rejects_sql_bearing_mysql_argv_before_subprocess(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = ""
        run.return_value.stderr = ""
        runner = ReadOnlyRunner()
        commands = [
            ["mysql", "--execute=DROP TABLE nova.instances"],
            ["mariadb", "-e", "DELETE FROM cinder.volumes"],
            ["mysql", "-eUPDATE nova.instances SET deleted = 1"],
            ["mysql", "-NeDROP TABLE nova.instances"],
            ["mysql", "--exec=DROP TABLE nova.instances"],
            ["mysql", "--init-command", "SET @probe = 1"],
            ["mariadb", "--init-command-add=INSERT INTO audit VALUES (1)"],
            [
                "docker", "exec", "mariadb", "mysql",
                "--execute", "DROP TABLE neutron.ports",
            ],
        ]

        for command in commands:
            with self.subTest(command=command):
                with self.assertRaisesRegex(MutationRejected, "SQL-bearing"):
                    runner.run_sql(command, "SELECT 1;", "sql-in-argv")
        run.assert_not_called()

    @patch("live_discovery.runner.subprocess.run")
    def test_run_sql_allows_non_sql_short_option_value_containing_e(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = "1\n"
        run.return_value.stderr = ""
        command = ["mysql", "-uservice", "--batch"]

        try:
            ReadOnlyRunner().run_sql(command, "SELECT 1;", "safe-short-option")
        except MutationRejected as error:
            self.fail(f"safe short option was rejected: {error}")

        run.assert_called_once_with(
            command,
            input="SELECT 1;",
            text=True,
            stdout=-1,
            stderr=-1,
            check=False,
        )

    @patch("live_discovery.runner.subprocess.run")
    def test_sensitive_evidence_redacts_token_from_argv_and_stderr(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = "secret-token"
        run.return_value.stderr = "authentication token secret-token rejected"
        command = ["printf", "secret-token"]

        evidence = ReadOnlyRunner().run(command, "token", sensitive_stdout=True)

        self.assertNotIn("secret-token", str(evidence.to_dict()))
        self.assertEqual("[REDACTED]", evidence.stdout)
        run.assert_called_once_with(
            command,
            text=True,
            stdout=-1,
            stderr=-1,
            check=False,
        )

    @patch("live_discovery.runner.subprocess.run")
    def test_sensitive_evidence_redacts_password_and_cinder_connection_data(self, run):
        connection_data = (
            '{"connection_info":{"driver_volume_type":"rbd",'
            '"auth_password":"cinder-pass"}}'
        )
        command = [
            "openstack", "--os-password=cloud-pass", "volume", "show", connection_data,
        ]
        run.return_value.returncode = 0
        run.return_value.stdout = connection_data
        run.return_value.stderr = f"password=cloud-pass connection_info={connection_data}"

        evidence = ReadOnlyRunner().run(command, "cinder", sensitive_stdout=True)
        serialized = str(evidence.to_dict())

        self.assertNotIn("cloud-pass", serialized)
        self.assertNotIn("cinder-pass", serialized)
        run.assert_called_once_with(
            command,
            text=True,
            stdout=-1,
            stderr=-1,
            check=False,
        )

    @patch("live_discovery.runner.subprocess.run")
    def test_sensitive_evidence_redacts_cinder_connection_payload_without_credentials(self, run):
        connection_data = (
            '{"driver_volume_type":"iscsi","data":{'
            '"target_portal":"10.0.0.5:3260",'
            '"target_iqn":"iqn.2026-07.example:volume-1"}}'
        )
        command = ["openstack", "volume", "show", connection_data]
        run.return_value.returncode = 0
        run.return_value.stdout = connection_data
        run.return_value.stderr = ""

        evidence = ReadOnlyRunner().run(command, "cinder", sensitive_stdout=True)

        self.assertNotIn("10.0.0.5:3260", str(evidence.to_dict()))
        self.assertNotIn("iqn.2026-07.example:volume-1", str(evidence.to_dict()))
        run.assert_called_once_with(
            command,
            text=True,
            stdout=-1,
            stderr=-1,
            check=False,
        )


if __name__ == "__main__":
    unittest.main()
