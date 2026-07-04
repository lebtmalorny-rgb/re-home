import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / "playbooks" / "10-source-quarantine.yml"
LOGIC_DOC = ROOT / "playbook-logic-ru.md"


class SourceQuarantinePlaybookTests(unittest.TestCase):
    def test_quarantine_is_apply_gated_and_requires_target_enable_artifact(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("source_quarantine_apply: false", text)
        self.assertIn("source_quarantine_apply | bool", text)
        self.assertIn("source_quarantine_require_target_enable_artifact: true", text)
        self.assertIn("target-enable-compute-service.yml", text)

    def test_quarantine_uses_source_kolla_toolbox_and_cleans_credentials(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("source_clouds_file_local", text)
        self.assertIn("OS_CLIENT_CONFIG_FILE", text)
        self.assertIn("openstack --os-cloud {{ source_cloud_name | quote }}", text)
        self.assertIn("source_quarantine_openstack_cli_container", text)
        self.assertIn("docker exec -u 0 {{ source_quarantine_openstack_cli_container | quote }} rm -f", text)
        self.assertIn("path: \"{{ source_quarantine_clouds_remote }}\"", text)
        self.assertIn("state: absent", text)

    def test_quarantine_disables_source_service_and_locks_source_servers(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("compute service set --disable", text)
        self.assertIn("--disable-reason", text)
        self.assertIn("compute service set --down", text)
        self.assertIn("server lock --reason", text)
        self.assertIn("--os-compute-api-version 2.73", text)
        self.assertIn("source_quarantine_force_down_compute_service: true", text)

    def test_quarantine_does_not_touch_dataplane_or_delete_metadata(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertNotIn("docker stop", text)
        self.assertNotIn("docker rm", text)
        self.assertNotIn("docker run", text)
        self.assertNotIn("server delete", text)
        self.assertNotIn("volume delete", text)
        self.assertNotIn("port delete", text)
        self.assertNotIn("DELETE FROM", text)
        self.assertIn("{{ runtime_guard_virsh_command }} list --name", text)

    def test_doc_has_source_quarantine_section(self):
        text = LOGIC_DOC.read_text(encoding="utf-8")

        self.assertIn("### `10-source-quarantine.yml`", text)


if __name__ == "__main__":
    unittest.main()
