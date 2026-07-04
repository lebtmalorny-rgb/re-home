import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / "playbooks" / "09-enable-target-service.yml"


class EnableTargetServicePlaybookTests(unittest.TestCase):
    def test_enable_is_apply_gated_and_kolla_aware(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("target_enable_compute_apply: false", text)
        self.assertIn("target_enable_compute_apply | bool", text)
        self.assertIn("deployment_driver == 'kolla'", text)
        self.assertIn("target_clouds_file_local", text)
        self.assertIn("OS_CLIENT_CONFIG_FILE", text)
        self.assertIn("openstack --os-cloud {{ target_cloud_name | quote }}", text)
        self.assertIn("compute service set --enable {{ rehome_host | quote }} nova-compute", text)
        self.assertNotIn("source {{ openrc_file }}", text)
        self.assertNotIn("OS_CLOUD={{ target_os_cloud }}", text)

    def test_enable_is_idempotent_and_requires_validation_artifact(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("target_enable_compute_require_validation_artifact: true", text)
        self.assertIn("target-validation.yml", text)
        self.assertIn("target_compute_service_status_before", text)
        self.assertIn("'enabled' not in target_compute_service_status_before.stdout_lines", text)

    def test_enable_does_not_remove_safe_mode_or_restart_runtime(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("safe-mode remains installed", text)
        self.assertIn("{{ runtime_guard_virsh_command }} list --name", text)
        self.assertNotIn("docker restart", text)
        self.assertNotIn("docker stop", text)
        self.assertNotIn("kolla-ansible reconfigure", text)
        self.assertNotIn("ansible.builtin.systemd", text)
        self.assertNotIn("rm -f /etc/kolla/nova-compute", text)

    def test_enable_cleans_temporary_target_clouds_files(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("docker exec -u 0 {{ target_enable_compute_openstack_cli_container | quote }} rm -f", text)
        self.assertIn("path: \"{{ target_enable_compute_clouds_remote }}\"", text)
        self.assertIn("state: absent", text)


if __name__ == "__main__":
    unittest.main()
