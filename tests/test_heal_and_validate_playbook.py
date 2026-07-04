import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / "playbooks" / "08-heal-and-validate.yml"


class HealAndValidatePlaybookTests(unittest.TestCase):
    def test_validation_uses_kolla_nova_manage_container(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("docker exec nova_api nova-manage cell_v2 verify_instance", text)
        self.assertIn("docker exec nova_api nova-manage placement heal_allocations", text)
        self.assertIn("docker exec nova_api nova-manage placement audit", text)
        self.assertIn("failed_when: heal_allocations_results.rc not in [0, 1, 4]", text)
        self.assertNotIn("ansible.builtin.command: nova-manage", text)

    def test_validation_uses_kolla_toolbox_for_target_openstack_cli(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("target_clouds_file_local", text)
        self.assertIn("OS_CLIENT_CONFIG_FILE", text)
        self.assertIn("openstack --os-cloud {{ target_cloud_name | quote }}", text)
        self.assertIn("server list --long --name", text)
        self.assertIn("docker exec -u 0 {{ target_validation_openstack_cli_container | quote }} rm -f", text)
        self.assertIn("path: \"{{ target_validation_clouds_remote }}\"", text)
        self.assertIn("state: absent", text)

    def test_validation_artifact_path_does_not_require_rehome_id(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("rehome_id | default(rehome_host", text)
        self.assertNotIn("/var/backups/openstack-rehome/{{ rehome_id }}", text)

    def test_compute_local_validation_uses_runtime_guard_virsh_command(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("{{ runtime_guard_virsh_command }} list --name", text)
        self.assertIn("{{ runtime_guard_virsh_command }} qemu-agent-command", text)
        self.assertNotIn("virsh list --name", text)
        self.assertNotIn("virsh qemu-agent-command", text)


if __name__ == "__main__":
    unittest.main()
