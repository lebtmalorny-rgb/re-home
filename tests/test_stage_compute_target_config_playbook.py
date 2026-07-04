import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / "playbooks" / "05-stage-compute-target-config.yml"
NOVA_SAFE_TEMPLATE = ROOT / "templates" / "nova-rehome-safe.conf.j2"


class StageComputeTargetConfigPlaybookTests(unittest.TestCase):
    def test_domain_check_uses_runtime_guard_virsh_command(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("{{ runtime_guard_virsh_command }} list --name", text)
        self.assertNotIn("ansible.builtin.command: virsh list --name", text)

    def test_playbook_sets_effective_nova_safe_mode_defaults(self):
        playbook_text = PLAYBOOK.read_text(encoding="utf-8")
        template_text = NOVA_SAFE_TEMPLATE.read_text(encoding="utf-8")

        self.assertIn("nova_safe_mode_defaults:", playbook_text)
        self.assertIn("nova_safe_mode_effective:", playbook_text)
        self.assertIn("running_deleted_instance_action: noop", playbook_text)
        self.assertIn("sync_power_state_interval: -1", playbook_text)
        self.assertIn("enable_new_services: false", playbook_text)
        self.assertIn("handle_virt_lifecycle_events: false", playbook_text)
        self.assertIn("nova_safe_mode_effective.running_deleted_instance_action", template_text)
        self.assertNotIn("nova_safe_mode.running_deleted_instance_action", template_text)


if __name__ == "__main__":
    unittest.main()
