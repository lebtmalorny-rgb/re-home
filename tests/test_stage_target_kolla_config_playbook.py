import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / "playbooks" / "05b-stage-target-kolla-config.yml"
INVENTORY = ROOT / "inventory" / "lab-os1-to-os2.yml"
CUTOVER = ROOT / "playbooks" / "06-cutover-compute.yml"


class StageTargetKollaConfigPlaybookTests(unittest.TestCase):
    def test_playbook_fetches_reference_configs_and_stages_full_kolla_bundle(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("hosts: target_reference_compute[0]", text)
        self.assertIn("hosts: rehome_compute", text)
        self.assertIn("target_kolla_config_services:", text)
        self.assertIn("nova-compute", text)
        self.assertIn("neutron-openvswitch-agent", text)
        self.assertIn("cron", text)
        self.assertIn("kolla-toolbox", text)
        self.assertIn("nova-ssh", text)
        self.assertIn("config.json", text)
        self.assertIn("target_kolla_config_stage_dir", text)
        self.assertIn("target-config-stage/kolla", text)

    def test_playbook_rewrites_host_specific_values_and_safe_mode(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("running_deleted_instance_action", text)
        self.assertIn("sync_power_state_interval", text)
        self.assertIn("enable_new_services", text)
        self.assertIn("handle_virt_lifecycle_events", text)
        self.assertIn("openvswitch_agent.ini", text)
        self.assertIn("local_ip", text)
        self.assertIn("hostnqn", text)
        self.assertIn("auth.conf", text)
        self.assertIn("preserve re-home libvirt auth.conf", text)
        self.assertIn("target_kolla_config_reference_hostname", text)

    def test_lab_inventory_declares_reference_compute(self):
        text = INVENTORY.read_text(encoding="utf-8")

        self.assertIn("target_reference_compute:", text)
        self.assertIn("os2-compute-01:", text)
        self.assertIn("ansible_host: 192.168.10.78", text)
        self.assertIn("target_kolla_config_reference_hostname: os2-compute-01.example.local", text)

    def test_cutover_runs_target_containers_with_rehome_hostname(self):
        text = CUTOVER.read_text(encoding="utf-8")

        self.assertIn("'--hostname', rehome_host", text)


if __name__ == "__main__":
    unittest.main()
