import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / "playbooks" / "04j-ensure-neutron-ml2-binding-levels.yml"


class NeutronMl2BindingLevelsPlaybookTests(unittest.TestCase):
    def test_playbook_is_apply_gated_and_idempotent(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("target_neutron_ml2_binding_levels_apply: false", text)
        self.assertIn("target_neutron_ml2_binding_levels_apply | bool", text)
        self.assertIn("ml2_port_binding_levels", text)
        self.assertIn("ml2_port_bindings", text)
        self.assertIn("networksegments", text)
        self.assertIn("INSERT INTO `neutron`.`ml2_port_binding_levels`", text)
        self.assertIn("NOT EXISTS", text)
        self.assertIn("ROW_COUNT()", text)

    def test_playbook_derives_ports_from_current_manifest_shape(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("target_neutron_ml2_binding_manifest.rehome_instances", text)
        self.assertIn("target_neutron_ml2_binding_manifest.source.instances", text)
        self.assertIn("map(attribute='ports')", text)

    def test_playbook_only_targets_neutron_metadata(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertNotIn("docker stop", text)
        self.assertNotIn("docker run", text)
        self.assertNotIn("nova_compute", text)
        self.assertNotIn("neutron_openvswitch_agent", text)


if __name__ == "__main__":
    unittest.main()
