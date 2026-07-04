import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
DOC = ROOT / "neutron-rehome-behavior-ru.md"


class NeutronRehomeBehaviorDocTests(unittest.TestCase):
    def test_doc_records_ovs_not_bound_failure_mode(self):
        text = DOC.read_text(encoding="utf-8")

        self.assertIn("Device <port_uuid> is not bound", text)
        self.assertIn("ml2_port_binding_levels", text)
        self.assertIn("04j-ensure-neutron-ml2-binding-levels.yml", text)
        self.assertIn("openstack port show", text)
        self.assertIn("не заменяет `04j`", text)


if __name__ == "__main__":
    unittest.main()
