import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "lab-topology-ru.md"
README = ROOT / "README.md"
INVENTORY = ROOT / "inventory" / "lab-os1-to-os2.yml"


class LabTopologyDocTests(unittest.TestCase):
    def test_topology_doc_records_lab_hosts_and_rehome_flow(self):
        text = DOC.read_text(encoding="utf-8")

        self.assertIn("```mermaid", text)
        self.assertIn("source_control", text)
        self.assertIn("target_control", text)
        self.assertIn("target_reference_compute", text)
        self.assertIn("rehome_compute", text)
        self.assertIn("192.168.10.74", text)
        self.assertIn("192.168.10.100", text)
        self.assertIn("nova_libvirt left on Rocky image", text)
        self.assertIn("runtime_guard_probe_targets", text)

    def test_readme_points_engineers_to_topology_and_inputs(self):
        text = README.read_text(encoding="utf-8")

        self.assertIn("docs/lab-topology-ru.md", text)
        self.assertIn("operator-inputs-ru.md", text)
        self.assertIn("playbook-logic-ru.md", text)
        self.assertIn("Что не коммитить", text)

    def test_lab_inventory_warns_about_lab_local_values(self):
        text = INVENTORY.read_text(encoding="utf-8")

        self.assertIn("Lab inventory for the os1 -> os2 re-home experiment", text)
        self.assertIn("Do not add plaintext passwords", text)
        self.assertIn("Lab-local staging and artifact paths", text)
        self.assertIn("runtime_guard_probe_targets", text)

    def test_topology_marks_nfs_as_lab_only_and_links_live_flow(self):
        text = DOC.read_text(encoding="utf-8")
        self.assertIn("только профиль текущего lab", text)
        self.assertIn("NFS/file", text)
        self.assertIn("RBD", text)
        self.assertIn("LVM", text)
        self.assertIn("iSCSI", text)
        self.assertIn("Fibre Channel", text)
        self.assertIn("[Поток live discovery](live-discovery-data-flow-ru.md)", text)

    def test_play_six_labels_both_delegates_with_cinder_and_glance_probes(self):
        text = DOC.read_text(encoding="utf-8")
        self.assertIn(
            "source Cinder backing + Glance Range probe — на `os1-compute-02`",
            text,
        )
        self.assertIn(
            "target Cinder backing + Glance Range probe — на `os2-ctrl-01`",
            text,
        )


if __name__ == "__main__":
    unittest.main()
