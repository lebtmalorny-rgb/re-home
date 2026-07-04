import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / "playbooks" / "11-cleanup-old-source-images.yml"
INVENTORY = ROOT / "inventory" / "lab-os1-to-os2.yml"
LOGIC_DOC = ROOT / "playbook-logic-ru.md"


class CleanupOldSourceImagesPlaybookTests(unittest.TestCase):
    def test_cleanup_is_report_only_by_default_and_requires_quarantine_artifact(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("source_runtime_image_cleanup_apply: false", text)
        self.assertIn("source_runtime_image_cleanup_require_quarantine_artifact: true", text)
        self.assertIn("source-quarantine.yml", text)
        self.assertIn("source_runtime_image_cleanup_apply | bool", text)

    def test_cleanup_removes_only_explicit_runtime_image_allowlist(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("source_runtime_cleanup_container_images", text)
        self.assertIn("source_runtime_switch_containers", text)
        self.assertIn("dataplane_keep_containers", text)
        self.assertIn("docker rmi \"$image\"", text)
        self.assertNotIn("docker image prune", text)
        self.assertNotIn("docker system prune", text)

    def test_cleanup_does_not_stop_or_remove_containers(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertNotIn("docker stop", text)
        self.assertNotIn("docker rm ", text)
        self.assertNotIn("docker rm\n", text)
        self.assertNotIn("docker run", text)
        self.assertIn("docker ps -a", text)

    def test_lab_inventory_defines_only_old_runtime_images_not_dataplane(self):
        text = INVENTORY.read_text(encoding="utf-8")

        self.assertIn("source_runtime_cleanup_container_images:", text)
        self.assertIn("nova_compute: quay.io/openstack.kolla/nova-compute:2025.1-rocky-9", text)
        self.assertIn(
            "neutron_openvswitch_agent: quay.io/openstack.kolla/neutron-openvswitch-agent:2025.1-rocky-9",
            text,
        )
        self.assertNotIn("nova_libvirt: quay.io/openstack.kolla/nova-libvirt:2025.1-rocky-9", text)
        self.assertNotIn("openvswitch_db: quay.io/openstack.kolla/openvswitch-db-server:2025.1-rocky-9", text)

    def test_doc_has_cleanup_section(self):
        text = LOGIC_DOC.read_text(encoding="utf-8")

        self.assertIn("### `11-cleanup-old-source-images.yml`", text)


if __name__ == "__main__":
    unittest.main()
