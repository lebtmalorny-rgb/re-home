import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / "playbooks" / "04k-ensure-nova-compute-service.yml"


class NovaComputeServicePlaybookTests(unittest.TestCase):
    def test_playbook_is_apply_gated_and_idempotent(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("target_nova_compute_service_apply: false", text)
        self.assertIn("target_nova_compute_service_apply | bool", text)
        self.assertIn("INSERT INTO `nova`.`services`", text)
        self.assertIn("NOT EXISTS", text)
        self.assertIn("ROW_COUNT()", text)
        self.assertIn("nova-compute", text)

    def test_playbook_uses_manifest_compute_service_uuid(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("target_nova_compute_service_manifest.source.compute_service", text)
        self.assertIn("target_nova_compute_service_source_service", text)
        self.assertIn("@service_uuid", text)

    def test_playbook_does_not_touch_runtime_containers(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertNotIn("docker stop", text)
        self.assertNotIn("docker run", text)
        self.assertNotIn("docker start", text)


if __name__ == "__main__":
    unittest.main()
