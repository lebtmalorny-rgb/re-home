import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / "playbooks" / "04i-prepull-target-images.yml"
README = ROOT / "README.md"
LOGIC_DOC = ROOT / "playbook-logic-ru.md"


class PrepullTargetImagesPlaybookTests(unittest.TestCase):
    def test_playbook_pulls_inventory_defined_target_runtime_images(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("hosts: rehome_compute", text)
        self.assertIn("target_runtime_switch_container_images", text)
        self.assertIn("target_runtime_switch_containers", text)
        self.assertIn("docker", text)
        self.assertIn("pull", text)
        self.assertIn("image", text)
        self.assertIn("inspect", text)

    def test_playbook_records_digest_report_without_cutover_actions(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("target-image-digests.txt", text)
        self.assertIn("RepoDigests", text)
        self.assertIn("local_artifact_dir", text)
        self.assertNotIn("docker stop", text)
        self.assertNotIn("docker run", text)
        self.assertNotIn("rsync -a --delete", text)

    def test_documentation_lists_playbook_in_execution_order(self):
        readme = README.read_text(encoding="utf-8")
        logic_doc = LOGIC_DOC.read_text(encoding="utf-8")

        self.assertIn("playbooks/04i-prepull-target-images.yml", readme)
        self.assertIn("### `04i-prepull-target-images.yml`", logic_doc)


if __name__ == "__main__":
    unittest.main()
