import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / "playbooks" / "04l-normalize-target-project-visibility.yml"
INVENTORY = ROOT / "inventory" / "lab-os1-to-os2.yml"
LOGIC_DOC = ROOT / "playbook-logic-ru.md"
HORIZON_DOC = ROOT / "horizon-rehome-visibility-ru.md"


class ProjectVisibilityNormalizationPlaybookTests(unittest.TestCase):
    def test_playbook_is_apply_gated_and_socket_based(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("target_project_visibility_normalize_apply: false", text)
        self.assertIn("target_project_visibility_normalize_apply | bool", text)
        self.assertNotIn("target_project_visibility_project_id: \"\"", text)
        self.assertNotIn("target_project_visibility_user_id: \"\"", text)
        self.assertIn("--socket={{ target_project_visibility_normalize_socket | quote }}", text)
        self.assertIn("--skip-column-names", text)
        self.assertIn("target_project_visibility_normalize_no_log: true", text)
        self.assertIn("target-project-visibility-normalization", text)
        self.assertIn("^updated\\t.*\\t[1-9][0-9]*$", text)

    def test_playbook_updates_all_project_scoped_services(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        expected_targets = [
            "`nova_api`.`instance_mappings`",
            "`nova_api`.`request_specs`",
            "`nova`.`instances`",
            "`neutron`.`networks`",
            "`neutron`.`subnets`",
            "`neutron`.`ports`",
            "`neutron`.`securitygroups`",
            "`neutron`.`securitygrouprules`",
            "`cinder`.`volumes`",
        ]
        for target in expected_targets:
            with self.subTest(target=target):
                self.assertIn(target, text)

        self.assertIn(
            "REPLACE(REPLACE(`spec`, @source_project_id, @target_project_id), @source_user_id, @target_user_id)",
            text,
        )

    def test_playbook_uses_manifest_scope_and_does_not_touch_runtime(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("target_project_visibility_manifest.source.instances", text)
        self.assertIn("target_project_visibility_instance_uuids", text)
        self.assertIn("target_project_visibility_port_ids", text)
        self.assertIn("target_project_visibility_volume_ids", text)
        self.assertNotIn("docker stop", text)
        self.assertNotIn("docker run", text)
        self.assertNotIn("docker start", text)

    def test_lab_inventory_defines_target_admin_identity(self):
        text = INVENTORY.read_text(encoding="utf-8")

        self.assertIn("target_project_visibility_project_id: b901604b49304f2bb64c42bd3bcf5512", text)
        self.assertIn("target_project_visibility_user_id: 9d209d661e2d456295236254b8caef17", text)

    def test_docs_reference_project_visibility_playbook(self):
        logic = LOGIC_DOC.read_text(encoding="utf-8")
        horizon = HORIZON_DOC.read_text(encoding="utf-8")

        self.assertIn("### `04l-normalize-target-project-visibility.yml`", logic)
        self.assertIn("04l-normalize-target-project-visibility.yml", horizon)


if __name__ == "__main__":
    unittest.main()
