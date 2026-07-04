import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / "playbooks" / "04h-normalize-target-metadata.yml"
INVENTORY = ROOT / "inventory" / "lab-os1-to-os2.yml"


class NormalizeTargetMetadataPlaybookTests(unittest.TestCase):
    def test_playbook_is_apply_gated_and_socket_based(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("target_metadata_normalize_apply: false", text)
        self.assertIn("target_metadata_normalize_allowed_targets:", text)
        self.assertIn("cinder.volumes.volume_type_id", text)
        self.assertNotIn("    target_metadata_normalizations: []", text)
        self.assertIn("--socket={{ target_metadata_normalize_socket | quote }}", text)
        self.assertIn("{% if target_metadata_normalize_apply | bool %}", text)
        self.assertIn("UPDATE `{{ item.schema }}`.`{{ item.table }}`", text)
        self.assertIn("--skip-column-names", text)
        self.assertIn("tee -a {{ target_metadata_normalize_remote_report_effective | quote }}", text)
        self.assertIn("target_metadata_normalize_sql_result.stdout_lines", text)
        self.assertIn("^updated\\t.*\\t[1-9][0-9]*$", text)

    def test_lab_inventory_maps_cinder_default_volume_type(self):
        text = INVENTORY.read_text(encoding="utf-8")

        self.assertIn("target_metadata_normalizations:", text)
        self.assertIn("table: volumes", text)
        self.assertIn("column: volume_type_id", text)
        self.assertIn("old: 59cbeca1-1937-4a44-be09-f612dc4d0373", text)
        self.assertIn("new: 81bf219f-8f67-493b-927f-215176983345", text)
        self.assertIn("where_column: id", text)
        self.assertIn("15c47caf-e3e0-4b14-86f0-a1bbc97d4256", text)


if __name__ == "__main__":
    unittest.main()
