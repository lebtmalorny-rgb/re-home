import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import prepare_target_sql_import


HARD_STOP_SQL = """-- DO NOT EXECUTE: target DB import draft for review only.
-- This file is generated from source DB rows and information_schema.
-- Review auto-increment IDs, foreign keys, target row existence and service-specific invariants.
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DO NOT EXECUTE: review and remove this hard-stop manually';
-- Service: neutron

-- BEGIN neutron.networks
INSERT INTO `neutron`.`networks` (`id`) VALUES ('net-1');
-- END neutron.networks
"""


class PrepareTargetSqlImportTests(unittest.TestCase):
    def test_refuses_hard_stopped_sql_without_explicit_strip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "draft"
            out = root / "prepared"
            source.mkdir()
            (source / "20-neutron.sql").write_text(HARD_STOP_SQL, encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "hard-stop"):
                prepare_target_sql_import.prepare_import(source, out, strip_hard_stop=False)

    def test_strips_hard_stop_and_preserves_insert(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "draft"
            out = root / "prepared"
            source.mkdir()
            (source / "20-neutron.sql").write_text(HARD_STOP_SQL, encoding="utf-8")

            manifest = prepare_target_sql_import.prepare_import(source, out, strip_hard_stop=True)
            prepared = (out / "20-neutron.sql").read_text(encoding="utf-8")

            self.assertNotIn("DO NOT EXECUTE", prepared)
            self.assertNotIn("SIGNAL SQLSTATE", prepared)
            self.assertIn("INSERT INTO `neutron`.`networks`", prepared)
            self.assertEqual(manifest["summary"]["files_prepared"], 1)
            self.assertEqual(manifest["summary"]["insert_statements"], 1)

    def test_skips_optional_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "draft"
            out = root / "prepared"
            source.mkdir()
            (source / "10-keystone.sql").write_text(HARD_STOP_SQL, encoding="utf-8")
            (source / "20-neutron.sql").write_text(HARD_STOP_SQL, encoding="utf-8")

            manifest = prepare_target_sql_import.prepare_import(
                source,
                out,
                strip_hard_stop=True,
                skip_files={"10-keystone.sql"},
            )

            self.assertFalse((out / "10-keystone.sql").exists())
            self.assertTrue((out / "20-neutron.sql").is_file())
            self.assertEqual(manifest["summary"]["files_skipped"], 1)

    def test_applies_literal_replacements(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "draft"
            out = root / "prepared"
            source.mkdir()
            (source / "40-nova-api.sql").write_text(
                HARD_STOP_SQL.replace("'net-1'", "'source-cell-id'"),
                encoding="utf-8",
            )

            manifest = prepare_target_sql_import.prepare_import(
                source,
                out,
                strip_hard_stop=True,
                literal_replacements={"source-cell-id": "target-cell-id"},
            )
            prepared = (out / "40-nova-api.sql").read_text(encoding="utf-8")

            self.assertIn("'target-cell-id'", prepared)
            self.assertNotIn("'source-cell-id'", prepared)
            self.assertEqual(manifest["summary"]["literal_replacements"], 1)

    def test_applies_table_column_replacements_without_touching_other_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "draft"
            out = root / "prepared"
            source.mkdir()
            (source / "40-nova-api.sql").write_text(
                "-- DO NOT EXECUTE\n"
                "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DO NOT EXECUTE';\n"
                "INSERT INTO `nova_api`.`instance_mappings` (`id`, `instance_uuid`, `cell_id`) "
                "VALUES ('4', 'inst-1', '4');\n",
                encoding="utf-8",
            )

            manifest = prepare_target_sql_import.prepare_import(
                source,
                out,
                strip_hard_stop=True,
                column_replacements={("nova_api", "instance_mappings", "cell_id"): "6"},
            )
            prepared = (out / "40-nova-api.sql").read_text(encoding="utf-8")

            self.assertIn("VALUES ('4', 'inst-1', '6');", prepared)
            self.assertEqual(manifest["summary"]["column_replacements"], 1)

    def test_rejects_destructive_sql(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "draft"
            out = root / "prepared"
            source.mkdir()
            (source / "20-neutron.sql").write_text("DELETE FROM `neutron`.`ports`;\n", encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "forbidden"):
                prepare_target_sql_import.prepare_import(source, out, strip_hard_stop=True)


if __name__ == "__main__":
    unittest.main()
