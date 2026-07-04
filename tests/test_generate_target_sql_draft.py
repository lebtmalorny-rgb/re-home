import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import generate_target_sql_draft


INFO_SCHEMA = """SERVICE:neutron
SECTION:COLUMNS
neutron\tports\t1\tid\tvarchar(36)\tNO\tNULL\t\tutf8mb3\tutf8mb3_general_ci
neutron\tports\t2\tnetwork_id\tvarchar(36)\tYES\tNULL\t\tutf8mb3\tutf8mb3_general_ci
SERVICE:nova_cell
SECTION:COLUMNS
nova\tinstances\t1\tid\tint(11)\tNO\tNULL\tauto_increment\tNULL\tNULL
nova\tinstances\t2\tuuid\tvarchar(36)\tNO\tNULL\t\tutf8mb3\tutf8mb3_general_ci
"""


def write_sample_rows(root):
    rows_dir = root / "rows"
    rows_dir.mkdir(parents=True)
    (rows_dir / "neutron.tsv").write_text(
        "BEGIN neutron.ports\n"
        "0333a723-8f93-4d00-a9c6-9a8af62c4c68\te1c2f8d7-33b8-44b8-8ea7-222b6be4c62b\n"
        "END neutron.ports\n",
        encoding="utf-8",
    )
    (rows_dir / "nova_cell.tsv").write_text(
        "BEGIN nova.instances\n"
        "42\td6015a8d-e41f-4c8f-8765-b73c83f7f159\n"
        "END nova.instances\n",
        encoding="utf-8",
    )
    return rows_dir


def sample_manifest():
    return {
        "services": [
            {"name": "neutron", "rows_file": "rows/neutron.tsv"},
            {"name": "nova_cell", "rows_file": "rows/nova_cell.tsv"},
        ]
    }


class TargetSqlDraftTests(unittest.TestCase):
    def test_generates_hard_stopped_insert_draft_from_rows_and_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            rows_dir = write_sample_rows(root)
            schema_path = root / "information-schema.tsv"
            schema_path.write_text(INFO_SCHEMA, encoding="utf-8")
            out_dir = root / "draft"

            schema = generate_target_sql_draft.parse_information_schema(schema_path)
            row_sections = generate_target_sql_draft.load_all_row_sections(sample_manifest(), root)
            summary = generate_target_sql_draft.write_draft_files(row_sections, schema, out_dir)

            neutron_sql = (out_dir / "20-neutron-networks-ports-sg.sql").read_text(encoding="utf-8")
            nova_sql = (out_dir / "50-nova-cell-instances-bdm-info-cache.sql").read_text(encoding="utf-8")

            self.assertIn("SIGNAL SQLSTATE '45000'", neutron_sql)
            self.assertIn("INSERT INTO `neutron`.`ports` (`id`, `network_id`) VALUES", neutron_sql)
            self.assertIn("'0333a723-8f93-4d00-a9c6-9a8af62c4c68'", neutron_sql)
            self.assertIn("REVIEW_REQUIRED: auto_increment columns: id", nova_sql)
            self.assertEqual(summary["files"][0]["row_count"], 1)
            self.assertEqual(summary["files"][1]["row_count"], 1)

            forbidden = ["UPDATE ", "DELETE ", "REPLACE ", "TRUNCATE ", "DROP ", "ALTER "]
            all_sql = neutron_sql.upper() + "\n" + nova_sql.upper()
            for word in forbidden:
                self.assertNotIn(word, all_sql)


if __name__ == "__main__":
    unittest.main()
