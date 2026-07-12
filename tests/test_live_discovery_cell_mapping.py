import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


class CellMappingEvidenceTests(unittest.TestCase):
    def test_query_is_host_scoped_and_sql_literal_is_escaped(self):
        from live_discovery.cell_mapping import build_cell_mapping_query

        sql = build_cell_mapping_query("compute-023.o'hare")

        self.assertIn("FROM nova_api.cell_mappings AS cm", sql)
        self.assertIn("JOIN nova_api.host_mappings AS hm", sql)
        self.assertIn("hm.host = 'compute-023.o''hare'", sql)
        self.assertNotIn("password", sql.lower())

    def test_parser_emits_only_sanitized_selected_cell(self):
        from live_discovery.cell_mapping import parse_cell_mapping_tsv

        raw = (
            "5\taaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\tcell1\t"
            "mysql+pymysql://nova:never-serialize@db.internal/nova_cell1\n"
        )
        result = parse_cell_mapping_tsv(raw, "compute-023")

        self.assertEqual("nova_cell1", result["database_schema"])
        self.assertEqual(5, result["id"])
        rendered = json.dumps(result, sort_keys=True)
        self.assertNotIn("never-serialize", rendered)
        self.assertNotIn("mysql+pymysql", rendered)

    def test_parser_rejects_ambiguous_or_malformed_connection(self):
        from live_discovery.cell_mapping import parse_cell_mapping_tsv

        valid = (
            "5\taaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\tcell1\t"
            "mysql://nova:secret@db/nova_cell1\n"
        )
        with self.assertRaisesRegex(ValueError, "exactly one"):
            parse_cell_mapping_tsv(valid + valid, "compute-023")
        with self.assertRaisesRegex(ValueError, "database schema"):
            parse_cell_mapping_tsv(
                "5\taaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\tcell1\t"
                "mysql://nova:secret@db/not/a/schema\n",
                "compute-023",
            )

    def test_source_playbook_collects_and_sanitizes_cell_before_api_phase(self):
        text = (
            ROOT / "playbooks" / "02b-discover-live-resource-graph.yml"
        ).read_text(encoding="utf-8")

        query = text.index("Source live discovery | build host-scoped Nova cell query")
        collect = text.index("Source live discovery | collect selected nova_api cell mapping")
        sanitize = text.index("Source live discovery | sanitize selected Nova cell mapping")
        api = text.index("Source live discovery | run initial signed API phase")
        self.assertLess(query, collect)
        self.assertLess(collect, sanitize)
        self.assertLess(sanitize, api)
        self.assertIn("--source-cell-mapping", text)
        self.assertIn("no_log: true", text[collect:api])


if __name__ == "__main__":
    unittest.main()
