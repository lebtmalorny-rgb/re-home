import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


class LiveDiscoverySchemaQueryTests(unittest.TestCase):
    def test_query_pack_quotes_only_strict_schema_identifiers(self):
        from live_discovery.schema_query import build_schema_query_pack

        pack = build_schema_query_pack(["nova", "cinder", "nova_api"])

        self.assertEqual(
            "openstack-rehome-schema-query-pack/v1alpha1",
            pack["schema_version"],
        )
        self.assertEqual(
            ["COLUMNS", "STATISTICS", "FOREIGN_KEYS"],
            [query["section"] for query in pack["queries"]],
        )
        for query in pack["queries"]:
            self.assertIn(
                "IN ('cinder', 'nova', 'nova_api')",
                query["sql"],
            )
            self.assertNotIn("IN (cinder, nova", query["sql"])
        self.assertIn("information_schema.COLUMNS", pack["queries"][0]["sql"])
        self.assertIn("information_schema.STATISTICS", pack["queries"][1]["sql"])
        self.assertIn("information_schema.KEY_COLUMN_USAGE", pack["queries"][2]["sql"])
        self.assertIn("information_schema.REFERENTIAL_CONSTRAINTS", pack["queries"][2]["sql"])
        self.assertIn("UPDATE_RULE", pack["queries"][2]["sql"])
        self.assertIn("DELETE_RULE", pack["queries"][2]["sql"])

    def test_query_pack_rejects_invalid_duplicate_and_unbounded_schema_names(self):
        from live_discovery.schema_query import build_schema_query_pack

        invalid = (
            [],
            ["nova", "nova"],
            ["nova-db"],
            ["nova' OR 1=1 --"],
            ["1nova"],
            ["a" * 65],
            ["nova", 7],
        )
        for names in invalid:
            with self.subTest(names=names), self.assertRaises(ValueError):
                build_schema_query_pack(names)

    def test_module_cli_emits_machine_validated_query_pack(self):
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "live_discovery.schema_query",
                "--databases-json",
                '["nova", "cinder"]',
            ],
            cwd=ROOT / "scripts",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(3, len(payload["queries"]))
        self.assertEqual(
            ["COLUMNS", "STATISTICS", "FOREIGN_KEYS"],
            [item["section"] for item in payload["queries"]],
        )

    def test_module_cli_rejects_sql_injection_without_emitting_queries(self):
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "live_discovery.schema_query",
                "--databases-json",
                '["nova); DROP TABLE instances; --"]',
            ],
            cwd=ROOT / "scripts",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(2, completed.returncode)
        self.assertEqual("", completed.stdout)
        self.assertIn("schema query input rejected", completed.stderr)


if __name__ == "__main__":
    unittest.main()
