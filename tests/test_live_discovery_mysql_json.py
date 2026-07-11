from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from live_discovery.mysql_json import (
    build_json_row_query,
    uuid_in,
    validate_identifier,
    validate_select_only_sql,
)
from live_discovery.runner import MutationRejected


class MysqlJsonTransportTests(unittest.TestCase):
    def assert_cli_rejects(self, sql):
        with tempfile.TemporaryDirectory() as directory:
            sql_path = Path(directory) / "query.sql"
            sql_path.write_text(sql, encoding="utf-8")
            env = dict(os.environ, PYTHONPATH=str(ROOT / "scripts"))
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "live_discovery.mysql_json",
                    "--validate-sql",
                    str(sql_path),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                env=env,
            )
        self.assertNotEqual(0, completed.returncode, completed.stdout)

    def test_json_object_transport_preserves_text_fields(self):
        sql = build_json_row_query(
            "nova",
            "instance_info_caches",
            ["instance_uuid", "network_info"],
            uuid_in(
                "instance_uuid",
                ["11111111-1111-1111-1111-111111111111"],
            ),
        )

        self.assertIn(
            "JSON_OBJECT('instance_uuid', `instance_uuid`, "
            "'network_info', `network_info`)",
            sql,
        )
        self.assertIn("FROM `nova`.`instance_info_caches`", sql)
        self.assertNotIn("SELECT *", sql)
        self.assertTrue(sql.endswith(";"))

    def test_uuid_filter_rejects_non_uuid_input(self):
        with self.assertRaisesRegex(ValueError, "invalid UUID"):
            uuid_in("id", ["x' OR 1=1"])

    def test_uuid_filter_canonicalizes_literals(self):
        clause = uuid_in("id", ["11111111111111111111111111111111"])

        self.assertEqual(
            "`id` IN ('11111111-1111-1111-1111-111111111111')",
            clause,
        )

    def test_identifier_validation_rejects_unsafe_names(self):
        for value in ("", "1table", "nova.services", "name`", "name value"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "invalid identifier"):
                    validate_identifier(value)

    def test_select_validator_rejects_unsafe_or_malformed_sql(self):
        unsafe = (
            "SELECT 1; DELETE FROM nova.instances;",
            "SELECT 1; -- DELETE FROM nova.instances",
            "SELECT 1 INTO OUTFILE '/tmp/result';",
            "SELECT LOAD_FILE('/etc/passwd');",
            "SELECT FROM nova.instances;",
            "SELECT ;",
        )

        for sql in unsafe:
            with self.subTest(sql=sql):
                with self.assertRaises(MutationRejected):
                    validate_select_only_sql(sql)

    def test_select_validator_allows_semicolon_inside_string_literal(self):
        self.assertEqual(
            "SELECT ';' AS delimiter;",
            validate_select_only_sql("SELECT ';' AS delimiter;"),
        )

    def test_select_validator_ignores_clause_tokens_inside_string_literal(self):
        sql = "SELECT 'FROM, WHERE, IN';"

        self.assertEqual(sql, validate_select_only_sql(sql))

    def test_select_validator_rejects_unterminated_string_literal(self):
        with self.assertRaisesRegex(MutationRejected, "malformed"):
            validate_select_only_sql("SELECT 'unterminated;")

    def test_select_validator_rejects_into_dumpfile(self):
        with self.assertRaisesRegex(MutationRejected, "INTO DUMPFILE"):
            validate_select_only_sql("SELECT 1 INTO DUMPFILE '/tmp/result';")

    def test_cli_rejects_into_dumpfile(self):
        self.assert_cli_rejects("SELECT 1 INTO DUMPFILE '/tmp/result';")

    def test_select_validator_rejects_incomplete_clauses(self):
        malformed = (
            "SELECT * FROM;",
            "SELECT 1 WHERE;",
            "SELECT 1 IN;",
            "SELECT 1,;",
            "SELECT ,1;",
            "SELECT 1,,2;",
            "SELECT ();",
            "SELECT (1,);",
        )

        for sql in malformed:
            with self.subTest(sql=sql):
                with self.assertRaisesRegex(MutationRejected, "malformed"):
                    validate_select_only_sql(sql)

    def test_cli_rejects_incomplete_clauses(self):
        malformed = (
            "SELECT * FROM;",
            "SELECT 1 WHERE;",
            "SELECT 1 IN;",
            "SELECT 1,;",
            "SELECT ,1;",
            "SELECT 1,,2;",
            "SELECT ();",
            "SELECT (1,);",
        )

        for sql in malformed:
            with self.subTest(sql=sql):
                self.assert_cli_rejects(sql)

    def test_cli_validates_with_shared_select_only_validator(self):
        with tempfile.TemporaryDirectory() as directory:
            sql_path = Path(directory) / "query.sql"
            sql_path.write_text("SELECT JSON_OBJECT('value', 1);", encoding="utf-8")
            env = dict(os.environ, PYTHONPATH=str(ROOT / "scripts"))

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "live_discovery.mysql_json",
                    "--validate-sql",
                    str(sql_path),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                env=env,
            )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("SELECT_ONLY_OK\n", completed.stdout)


if __name__ == "__main__":
    unittest.main()
