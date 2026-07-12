import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
FIXTURES = ROOT / "tests" / "fixtures" / "live_discovery"

from live_discovery.schema import (
    CLASSIFICATIONS,
    SchemaSnapshot,
    build_directional_mapping,
    parse_information_schema,
    schema_capability,
)


class DirectionalSchemaMappingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_snapshot = parse_information_schema(
            FIXTURES / "source-information-schema.tsv"
        )
        cls.target_snapshot = parse_information_schema(
            FIXTURES / "target-information-schema.tsv"
        )
        cls.policy = json.loads(
            (FIXTURES / "schema-policy.json").read_text(encoding="utf-8")
        )

    def test_information_schema_parser_preserves_directional_metadata(self):
        column = self.source_snapshot.tables["nova.instances"]["progress"]

        self.assertEqual("integer unsigned", column.column_type)
        self.assertFalse(column.nullable)
        self.assertEqual("0", column.default)
        self.assertEqual("", column.extra)
        self.assertEqual(1, column.ordinal)

    def test_vendor_source_column_is_ignored_only_by_explicit_policy(self):
        mapping = build_directional_mapping(
            self.source_snapshot,
            self.target_snapshot,
            {"nova.services": ["uuid", "host", "admin_state"]},
            {"source_only_allowlist": ["nova.services.admin_state"]},
        )
        by_column = {
            item["column"]: item for item in mapping["tables"]["nova.services"]
        }

        self.assertEqual("COMMON_COMPATIBLE", by_column["uuid"]["classification"])
        self.assertEqual(
            "SOURCE_ONLY_IGNORED",
            by_column["admin_state"]["classification"],
        )
        self.assertEqual([], mapping["blockers"])

    def test_unreviewed_source_only_used_column_blocks(self):
        mapping = build_directional_mapping(
            self.source_snapshot,
            self.target_snapshot,
            {"cinder.volumes": ["id", "source_code"]},
            {"source_only_allowlist": []},
        )
        by_column = {
            item["column"]: item for item in mapping["tables"]["cinder.volumes"]
        }

        self.assertEqual("BLOCKED", by_column["source_code"]["classification"])
        self.assertIn("cinder.volumes.source_code", mapping["blockers"])

    def test_target_required_column_without_default_blocks(self):
        mapping = build_directional_mapping(
            self.source_snapshot,
            self.target_snapshot,
            {"cinder.volumes": ["id", "service_uuid"]},
            {"source_only_allowlist": []},
        )
        by_column = {
            item["column"]: item for item in mapping["tables"]["cinder.volumes"]
        }

        self.assertEqual(
            "TARGET_VALUE_REQUIRED",
            by_column["target_required"]["classification"],
        )
        self.assertEqual("TARGET_DEFAULT", by_column["created_at"]["classification"])
        self.assertIn("cinder.volumes.target_required", mapping["blockers"])

    def test_mapping_columns_follow_canonical_target_order(self):
        mapping = build_directional_mapping(
            self.source_snapshot,
            self.target_snapshot,
            {"cinder.volumes": ["service_uuid", "id"]},
            {"source_only_allowlist": []},
        )

        self.assertEqual(
            ["id", "service_uuid", "target_required", "created_at"],
            [item["column"] for item in mapping["tables"]["cinder.volumes"]],
        )

    def test_type_normalization_and_directional_special_cases(self):
        mapping = build_directional_mapping(
            self.source_snapshot,
            self.target_snapshot,
            {
                "nova.instances": ["progress", "task_state", "compute_id"],
                "nova_api.host_mappings": ["cell_id"],
            },
            self.policy,
        )
        instances = {
            item["column"]: item for item in mapping["tables"]["nova.instances"]
        }
        host_mappings = {
            item["column"]: item
            for item in mapping["tables"]["nova_api.host_mappings"]
        }

        self.assertEqual("COMMON_COMPATIBLE", instances["progress"]["classification"])
        self.assertEqual("SEMANTIC_MISMATCH", instances["task_state"]["classification"])
        self.assertEqual("NORMALIZATION_REQUIRED", instances["compute_id"]["classification"])
        self.assertEqual(
            "NORMALIZATION_REQUIRED",
            host_mappings["cell_id"]["classification"],
        )
        emitted = {
            item["classification"]
            for columns in mapping["tables"].values()
            for item in columns
        }
        self.assertLessEqual(emitted, CLASSIFICATIONS)

    def test_reviewed_policy_fixture_matches_inventory_policy(self):
        inventory_policy = json.loads(
            (ROOT / "inventory" / "live-discovery-schema-policy.json").read_text(
                encoding="utf-8"
            )
        )

        self.assertEqual(self.policy, inventory_policy)

    def test_parser_preserves_indexes_unique_constraints_and_foreign_key_actions(self):
        artifact = """SERVICE:source-control
SECTION:COLUMNS
nova\tinstances\t1\tid\tvarchar(36)\tNO\t\\N\t\\N
nova\tinstances\t2\thost_id\tint(11)\tNO\t\\N\t\\N
nova\thosts\t1\tid\tint(11)\tNO\t\\N\tauto_increment
SECTION:STATISTICS
nova\tinstances\tPRIMARY\t0\t1\tid\tBTREE
nova\tinstances\tuniq_host\t0\t1\thost_id\tBTREE
nova\thosts\tPRIMARY\t0\t1\tid\tBTREE
SECTION:FOREIGN_KEYS
nova\tinstances\tfk_instances_host\t1\thost_id\tnova\thosts\tid\tCASCADE\tRESTRICT
"""
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "information-schema.tsv"
            path.write_text(artifact, encoding="utf-8")

            snapshot = parse_information_schema(path)

        primary = snapshot.indexes["nova.instances"]["PRIMARY"]
        unique = snapshot.indexes["nova.instances"]["uniq_host"]
        foreign_key = snapshot.foreign_keys["nova.instances"]["fk_instances_host"]
        self.assertTrue(primary.unique)
        self.assertEqual(("id",), primary.columns)
        self.assertTrue(unique.unique)
        self.assertEqual(("host_id",), unique.columns)
        self.assertEqual(("host_id",), foreign_key.columns)
        self.assertEqual("nova.hosts", foreign_key.referenced_table)
        self.assertEqual(("id",), foreign_key.referenced_columns)
        self.assertEqual("CASCADE", foreign_key.update_rule)
        self.assertEqual("RESTRICT", foreign_key.delete_rule)

    def test_parser_rejects_invalid_constraint_metadata(self):
        base = """SERVICE:source-control
SECTION:COLUMNS
nova\tinstances\t1\tid\tvarchar(36)\tNO\t\\N\t\\N
SECTION:STATISTICS
{statistics}
SECTION:FOREIGN_KEYS
{foreign_keys}
"""
        cases = {
            "index gap": (
                "nova\tinstances\tPRIMARY\t0\t2\tid\tBTREE",
                "",
            ),
            "unknown index column": (
                "nova\tinstances\tPRIMARY\t0\t1\tmissing\tBTREE",
                "",
            ),
            "invalid uniqueness": (
                "nova\tinstances\tPRIMARY\t2\t1\tid\tBTREE",
                "",
            ),
            "unknown action": (
                "nova\tinstances\tPRIMARY\t0\t1\tid\tBTREE",
                "nova\tinstances\tfk_bad\t1\tid\tnova\tinstances\tid\tEXPLODE\tRESTRICT",
            ),
        }
        for name, (statistics, foreign_keys) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "information-schema.tsv"
                path.write_text(
                    base.format(statistics=statistics, foreign_keys=foreign_keys),
                    encoding="utf-8",
                )
                with self.assertRaises(ValueError):
                    parse_information_schema(path)

    def test_directional_capability_requires_complete_metadata_sections(self):
        incomplete = SchemaSnapshot(tables=self.source_snapshot.tables)
        with self.assertRaisesRegex(ValueError, "constraint metadata"):
            schema_capability(incomplete, {"nova.instances": ["progress"]})

        artifact = """SERVICE:target-control
SECTION:COLUMNS
nova\tinstances\t1\tid\tvarchar(36)\tNO\t\\N\t\\N
SECTION:STATISTICS
nova\tinstances\tPRIMARY\t0\t1\tid\tBTREE
SECTION:FOREIGN_KEYS
"""
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "information-schema.tsv"
            path.write_text(artifact, encoding="utf-8")
            complete_snapshot = parse_information_schema(path)
            capability = schema_capability(
                complete_snapshot,
                {"nova.instances": ["id"]},
            )

        self.assertEqual(
            {"tables", "indexes", "foreign_keys", "used_columns"},
            set(capability),
        )
        self.assertEqual(
            {
                "name": "PRIMARY",
                "unique": True,
                "columns": ["id"],
                "index_type": "BTREE",
            },
            capability["indexes"]["nova.instances"]["PRIMARY"],
        )
        with self.assertRaisesRegex(ValueError, "used schema columns"):
            schema_capability(
                complete_snapshot,
                {"nova.instances": ["missing"]},
            )


if __name__ == "__main__":
    unittest.main()
