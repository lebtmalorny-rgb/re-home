import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
FIXTURES = ROOT / "tests" / "fixtures" / "live_discovery"

from live_discovery.schema import (
    CLASSIFICATIONS,
    build_directional_mapping,
    parse_information_schema,
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


if __name__ == "__main__":
    unittest.main()
