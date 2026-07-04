import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import plan_db_metadata_import


def sample_manifest():
    return {
        "rehome_host": "os1-compute-02.example.local",
        "source": {
            "instances": [
                {
                    "uuid": "d6015a8d-e41f-4c8f-8765-b73c83f7f159",
                    "name": "os1-vm-100",
                    "instance_name": "instance-00000004",
                    "project_id": "4c5867676d6048af9f03bb846d4bdf70",
                    "user_id": "cb91cdedff2046a4a350513d1ea1657f",
                    "ports": [
                        {
                            "id": "0333a723-8f93-4d00-a9c6-9a8af62c4c68",
                            "network": {
                                "id": "e1c2f8d7-33b8-44b8-8ea7-222b6be4c62b",
                                "name": "lab-net",
                            },
                            "subnets": [
                                {
                                    "id": "e0b3e205-b767-46d3-9a5d-9b87b7bfe4d7",
                                    "name": "lab-subnet",
                                }
                            ],
                            "security_groups": [
                                {
                                    "id": "0b394beb-8ca1-43e9-83a5-398309f5dfdb",
                                    "name": "lab-access",
                                }
                            ],
                        }
                    ],
                    "volumes": [
                        {
                            "id": "15c47caf-e3e0-4b14-86f0-a1bbc97d4256",
                            "name": "os1-vm-100-root",
                        }
                    ],
                }
            ]
        },
    }


def sample_api_report():
    return {
        "summary": {
            "create_api_safe": 1,
            "requires_existing_or_db_import": 4,
            "db_import_only": 1,
        },
        "items": [
            {"resource_type": "flavor", "id": "lab.tiny", "action": "create_api_safe"},
            {
                "resource_type": "network",
                "id": "e1c2f8d7-33b8-44b8-8ea7-222b6be4c62b",
                "action": "requires_existing_or_db_import",
            },
            {
                "resource_type": "subnet",
                "id": "e0b3e205-b767-46d3-9a5d-9b87b7bfe4d7",
                "action": "requires_existing_or_db_import",
            },
            {
                "resource_type": "security_group",
                "id": "0b394beb-8ca1-43e9-83a5-398309f5dfdb",
                "action": "requires_existing_or_db_import",
            },
            {
                "resource_type": "port",
                "id": "0333a723-8f93-4d00-a9c6-9a8af62c4c68",
                "action": "requires_existing_or_db_import",
            },
            {
                "resource_type": "volume",
                "id": "15c47caf-e3e0-4b14-86f0-a1bbc97d4256",
                "action": "db_import_only",
            },
        ],
    }


class DbMetadataImportPlanTests(unittest.TestCase):
    def test_build_plan_maps_resources_to_reviewed_sql_blocks(self):
        plan = plan_db_metadata_import.build_plan(sample_manifest(), sample_api_report())
        blocks = {block["name"]: block for block in plan["blocks"]}

        self.assertEqual(plan["summary"]["instances"], 1)
        self.assertEqual(plan["summary"]["requires_reviewed_sql_files"], 5)
        self.assertEqual(
            plan["ordered_sql_files"],
            [
                "sql-skeleton/10-keystone-projects-users-optional.sql",
                "sql-skeleton/20-neutron-networks-ports-sg.sql",
                "sql-skeleton/30-cinder-volumes-attachments.sql",
                "sql-skeleton/40-nova-api-instance-mappings-request-specs.sql",
                "sql-skeleton/50-nova-cell-instances-bdm-info-cache.sql",
            ],
        )
        self.assertEqual(
            blocks["neutron_metadata"]["resource_ids"]["ports"],
            ["0333a723-8f93-4d00-a9c6-9a8af62c4c68"],
        )
        self.assertEqual(
            blocks["cinder_metadata"]["resource_ids"]["volumes"],
            ["15c47caf-e3e0-4b14-86f0-a1bbc97d4256"],
        )
        self.assertIn("instance_mappings", blocks["nova_api_metadata"]["tables"])
        self.assertIn("host_mappings", blocks["nova_api_metadata"]["tables"])
        self.assertEqual(
            blocks["nova_api_metadata"]["resource_ids"]["rehome_hosts"],
            ["os1-compute-02.example.local"],
        )
        self.assertIn("block_device_mapping", blocks["nova_cell_metadata"]["tables"])

    def test_render_sql_review_pack_writes_non_executable_skeletons(self):
        plan = plan_db_metadata_import.build_plan(sample_manifest(), sample_api_report())
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = pathlib.Path(tmp)
            written = plan_db_metadata_import.render_sql_review_pack(plan, out_dir)

            self.assertEqual(len(written), 5)
            neutron_sql = out_dir / "20-neutron-networks-ports-sg.sql"
            content = neutron_sql.read_text(encoding="utf-8")
            self.assertIn("DO NOT EXECUTE", content)
            self.assertIn("0333a723-8f93-4d00-a9c6-9a8af62c4c68", content)
            self.assertIn("e1c2f8d7-33b8-44b8-8ea7-222b6be4c62b", content)


if __name__ == "__main__":
    unittest.main()
