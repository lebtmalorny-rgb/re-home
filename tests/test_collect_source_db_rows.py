import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import collect_source_db_rows


def sample_db_import_plan():
    return {
        "resource_ids": {
            "instances": ["d6015a8d-e41f-4c8f-8765-b73c83f7f159"],
            "instance_names": ["instance-00000004"],
            "projects": ["4c5867676d6048af9f03bb846d4bdf70"],
            "users": ["cb91cdedff2046a4a350513d1ea1657f"],
            "networks": ["e1c2f8d7-33b8-44b8-8ea7-222b6be4c62b"],
            "subnets": ["e0b3e205-b767-46d3-9a5d-9b87b7bfe4d7"],
            "security_groups": ["0b394beb-8ca1-43e9-83a5-398309f5dfdb"],
            "ports": ["0333a723-8f93-4d00-a9c6-9a8af62c4c68"],
            "volumes": ["15c47caf-e3e0-4b14-86f0-a1bbc97d4256"],
            "rehome_hosts": ["os1-compute-02.example.local"],
        }
    }


class SourceDbRowCollectorTests(unittest.TestCase):
    def test_build_query_pack_contains_only_read_only_uuid_scoped_queries(self):
        query_pack = collect_source_db_rows.build_query_pack(sample_db_import_plan())
        service_names = [service["name"] for service in query_pack["services"]]

        self.assertEqual(service_names, ["keystone", "neutron", "cinder", "nova_api", "nova_cell"])
        neutron_sql = query_pack["services_by_name"]["neutron"]["sql"]
        nova_cell_sql = query_pack["services_by_name"]["nova_cell"]["sql"]

        self.assertIn("SELECT 'BEGIN neutron.standardattributes'", neutron_sql)
        self.assertLess(
            neutron_sql.index("SELECT 'BEGIN neutron.standardattributes'"),
            neutron_sql.index("SELECT 'BEGIN neutron.networks'"),
        )
        self.assertIn("SELECT 'BEGIN neutron.ports'", neutron_sql)
        self.assertIn("FROM `neutron`.`ports`", neutron_sql)
        self.assertIn("FROM `neutron`.`standardattributes`", neutron_sql)
        self.assertIn("'0333a723-8f93-4d00-a9c6-9a8af62c4c68'", neutron_sql)
        self.assertIn("SELECT 'BEGIN nova_api.host_mappings'", query_pack["services_by_name"]["nova_api"]["sql"])
        self.assertIn("FROM `nova_api`.`host_mappings`", query_pack["services_by_name"]["nova_api"]["sql"])
        self.assertIn("'os1-compute-02.example.local'", query_pack["services_by_name"]["nova_api"]["sql"])
        self.assertIn("FROM `nova`.`instances`", nova_cell_sql)
        self.assertIn("'d6015a8d-e41f-4c8f-8765-b73c83f7f159'", nova_cell_sql)

        all_sql = "\n".join(service["sql"] for service in query_pack["services"])
        forbidden = ["INSERT ", "UPDATE ", "DELETE ", "REPLACE ", "TRUNCATE ", "DROP ", "ALTER "]
        for word in forbidden:
            self.assertNotIn(word, all_sql.upper())

    def test_write_query_pack_creates_service_sql_files_and_manifest(self):
        query_pack = collect_source_db_rows.build_query_pack(sample_db_import_plan())
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = pathlib.Path(tmp)
            manifest = collect_source_db_rows.write_query_pack(query_pack, out_dir)

            self.assertTrue((out_dir / "queries" / "neutron.sql").is_file())
            self.assertTrue((out_dir / "queries" / "nova_cell.sql").is_file())
            self.assertTrue((out_dir / "source-db-row-query-manifest.json").is_file())
            self.assertEqual(manifest["services"][1]["sql_file"], "queries/neutron.sql")


if __name__ == "__main__":
    unittest.main()
