from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
FIXTURES = ROOT / "tests" / "fixtures" / "live_discovery"

from live_discovery.nova import NovaCollector


DB_TABLES = (
    "host_mappings",
    "cell_mappings",
    "instance_mappings",
    "request_specs",
    "instances",
    "block_device_mapping",
    "instance_info_caches",
    "compute_nodes",
    "services",
)


class FixtureClient:
    def __init__(self, fixture):
        self.has_cell_mapping_evidence = bool(fixture.get("cell_mappings"))
        self.db_facts = {
            table: deepcopy(fixture.get(table, [])) for table in DB_TABLES
        }
        self.responses = {
            tuple(item["command"]): deepcopy(item["payload"])
            for item in fixture["openstack"]
        }
        self.commands = []

    def json(self, command, evidence_id, required=True):
        del required
        key = tuple(command)
        self.commands.append(list(command))
        if key not in self.responses:
            raise AssertionError(f"unexpected OpenStack command: {command}")
        return deepcopy(self.responses[key]), {"id": evidence_id}


class DbRecordsFixtureClient(FixtureClient):
    def __init__(self, fixture, evidence_by_table):
        super().__init__(fixture)
        self.evidence_by_table = deepcopy(evidence_by_table)

    def db_records(self, table):
        evidence = self.evidence_by_table.get(
            table,
            {"evidence_id": f"db-{table}"},
        )
        return deepcopy(self.db_facts[table]), deepcopy(evidence)


def collect_from_fixture(fixture, rehome_host, side):
    client = FixtureClient(fixture)
    return NovaCollector(client, side).collect(rehome_host)


class NovaCollectorTests(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads(
            (FIXTURES / "nova-source.json").read_text(encoding="utf-8")
        )

    def test_nova_collector_roots_graph_at_exact_rehome_host(self):
        result = collect_from_fixture(self.fixture, "compute-023", "source")

        instances = [node for node in result.nodes if node.kind == "instance"]
        self.assertEqual(
            ["11111111-1111-1111-1111-111111111111"],
            [node.id for node in instances],
        )
        self.assertEqual("compute-023", instances[0].facts["host"])
        required_targets = {edge.target for edge in result.edges if edge.required}
        self.assertIn("cell_mapping:cell-source", required_targets)
        self.assertIn("flavor:flavor-1", required_targets)

    def test_resolves_cell_database_schema_without_serializing_credentials(self):
        fixture = deepcopy(self.fixture)
        fixture["cell_mappings"] = [{
            "_schema": "nova_api",
            "_table": "cell_mappings",
            "row": {
                "id": "cell-source",
                "uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "name": "cell1",
                "database_connection": (
                    "mysql+pymysql://nova:never-serialize@db.internal/nova_cell1"
                ),
            },
        }]

        result = collect_from_fixture(fixture, "compute-023", "source")

        cell = next(node for node in result.nodes if node.kind == "cell_mapping")
        self.assertEqual("nova_cell1", cell.facts["database_schema"])
        rendered = json.dumps(result.to_dict(), sort_keys=True)
        self.assertNotIn("never-serialize", rendered)
        self.assertNotIn("mysql+pymysql", rendered)

    def test_multi_cell_records_are_bound_to_resolved_cell_schema(self):
        fixture = deepcopy(self.fixture)
        fixture["cell_mappings"] = [{
            "_schema": "nova_api",
            "_table": "cell_mappings",
            "row": {
                "id": "cell-source",
                "uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "name": "cell1",
                "database_connection": "mysql://nova:secret@db/nova_cell1",
            },
        }]
        for table in (
            "instances", "block_device_mapping", "instance_info_caches",
            "compute_nodes", "services",
        ):
            for record in fixture[table]:
                record["_schema"] = "nova_cell1"
        client = FixtureClient(fixture)

        result = NovaCollector(
            client, "source", cell_schema="nova_cell1"
        ).collect("compute-023")

        self.assertEqual([], result.blockers)
        cell = next(node for node in result.nodes if node.kind == "cell_mapping")
        self.assertEqual("nova_cell1", cell.facts["database_schema"])

    def test_missing_instance_mapping_is_blocker(self):
        fixture = deepcopy(self.fixture)
        fixture["instance_mappings"] = []

        result = collect_from_fixture(fixture, "compute-023", "source")

        self.assertIn(
            "instance mapping missing: 11111111-1111-1111-1111-111111111111",
            result.blockers,
        )

    def test_emits_nova_nodes_and_uuid_only_downstream_dependencies(self):
        result = collect_from_fixture(self.fixture, "compute-023", "source")

        self.assertEqual(
            {
                "compute_host",
                "nova_service",
                "compute_node",
                "instance",
                "project",
                "user",
                "flavor",
                "image_ref",
                "cell_mapping",
                "request_spec",
                "placement_provider",
            },
            {node.kind for node in result.nodes},
        )
        targets = {edge.target for edge in result.edges}
        self.assertIn("port:33333333-3333-3333-3333-333333333333", targets)
        self.assertIn("volume:22222222-2222-2222-2222-222222222222", targets)
        self.assertIn("image_ref:image-1", targets)
        self.assertFalse(
            {"port", "volume", "network", "subnet"}
            & {node.kind for node in result.nodes}
        )

    def test_issues_only_required_host_scoped_openstack_commands(self):
        client = FixtureClient(self.fixture)

        NovaCollector(client, "source").collect("compute-023")

        instance_uuid = "11111111-1111-1111-1111-111111111111"
        self.assertEqual(
            [
                [
                    "server", "list", "--all-projects", "--host", "compute-023",
                    "--long", "-f", "json",
                ],
                ["compute", "service", "list", "--host", "compute-023", "-f", "json"],
                ["hypervisor", "show", "compute-023", "-f", "json"],
                ["resource", "provider", "list", "--name", "compute-023", "-f", "json"],
                ["server", "show", instance_uuid, "-f", "json"],
                ["flavor", "show", "flavor-1", "-f", "json"],
                ["resource", "provider", "allocation", "show", instance_uuid, "-f", "json"],
            ],
            client.commands,
        )

    def test_host_mismatch_is_blocker(self):
        fixture = deepcopy(self.fixture)
        fixture["openstack"][0]["payload"][0]["Host"] = "compute-099"

        result = collect_from_fixture(fixture, "compute-023", "source")

        self.assertIn(
            "instance host mismatch: 11111111-1111-1111-1111-111111111111 "
            "expected compute-023 got compute-099",
            result.blockers,
        )

    def test_missing_instance_db_row_is_blocker(self):
        fixture = deepcopy(self.fixture)
        fixture["instances"] = []

        result = collect_from_fixture(fixture, "compute-023", "source")

        self.assertIn(
            "instance DB row missing: 11111111-1111-1111-1111-111111111111",
            result.blockers,
        )

    def test_missing_cell_id_is_blocker(self):
        fixture = deepcopy(self.fixture)
        fixture["instance_mappings"][0]["row"]["cell_id"] = None

        result = collect_from_fixture(fixture, "compute-023", "source")

        self.assertIn(
            "cell mapping missing: 11111111-1111-1111-1111-111111111111",
            result.blockers,
        )

    def test_duplicate_canonical_service_is_blocker(self):
        fixture = deepcopy(self.fixture)
        duplicate = deepcopy(fixture["services"][0])
        duplicate["row"]["uuid"] = "service-duplicate"
        duplicate["row"]["id"] = 43
        fixture["services"].append(duplicate)

        result = collect_from_fixture(fixture, "compute-023", "source")

        self.assertIn("canonical nova service duplicate: compute-023", result.blockers)

    def test_duplicate_instance_uuid_is_blocker(self):
        fixture = deepcopy(self.fixture)
        fixture["openstack"][0]["payload"].append(
            deepcopy(fixture["openstack"][0]["payload"][0])
        )

        result = collect_from_fixture(fixture, "compute-023", "source")

        self.assertIn(
            "instance UUID duplicate: 11111111-1111-1111-1111-111111111111",
            result.blockers,
        )

    def test_invalid_volume_uuid_is_blocker_and_not_emitted(self):
        fixture = deepcopy(self.fixture)
        fixture["block_device_mapping"][0]["row"]["volume_id"] = "not-a-uuid"

        result = collect_from_fixture(fixture, "compute-023", "source")

        self.assertIn(
            "volume UUID invalid: 11111111-1111-1111-1111-111111111111 "
            "got 'not-a-uuid'",
            result.blockers,
        )
        self.assertNotIn("volume:not-a-uuid", {edge.target for edge in result.edges})

    def test_allocation_missing_selected_provider_is_blocker(self):
        fixture = deepcopy(self.fixture)
        fixture["openstack"][-1]["payload"] = {"allocations": {}}

        result = collect_from_fixture(fixture, "compute-023", "source")

        self.assertIn(
            "placement allocation missing: 11111111-1111-1111-1111-111111111111 "
            "provider aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            result.blockers,
        )

    def test_wrong_jsonl_schema_is_blocker(self):
        fixture = deepcopy(self.fixture)
        fixture["instances"][0]["_schema"] = "neutron"

        result = collect_from_fixture(fixture, "compute-023", "source")

        self.assertIn("DB JSONL record invalid: instances[0]", result.blockers)
        self.assertIn(
            "instance DB row missing: 11111111-1111-1111-1111-111111111111",
            result.blockers,
        )

    def test_bare_db_row_without_jsonl_envelope_is_blocker(self):
        fixture = deepcopy(self.fixture)
        fixture["instances"][0] = fixture["instances"][0]["row"]

        result = collect_from_fixture(fixture, "compute-023", "source")

        self.assertIn("DB JSONL record invalid: instances[0]", result.blockers)
        self.assertIn(
            "instance DB row missing: 11111111-1111-1111-1111-111111111111",
            result.blockers,
        )

    def test_invalid_port_uuid_is_blocker_and_not_emitted(self):
        fixture = deepcopy(self.fixture)
        fixture["instance_info_caches"][0]["row"]["network_info"] = (
            '[{"id":"not-a-uuid"}]'
        )

        result = collect_from_fixture(fixture, "compute-023", "source")

        self.assertIn(
            "port UUID invalid: 11111111-1111-1111-1111-111111111111 "
            "got 'not-a-uuid'",
            result.blockers,
        )
        self.assertNotIn("port:not-a-uuid", {edge.target for edge in result.edges})

    def test_missing_instance_info_cache_is_blocker(self):
        fixture = deepcopy(self.fixture)
        fixture["instance_info_caches"] = []

        result = collect_from_fixture(fixture, "compute-023", "source")

        self.assertIn(
            "instance info cache missing: 11111111-1111-1111-1111-111111111111",
            result.blockers,
        )

    def test_duplicate_instance_info_cache_is_blocker(self):
        fixture = deepcopy(self.fixture)
        fixture["instance_info_caches"].append(
            deepcopy(fixture["instance_info_caches"][0])
        )

        result = collect_from_fixture(fixture, "compute-023", "source")

        self.assertIn(
            "instance info cache duplicate: 11111111-1111-1111-1111-111111111111",
            result.blockers,
        )

    def test_deleted_instance_info_cache_is_blocker(self):
        fixture = deepcopy(self.fixture)
        fixture["instance_info_caches"][0]["row"]["deleted"] = 1

        result = collect_from_fixture(fixture, "compute-023", "source")

        self.assertIn(
            "instance info cache deleted: 11111111-1111-1111-1111-111111111111",
            result.blockers,
        )

    def test_malformed_instance_info_cache_is_blocker(self):
        fixture = deepcopy(self.fixture)
        fixture["instance_info_caches"][0]["row"]["network_info"] = "{not-json"

        result = collect_from_fixture(fixture, "compute-023", "source")

        self.assertIn(
            "instance info cache malformed: "
            "11111111-1111-1111-1111-111111111111",
            result.blockers,
        )

    def test_valid_empty_network_info_is_zero_ports_without_blocker(self):
        fixture = deepcopy(self.fixture)
        fixture["instance_info_caches"][0]["row"]["network_info"] = "[]"

        result = collect_from_fixture(fixture, "compute-023", "source")

        self.assertFalse(
            [item for item in result.blockers if "instance info cache" in item]
        )
        instance = next(node for node in result.nodes if node.kind == "instance")
        self.assertEqual([], instance.facts["port_ids"])
        self.assertFalse(
            [edge for edge in result.edges if edge.target.startswith("port:")]
        )

    def test_invalid_canonical_service_uuid_is_blocker(self):
        fixture = deepcopy(self.fixture)
        fixture["services"][0]["row"]["uuid"] = "not-a-uuid"

        result = collect_from_fixture(fixture, "compute-023", "source")

        self.assertIn(
            "canonical nova service UUID invalid: compute-023 got 'not-a-uuid'",
            result.blockers,
        )
        self.assertFalse([node for node in result.nodes if node.kind == "nova_service"])

    def test_invalid_compute_node_uuid_is_blocker(self):
        fixture = deepcopy(self.fixture)
        fixture["compute_nodes"][0]["row"]["uuid"] = "not-a-uuid"

        result = collect_from_fixture(fixture, "compute-023", "source")

        self.assertIn(
            "compute node UUID invalid: compute-023 got 'not-a-uuid'",
            result.blockers,
        )
        self.assertFalse([node for node in result.nodes if node.kind == "compute_node"])

    def test_missing_hypervisor_api_identity_is_blocker(self):
        fixture = deepcopy(self.fixture)
        del fixture["openstack"][2]["payload"]["id"]

        result = collect_from_fixture(fixture, "compute-023", "source")

        self.assertIn("hypervisor identity missing: compute-023", result.blockers)

    def test_numeric_hypervisor_api_identity_mismatch_is_blocker(self):
        fixture = deepcopy(self.fixture)
        fixture["openstack"][2]["payload"]["id"] = 999

        result = collect_from_fixture(fixture, "compute-023", "source")

        self.assertIn(
            "hypervisor identity mismatch: compute-023 API 999 DB 7",
            result.blockers,
        )

    def test_hypervisor_uuid_identity_matches_compute_node(self):
        fixture = deepcopy(self.fixture)
        fixture["openstack"][2]["payload"]["id"] = (
            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        )

        result = collect_from_fixture(fixture, "compute-023", "source")

        self.assertFalse(
            [item for item in result.blockers if "hypervisor identity" in item]
        )
        self.assertTrue([node for node in result.nodes if node.kind == "compute_node"])

    def test_hypervisor_uuid_identity_mismatch_is_blocker(self):
        fixture = deepcopy(self.fixture)
        fixture["openstack"][2]["payload"]["id"] = (
            "99999999-9999-9999-9999-999999999999"
        )

        result = collect_from_fixture(fixture, "compute-023", "source")

        self.assertIn(
            "hypervisor identity mismatch: compute-023 API "
            "99999999-9999-9999-9999-999999999999 DB "
            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            result.blockers,
        )

    def test_invalid_placement_provider_uuid_is_blocker(self):
        fixture = deepcopy(self.fixture)
        fixture["openstack"][3]["payload"][0]["uuid"] = "not-a-uuid"

        result = collect_from_fixture(fixture, "compute-023", "source")

        self.assertIn(
            "placement provider UUID invalid: compute-023 got 'not-a-uuid'",
            result.blockers,
        )
        self.assertFalse(
            [node for node in result.nodes if node.kind == "placement_provider"]
        )

    def test_malformed_db_records_evidence_mapping_is_blocker(self):
        client = DbRecordsFixtureClient(
            self.fixture,
            {"instances": {"returncode": 0}},
        )

        result = NovaCollector(client, "source").collect("compute-023")

        self.assertIn("DB evidence invalid: instances", result.blockers)
        self.assertNotIn("returncode", str(result.evidence))

    def test_list_db_records_evidence_is_blocker(self):
        client = DbRecordsFixtureClient(
            self.fixture,
            {"instances": [{"evidence_id": "db-instances"}]},
        )

        result = NovaCollector(client, "source").collect("compute-023")

        self.assertIn("DB evidence invalid: instances", result.blockers)
        self.assertNotIn("db-instances", str(result.evidence))

    def test_secret_bearing_db_records_evidence_is_canonicalized(self):
        secret = "db-password-secret"
        client = DbRecordsFixtureClient(
            self.fixture,
            {
                "instances": {
                    "evidence_id": "db-instances",
                    "argv": ["mysql", f"--password={secret}"],
                    "stdout": secret,
                    "arbitrary": {"token": secret},
                }
            },
        )

        result = NovaCollector(client, "source").collect("compute-023")

        serialized = str(result.to_dict())
        self.assertNotIn(secret, serialized)
        self.assertIn(
            {
                "evidence_id": "source-db:nova.instances",
                "kind": "db-jsonl",
                "schema": "nova",
                "table": "instances",
            },
            result.evidence,
        )

    def test_secret_bearing_db_evidence_id_is_discarded(self):
        evidence_id = "db-password-secret"
        client = DbRecordsFixtureClient(
            self.fixture,
            {"instances": {"evidence_id": evidence_id}},
        )

        result = NovaCollector(client, "source").collect("compute-023")

        self.assertNotIn(evidence_id, str(result.evidence))
        self.assertNotIn("DB evidence invalid: instances", result.blockers)
        self.assertIn(
            {
                "evidence_id": "source-db:nova.instances",
                "kind": "db-jsonl",
                "schema": "nova",
                "table": "instances",
            },
            result.evidence,
        )

    def test_opaque_secret_db_evidence_id_is_discarded(self):
        opaque_secret = "sk-proj-AbCdEf0123456789"
        client = DbRecordsFixtureClient(
            self.fixture,
            {"instances": {"evidence_id": opaque_secret}},
        )

        result = NovaCollector(client, "source").collect("compute-023")

        serialized = str(result.to_dict())
        self.assertNotIn(opaque_secret, serialized)
        self.assertIn("source-db:nova.instances", serialized)

    def test_target_fixture_collects_host_identity_without_instances(self):
        fixture = json.loads(
            (FIXTURES / "nova-target.json").read_text(encoding="utf-8")
        )

        result = collect_from_fixture(fixture, "compute-023", "target")

        self.assertEqual([], result.blockers)
        self.assertEqual([], [node for node in result.nodes if node.kind == "instance"])
        self.assertEqual(
            {"compute_host", "nova_service", "compute_node", "placement_provider"},
            {node.kind for node in result.nodes},
        )


if __name__ == "__main__":
    unittest.main()
