from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
FIXTURES = ROOT / "tests" / "fixtures" / "live_discovery"

from live_discovery.cinder import CinderCollector


class ProbeError(RuntimeError):
    def __init__(self, status_code=None, reason=None):
        self.status_code = status_code
        self.reason = reason
        super().__init__("must-not-leak secret-token")


class FixtureClient:
    _fixture_only = True

    def __init__(self, fixture, failures=None):
        self.fixture = deepcopy(fixture)
        self.responses = {
            tuple(item["command"]): deepcopy(item["payload"])
            for item in fixture["openstack"]
        }
        self.failures = failures or {}
        self.commands = []
        self.queries = []

    def json(self, command, evidence_id, required=True):
        del required
        self.commands.append(deepcopy(command))
        if tuple(command) in self.failures:
            raise self.failures[tuple(command)]
        if tuple(command) not in self.responses:
            raise AssertionError(f"unexpected command: {command}")
        return deepcopy(self.responses[tuple(command)]), {"id": evidence_id}

    def db_records(self, table, filters=None):
        normalized = deepcopy(filters)
        self.queries.append((table, normalized))
        rows = deepcopy(self.fixture.get("tables", {}).get(table, []))
        if filters:
            rows = [
                row for row in rows
                if any(row.get(field) in values for field, values in filters.items())
            ]
        return [
            {"_schema": "cinder", "_table": table, "row": row}
            for row in rows
        ], {
            "evidence_id": f"{self.fixture.get('side', 'source')}-db:cinder.{table}",
            "schema": "cinder",
            "table": table,
            "filters": normalized,
        }


def schema_from_fixture(fixture):
    return {f"cinder.{table}": {} for table in fixture["schema_tables"]}


def collect_from_fixture(fixture, volume_ids=("volume-1",), failures=None):
    client = FixtureClient(fixture, failures)
    result = CinderCollector.for_fixture(
        client, fixture.get("side", "source"), schema_from_fixture(fixture)
    ).collect(list(volume_ids))
    return result, client


CANONICAL_IDS = {
    name: f"10000000-0000-0000-0000-{index:012d}"
    for index, name in enumerate(
        ("volume-1", "attachment-1", "type-1", "service-1", "key-1", "instance-1", "qos-1", "snapshot-1"),
        start=1,
    )
}


def canonical_fixture(fixture):
    def replace(value):
        if isinstance(value, str):
            return CANONICAL_IDS.get(value, value)
        if isinstance(value, list):
            return [replace(item) for item in value]
        if isinstance(value, dict):
            return {key: replace(item) for key, item in value.items()}
        return value

    return replace(deepcopy(fixture))


class CinderCollectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_fixture = json.loads(
            (FIXTURES / "cinder-source.json").read_text(encoding="utf-8")
        )

    def test_encrypted_volume_requires_complete_dependency_graph(self):
        result, _ = collect_from_fixture(self.source_fixture)
        targets = {
            edge.target for edge in result.edges
            if edge.source == "volume:volume-1" and edge.required
        }
        self.assertEqual(
            {
                "volume_attachment:attachment-1",
                "volume_type:type-1",
                "cinder_service:service-1",
                "encryption_key_ref:key-1",
                "storage_backend:nfs-1",
            },
            targets,
        )
        self.assertEqual([], result.blockers)

    def test_missing_encryption_key_uuid_is_blocker(self):
        fixture = deepcopy(self.source_fixture)
        fixture["tables"]["volumes"][0]["encryption_key_id"] = None
        result, _ = collect_from_fixture(fixture)
        self.assertIn("encrypted volume volume-1 has no key UUID", result.blockers)

    def test_database_acquisition_is_scoped_and_provenanced(self):
        result, client = collect_from_fixture(self.source_fixture)
        self.assertEqual([], result.blockers)
        self.assertTrue(client.queries)
        self.assertTrue(all(filters for _, filters in client.queries))
        self.assertIn(("volumes", {"id": ["volume-1"]}), client.queries)
        self.assertIn(("volume_attachment", {"volume_id": ["volume-1"]}), client.queries)
        self.assertTrue(all(item.get("kind") == "db-jsonl" or item.get("kind") == "openstack-json" for item in result.evidence))

    def test_bare_database_rows_are_rejected(self):
        fixture = deepcopy(self.source_fixture)
        client = FixtureClient(fixture)
        client.db_records = lambda table, filters=None: (deepcopy(fixture["tables"].get(table, [])), {
            "evidence_id": f"source-db:cinder.{table}", "schema": "cinder", "table": table, "filters": deepcopy(filters),
        })
        result = CinderCollector.for_fixture(
            client, "source", schema_from_fixture(fixture)
        ).collect(["volume-1"])
        self.assertTrue(any("DB JSONL record invalid: volumes" in item for item in result.blockers))

    def test_missing_required_attachment_row_blocks(self):
        fixture = deepcopy(self.source_fixture)
        fixture["tables"]["volume_attachment"] = []
        result, _ = collect_from_fixture(fixture)
        self.assertIn("required attachment missing: attachment-1", result.blockers)

    def test_secret_403_and_404_are_blocked(self):
        command = ("secret", "get", "key-1", "-f", "json")
        for status in (403, 404):
            with self.subTest(status=status):
                result, _ = collect_from_fixture(
                    self.source_fixture, failures={command: ProbeError(status)}
                )
                self.assertIn(
                    f"encryption key key-1 metadata access returned {status}",
                    result.blockers,
                )

    def test_missing_barbican_endpoint_is_unknown(self):
        command = ("secret", "get", "key-1", "-f", "json")
        result, _ = collect_from_fixture(
            self.source_fixture,
            failures={command: ProbeError(reason="endpoint-missing")},
        )
        self.assertIn("encryption key service endpoint missing: key-1", result.unknowns)

    def test_connection_material_is_redacted_to_safe_summary(self):
        result, _ = collect_from_fixture(self.source_fixture)
        attachment = next(node for node in result.nodes if node.kind == "volume_attachment")
        self.assertEqual("[REDACTED]", attachment.facts["connection_info"])
        self.assertEqual("[REDACTED]", attachment.facts["connector"])
        self.assertEqual(
            {"driver_type": "iscsi", "target_count": 2, "multipath": True},
            attachment.facts["connection_summary"],
        )
        serialized = json.dumps(result.to_dict())
        for secret in ("chap-secret", "token-secret", "10.0.0.10", "iqn.1", "api-secret"):
            self.assertNotIn(secret, serialized)

    def test_probe_exception_is_sanitized(self):
        command = ("volume", "show", "volume-1", "-f", "json")
        result, _ = collect_from_fixture(
            self.source_fixture,
            failures={command: ProbeError()},
        )
        serialized = json.dumps(result.to_dict())
        self.assertNotIn("secret-token", serialized)
        self.assertIn("OpenStack API probe failed: cinder-source-volume-show-volume-1", result.blockers)

    def test_production_rejects_alias_root_before_any_probe(self):
        client = FixtureClient(self.source_fixture)
        result = CinderCollector(
            client, "source", schema_from_fixture(self.source_fixture)
        ).collect(["volume-1"])
        self.assertIn("Cinder volume roots invalid", result.blockers)
        self.assertEqual([], client.commands)
        self.assertEqual([], client.queries)

    def test_fixture_aliases_require_explicit_fixture_factory(self):
        with self.assertRaisesRegex(ValueError, "fixture-only Cinder client required"):
            CinderCollector.for_fixture(object(), "source", {})

    def test_production_accepts_only_canonical_uuid_graph(self):
        fixture = canonical_fixture(self.source_fixture)
        client = FixtureClient(fixture)
        volume_id = CANONICAL_IDS["volume-1"]
        result = CinderCollector(
            client, "source", schema_from_fixture(fixture)
        ).collect([volume_id])
        self.assertEqual([], result.blockers)
        self.assertIn(f"volume:{volume_id}", {node.key for node in result.nodes})
        self.assertTrue(all(filters for _, filters in client.queries))

    def test_api_db_volume_identity_mismatch_blocks(self):
        fixture = deepcopy(self.source_fixture)
        fixture["openstack"][0]["payload"]["id"] = "volume-other"
        result, _ = collect_from_fixture(fixture)
        self.assertIn("volume API UUID mismatch: volume-1", result.blockers)

    def test_malformed_dependency_identifier_blocks(self):
        fixture = deepcopy(self.source_fixture)
        fixture["tables"]["volumes"][0]["service_uuid"] = "../../service"
        result, _ = collect_from_fixture(fixture)
        self.assertIn("Cinder dependency UUID invalid: volumes.service_uuid", result.blockers)

    def test_service_api_without_uuid_correlates_by_host_and_binary(self):
        fixture = deepcopy(self.source_fixture)
        service = fixture["openstack"][3]["payload"][0]
        service.pop("id")
        service.pop("uuid")
        result, _ = collect_from_fixture(fixture)
        self.assertNotIn("Cinder service API identity missing: service-1", result.blockers)

    def test_attachment_api_db_server_identity_mismatch_blocks(self):
        fixture = deepcopy(self.source_fixture)
        fixture["openstack"][1]["payload"]["server_id"] = "instance-other"
        result, _ = collect_from_fixture(fixture)
        self.assertIn("attachment API/DB server mismatch: attachment-1", result.blockers)

    def test_active_attachment_with_malformed_connection_info_blocks_safely(self):
        fixture = deepcopy(self.source_fixture)
        fixture["tables"]["volume_attachment"][0]["connection_info"] = "password=must-not-leak"
        result, _ = collect_from_fixture(fixture)
        self.assertIn("active attachment connection metadata invalid: attachment-1", result.blockers)
        self.assertNotIn("must-not-leak", json.dumps(result.to_dict()))

    def test_volume_size_api_db_mismatch_blocks(self):
        fixture = deepcopy(self.source_fixture)
        fixture["openstack"][0]["payload"]["size"] = 2
        result, _ = collect_from_fixture(fixture)
        self.assertIn("volume API/DB size mismatch: volume-1", result.blockers)

    def test_retained_snapshot_is_collected_as_non_required_child(self):
        fixture = deepcopy(self.source_fixture)
        fixture["tables"]["snapshots"] = [{
            "id": "snapshot-1", "volume_id": "volume-1", "status": "available",
            "volume_size": 1, "deleted": False,
        }]
        result, _ = collect_from_fixture(fixture)
        self.assertIn("snapshot:snapshot-1", {node.key for node in result.nodes})
        self.assertIn(
            ("volume:volume-1", "snapshot:snapshot-1", False),
            {(edge.source, edge.target, edge.required) for edge in result.edges},
        )


if __name__ == "__main__":
    unittest.main()
