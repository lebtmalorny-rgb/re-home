from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
FIXTURES = ROOT / "tests" / "fixtures" / "live_discovery"

from live_discovery.contract import CheckResult
from live_discovery.glance import GlanceCollector


class ProbeError(RuntimeError):
    def __init__(self, status_code=None):
        self.status_code = status_code
        super().__init__("must-not-leak secret-token https://user:pass@evil.invalid")


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
        self.probes = []

    def json(self, command, evidence_id, required=True):
        del required
        self.commands.append(deepcopy(command))
        if tuple(command) in self.failures:
            raise self.failures[tuple(command)]
        if tuple(command) not in self.responses:
            raise AssertionError(f"unexpected command: {command}")
        return deepcopy(self.responses[tuple(command)]), {"id": evidence_id}

    def probe_image_data(self, image_id, expected_size, required):
        self.probes.append((image_id, expected_size, required))
        status = self.fixture.get("probe_status", "UNKNOWN")
        return CheckResult(
            f"glance.{self.fixture.get('side', 'source')}.image-data.{image_id}",
            status,
            "one-byte Glance API probe completed" if status == "PASS" else "image data probe unavailable",
            [f"image:{image_id}"],
        )

    def glance_store_capabilities(self, evidence_id):
        return deepcopy(self.fixture.get("store_capabilities")), {"id": evidence_id}


class SecretProbeClient(FixtureClient):
    def probe_image_data(self, image_id, expected_size, required):
        del expected_size, required
        return CheckResult(
            "secret-token", "PASS", "https://user:pass@evil.invalid secret-token",
            ["secret-token"], ["secret-token"],
        )


class UnprovenCapabilityClient(FixtureClient):
    def glance_store_capabilities(self, evidence_id):
        del evidence_id
        return deepcopy(self.fixture.get("store_capabilities")), {
            "id": "secret-token"
        }


def collect_from_fixture(fixture, requirements, failures=None):
    client = FixtureClient(fixture, failures)
    result = GlanceCollector.for_fixture(
        client, fixture.get("side", "source")
    ).collect(requirements)
    return result, client


class GlanceCollectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_fixture = json.loads(
            (FIXTURES / "glance-source.json").read_text(encoding="utf-8")
        )
        cls.target_fixture = json.loads(
            (FIXTURES / "glance-target.json").read_text(encoding="utf-8")
        )

    def required(self, **overrides):
        value = {
            "required": True,
            "reason": "local_root",
            "bdm_proves_no_local_root": False,
            "runtime_proves_no_local_root": False,
            "consumer_project_ids": ["project-1", "project-2"],
        }
        value.update(overrides)
        return {"image-1": value}

    def historical(self, **overrides):
        value = {
            "required": False,
            "reason": "volume_image_metadata",
            "bdm_proves_no_local_root": True,
            "runtime_proves_no_local_root": True,
        }
        value.update(overrides)
        return {"image-1": value}

    def test_required_image_has_complete_multi_store_graph(self):
        result, client = collect_from_fixture(self.source_fixture, self.required())
        image = next(node for node in result.nodes if node.kind == "image")
        self.assertTrue(image.facts["required_for_rehome"])
        self.assertEqual(["file", "rbd"], image.facts["store_ids"])
        self.assertEqual(("image-1", 1024, True), client.probes[0])
        required_targets = {
            edge.target for edge in result.edges
            if edge.source == "image:image-1" and edge.required
        }
        self.assertTrue({"glance_store:file", "glance_store:rbd"} <= required_targets)
        self.assertEqual(2, len([node for node in result.nodes if node.kind == "image_location"]))
        for location in [node for node in result.nodes if node.kind == "image_location"]:
            self.assertRegex(location.facts["location_fingerprint"], r"^[0-9a-f]{64}$")
        self.assertEqual([], result.blockers)
        self.assertEqual([], result.unknowns)

    def test_target_fixture_handles_rbd_and_swift_without_backend_assumption(self):
        result, _ = collect_from_fixture(self.target_fixture, self.required())
        stores = {node.id for node in result.nodes if node.kind == "glance_store"}
        self.assertEqual({"rbd", "swift"}, stores)
        self.assertEqual([], result.blockers)

    def test_enabled_store_inventory_is_generic_for_file_rbd_swift_s3_and_vendor(self):
        result, _ = collect_from_fixture(self.source_fixture, self.required())
        inventory = next(node for node in result.nodes if node.kind == "glance_store_inventory")
        self.assertEqual(
            ["file", "rbd", "s3", "swift", "vendor_archive"],
            inventory.facts["enabled_store_ids"],
        )
        self.assertEqual("file", inventory.facts["default_store_id"])

    def test_store_inventory_requires_exactly_one_typed_default(self):
        cases = (
            lambda stores: [item.__setitem__("Default", False) for item in stores],
            lambda stores: stores[1].__setitem__("Default", True),
            lambda stores: stores[0].__setitem__("Default", 1),
        )
        for mutate in cases:
            with self.subTest(mutate=mutate):
                fixture = deepcopy(self.source_fixture)
                mutate(fixture["openstack"][2]["payload"])
                result, _ = collect_from_fixture(fixture, self.required())
                self.assertTrue(result.unknowns or result.blockers)

    def test_store_inventory_rejects_case_and_alias_collisions_strictly(self):
        mutations = (
            ("id-conflict", lambda row: row.__setitem__("id", "rbd")),
            ("id-equal", lambda row: row.__setitem__("id", "file")),
            ("default-conflict", lambda row: row.__setitem__("default", False)),
            ("default-equal", lambda row: row.__setitem__("default", True)),
            ("backend-conflict", lambda row: row.update({"Backend Type": "file", "store_type": "rbd"})),
            ("backend-equal", lambda row: row.update({"Backend Type": "file", "store_type": "file"})),
            ("non-string-key", lambda row: row.__setitem__(7, "secret-token")),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                fixture = deepcopy(self.source_fixture)
                mutate(fixture["openstack"][2]["payload"][0])
                result, _ = collect_from_fixture(fixture, self.required())
                serialized = json.dumps(result.to_dict(), sort_keys=True)
                self.assertIn("Glance store inventory row malformed", result.blockers)
                self.assertNotIn("secret-token", serialized)

        fixture = deepcopy(self.source_fixture)
        fixture["openstack"][2]["payload"][0] = []
        result, _ = collect_from_fixture(fixture, self.required())
        self.assertIn("Glance store inventory row malformed", result.blockers)

    def test_store_capabilities_reject_alias_collisions_and_malformed_rows(self):
        mutations = (
            ("id-conflict", lambda row: row.__setitem__("id", "rbd")),
            ("id-equal", lambda row: row.__setitem__("id", "file")),
            ("type-conflict", lambda row: row.__setitem__("store_type", "rbd")),
            ("type-equal", lambda row: row.__setitem__("store_type", "file")),
            ("non-string-key", lambda row: row.__setitem__(7, "secret-token")),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                fixture = deepcopy(self.source_fixture)
                mutate(fixture["store_capabilities"][0])
                result, _ = collect_from_fixture(fixture, self.required())
                serialized = json.dumps(result.to_dict(), sort_keys=True)
                self.assertIn("Glance store capability row malformed", result.blockers)
                self.assertNotIn("secret-token", serialized)

        fixture = deepcopy(self.source_fixture)
        fixture["store_capabilities"][0] = []
        result, _ = collect_from_fixture(fixture, self.required())
        self.assertIn("Glance store capability row malformed", result.blockers)

    def test_historical_image_warns_only_with_explicit_bdm_and_runtime_proof(self):
        result, client = collect_from_fixture(self.source_fixture, self.historical())
        self.assertFalse(result.blockers)
        self.assertTrue(any(check.status == "WARN" for check in result.checks))
        self.assertEqual([], client.probes)
        self.assertFalse(any(check.status in {"BLOCKED", "UNKNOWN"} for check in result.checks))
        self.assertFalse(any(edge.required for edge in result.edges))

    def test_historical_classification_without_both_proofs_fails_closed(self):
        for field in ("bdm_proves_no_local_root", "runtime_proves_no_local_root"):
            with self.subTest(field=field):
                result, _ = collect_from_fixture(
                    self.source_fixture, self.historical(**{field: False})
                )
                self.assertTrue(result.unknowns)
                self.assertFalse(any(check.status == "WARN" for check in result.checks))

    def test_production_requires_canonical_uuid_and_fixture_alias_is_explicit(self):
        client = FixtureClient(self.source_fixture)
        result = GlanceCollector(client, "source").collect(self.required())
        self.assertIn("Glance image requirements invalid", result.blockers)
        with self.assertRaisesRegex(ValueError, "fixture-only"):
            GlanceCollector.for_fixture(object(), "source")

    def test_invalid_requirement_types_fail_before_api_calls(self):
        cases = (
            {},
            {"image-1": {"required": 1, "reason": "local_root"}},
            {"image-1": {"required": True, "reason": "bad\nreason"}},
            {"image-1": {"required": False, "reason": "local_root"}},
            {"image-1": []},
        )
        for requirements in cases:
            with self.subTest(requirements=requirements):
                result, client = collect_from_fixture(self.source_fixture, requirements)
                self.assertTrue(result.blockers)
                self.assertEqual([], client.commands)

    def test_non_active_states_are_never_data_ready(self):
        for status in (
            "queued", "saving", "killed", "deleted", "pending_delete",
            "deactivated", "uploading", "importing",
        ):
            with self.subTest(status=status):
                fixture = deepcopy(self.source_fixture)
                fixture["openstack"][0]["payload"]["status"] = status
                result, client = collect_from_fixture(fixture, self.required())
                self.assertTrue(result.blockers or result.unknowns)
                self.assertEqual([], client.probes)

    def test_missing_or_duplicate_store_and_location_evidence_blocks(self):
        mutations = (
            ("missing stores", lambda image, stores: image.pop("stores")),
            ("duplicate stores", lambda image, stores: image.__setitem__("stores", ["file", "file"])),
            ("missing locations", lambda image, stores: image.pop("locations")),
            ("duplicate locations", lambda image, stores: image["locations"].append(deepcopy(image["locations"][0]))),
            ("store inventory missing", lambda image, stores: stores.__setitem__(slice(None), [stores[0]])),
            ("store inventory duplicate", lambda image, stores: stores.append(deepcopy(stores[0]))),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                fixture = deepcopy(self.source_fixture)
                mutate(fixture["openstack"][0]["payload"], fixture["openstack"][2]["payload"])
                result, _ = collect_from_fixture(fixture, self.required())
                self.assertTrue(result.blockers or result.unknowns)

    def test_distinct_locations_in_same_store_are_not_false_duplicates(self):
        fixture = deepcopy(self.source_fixture)
        image = fixture["openstack"][0]["payload"]
        image["stores"] = ["rbd"]
        image["locations"] = [
            {"url": "rbd://cluster/pool/image-1/snap-a", "metadata": {"store": "rbd"}},
            {"url": "rbd://cluster/pool/image-1/snap-b", "metadata": {"store": "rbd"}},
        ]
        result, _ = collect_from_fixture(fixture, self.required())
        self.assertFalse(any("locations ambiguous" in item for item in result.blockers))
        self.assertEqual(2, len([node for node in result.nodes if node.kind == "image_location"]))

    def test_network_location_scheme_requires_authority(self):
        fixture = deepcopy(self.source_fixture)
        fixture["openstack"][0]["payload"]["stores"] = ["swift"]
        fixture["openstack"][0]["payload"]["locations"] = [{
            "url": "swift+https:///v1/container/image-1", "metadata": {"store": "swift"}
        }]
        result, _ = collect_from_fixture(fixture, self.required())
        self.assertTrue(result.unknowns)
        self.assertFalse(any(check.status == "PASS" and "store.swift" in check.check_id for check in result.checks))

    def test_image_formats_are_canonical_typed_enums(self):
        for field in ("disk_format", "container_format"):
            with self.subTest(field=field):
                fixture = deepcopy(self.source_fixture)
                fixture["openstack"][0]["payload"][field] = "totally_unknown_format"
                result, _ = collect_from_fixture(fixture, self.required())
                serialized = json.dumps(result.to_dict(), sort_keys=True)
                self.assertTrue(result.unknowns)
                self.assertNotIn("totally_unknown_format", serialized)

    def test_unknown_store_is_explicit_unknown_and_never_passes(self):
        fixture = deepcopy(self.source_fixture)
        fixture["openstack"][0]["payload"]["stores"] = ["mystery"]
        fixture["openstack"][0]["payload"]["locations"] = [{
            "url": "custom://opaque/image-1", "metadata": {"store": "mystery"}
        }]
        fixture["openstack"][2]["payload"] = [{
            "ID": "mystery", "Default": True
        }]
        fixture["store_capabilities"] = [{
            "store_id": "mystery", "backend_type": "vendor-secret-token"
        }]
        result, _ = collect_from_fixture(fixture, self.required())
        self.assertTrue(result.unknowns)
        self.assertFalse(any(check.status == "PASS" and "store" in check.check_id for check in result.checks))

    def test_api_identity_size_owner_hash_and_checksum_are_typed_and_consistent(self):
        mutations = (
            ("id", "other-image"),
            ("size", "1024"),
            ("owner", 7),
            ("os_hash_algo", 7),
            ("os_hash_value", "abcd"),
            ("checksum", 123),
            ("protected", "false"),
            ("tags", ["ok", 1]),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                fixture = deepcopy(self.source_fixture)
                fixture["openstack"][0]["payload"][field] = value
                result, _ = collect_from_fixture(fixture, self.required())
                self.assertTrue(result.blockers or result.unknowns)

    def test_hash_pair_is_preferred_and_checksum_is_secondary(self):
        result, _ = collect_from_fixture(self.source_fixture, self.required())
        image = next(node for node in result.nodes if node.kind == "image")
        self.assertEqual("sha256", image.facts["hash"]["algorithm"])
        self.assertEqual(64, len(image.facts["hash"]["value"]))
        self.assertEqual(32, len(image.facts["legacy_checksum"]))

    def test_image_properties_use_explicit_typed_allowlist(self):
        fixture = deepcopy(self.source_fixture)
        image = fixture["openstack"][0]["payload"]
        image["properties"] = {
            "hw_machine_type": "q35",
            "auth_token": "secret-token",
            "vendor_unknown": "must-not-serialize",
        }
        image["hw_disk_bus"] = "virtio"
        result, _ = collect_from_fixture(fixture, self.required())
        node = next(item for item in result.nodes if item.kind == "image")
        self.assertEqual(
            {"hw_machine_type": "q35", "hw_disk_bus": "virtio"},
            node.facts["properties"],
        )
        serialized = json.dumps(result.to_dict(), sort_keys=True)
        self.assertNotIn("secret-token", serialized)
        self.assertNotIn("must-not-serialize", serialized)

    def test_member_identity_status_and_duplicates_fail_closed(self):
        cases = (
            [{"image_id": "other", "member_id": "project-2", "status": "accepted"}],
            [{"image_id": "image-1", "member_id": "bad member", "status": "accepted"}],
            [{"image_id": "image-1", "member_id": "project-2", "status": "maybe"}],
            [
                {"image_id": "image-1", "member_id": "project-2", "status": "accepted"},
                {"image_id": "image-1", "member_id": "project-2", "status": "accepted"},
            ],
        )
        for members in cases:
            with self.subTest(members=members):
                fixture = deepcopy(self.source_fixture)
                fixture["openstack"][1]["payload"] = members
                result, _ = collect_from_fixture(fixture, self.required())
                self.assertTrue(result.blockers or result.unknowns)

    def test_required_edge_targets_always_resolve(self):
        result, _ = collect_from_fixture(self.source_fixture, self.required())
        keys = {node.key for node in result.nodes}
        dangling = [edge.target for edge in result.edges if edge.required and edge.target not in keys]
        self.assertEqual([], dangling)

    def test_real_osc_store_list_shape_is_case_normalized(self):
        payload = self.source_fixture["openstack"][2]["payload"]
        self.assertIsInstance(payload, list)
        self.assertIn("ID", payload[0])
        self.assertNotIn("Backend Type", payload[0])
        result, _ = collect_from_fixture(self.source_fixture, self.required())
        inventory = next(node for node in result.nodes if node.kind == "glance_store_inventory")
        self.assertEqual("file", inventory.facts["default_store_id"])
        self.assertEqual([], result.blockers)

    def test_store_nodes_and_checks_are_globally_unique_for_two_images(self):
        fixture = deepcopy(self.source_fixture)
        second_image = deepcopy(fixture["openstack"][0])
        second_image["command"][2] = "image-2"
        second_image["payload"]["id"] = "image-2"
        second_image["payload"]["locations"] = [
            {"url": "file:///var/lib/glance/images/image-2", "metadata": {"store": "file"}},
            {"url": "rbd://cluster/pool/image-2/snap", "metadata": {"store": "rbd"}},
        ]
        second_members = deepcopy(fixture["openstack"][1])
        second_members["command"][3] = "image-2"
        second_members["payload"][0]["image_id"] = "image-2"
        fixture["openstack"].extend([second_image, second_members])
        requirements = self.required()
        requirements["image-2"] = deepcopy(requirements["image-1"])
        result, _ = collect_from_fixture(fixture, requirements)
        store_keys = [node.key for node in result.nodes if node.kind == "glance_store"]
        store_checks = [check.check_id for check in result.checks if ".store." in check.check_id]
        self.assertEqual(len(store_keys), len(set(store_keys)))
        self.assertEqual(len(store_checks), len(set(store_checks)))
        self.assertEqual({"glance_store:file", "glance_store:rbd"}, set(store_keys))
        self.assertEqual([], result.blockers)

    def test_store_backend_type_must_be_explicit_supported_and_match_scheme(self):
        cases = (
            ("absent", lambda fixture: fixture.pop("store_capabilities"), "Glance store backend type unavailable"),
            ("mismatch", lambda fixture: fixture["store_capabilities"][0].__setitem__("backend_type", "rbd"), "Glance store backend type mismatch"),
            ("vendor", lambda fixture: fixture["store_capabilities"][0].__setitem__("backend_type", "vendor-secret-token"), "Glance store backend type unsupported"),
        )
        for label, mutate, expected in cases:
            with self.subTest(label=label):
                fixture = deepcopy(self.source_fixture)
                mutate(fixture)
                result, _ = collect_from_fixture(fixture, self.required())
                self.assertTrue(any(expected in item for item in result.unknowns))
                self.assertFalse(any(
                    check.status == "PASS" and check.check_id.endswith("store.file")
                    for check in result.checks
                ))
                self.assertNotIn("vendor-secret-token", json.dumps(result.to_dict(), sort_keys=True))

    def test_store_backend_capability_requires_sanitized_provenance(self):
        client = UnprovenCapabilityClient(self.source_fixture)
        result = GlanceCollector.for_fixture(client, "source").collect(
            self.required()
        )
        serialized = json.dumps(result.to_dict(), sort_keys=True)
        self.assertTrue(any(
            "Glance store backend type unavailable" in item
            for item in result.unknowns
        ))
        self.assertFalse(any(
            check.status == "PASS" and ".store." in check.check_id
            for check in result.checks
        ))
        self.assertNotIn("secret-token", serialized)

    def test_required_image_project_access_matrix(self):
        cases = (
            ("owner-private", "private", "project-1", "accepted", False),
            ("public", "public", "project-3", "accepted", False),
            ("community", "community", "project-3", "accepted", False),
            ("shared-accepted", "shared", "project-2", "accepted", False),
            ("shared-pending", "shared", "project-2", "pending", True),
            ("shared-rejected", "shared", "project-2", "rejected", True),
            ("private-wrong-owner", "private", "project-2", "accepted", True),
            ("shared-missing", "shared", "project-3", "accepted", True),
        )
        for label, visibility, consumer, member_status, blocked in cases:
            with self.subTest(label=label):
                fixture = deepcopy(self.source_fixture)
                fixture["openstack"][0]["payload"]["visibility"] = visibility
                fixture["openstack"][1]["payload"][0]["status"] = member_status
                requirements = self.required(consumer_project_ids=[consumer])
                result, _ = collect_from_fixture(fixture, requirements)
                access_blockers = [item for item in result.blockers if "project access" in item]
                self.assertEqual(blocked, bool(access_blockers))

    def test_missing_invalid_or_contradictory_consumer_membership_blocks(self):
        invalid_requirements = self.required()
        invalid_requirements["image-1"].pop("consumer_project_ids")
        result, client = collect_from_fixture(self.source_fixture, invalid_requirements)
        self.assertIn("Glance image requirements invalid", result.blockers)
        self.assertEqual([], client.commands)

        fixture = deepcopy(self.source_fixture)
        fixture["openstack"][1]["payload"].append({
            "image_id": "image-1", "member_id": "project-2", "status": "rejected"
        })
        result, _ = collect_from_fixture(fixture, self.required())
        self.assertTrue(any("member evidence ambiguous" in item for item in result.blockers))
        self.assertTrue(any("project access" in item for item in result.blockers))

    def test_probe_blocked_or_unknown_propagates_fail_closed(self):
        for status, collection in (("BLOCKED", "blockers"), ("UNKNOWN", "unknowns")):
            with self.subTest(status=status):
                fixture = deepcopy(self.source_fixture)
                fixture["probe_status"] = status
                result, _ = collect_from_fixture(fixture, self.required())
                self.assertTrue(getattr(result, collection))

    def test_probe_result_is_rebuilt_from_status_without_untrusted_text(self):
        client = SecretProbeClient(self.source_fixture)
        result = GlanceCollector.for_fixture(client, "source").collect(self.required())
        serialized = json.dumps(result.to_dict(), sort_keys=True)
        self.assertNotIn("secret-token", serialized)
        self.assertNotIn("evil.invalid", serialized)
        self.assertTrue(any(check.status == "PASS" for check in result.checks))

    def test_missing_proven_historical_image_is_warn_only(self):
        result, _ = collect_from_fixture(
            self.source_fixture, self.historical(),
            {("image", "show", "image-1", "-f", "json"): ProbeError(404)},
        )
        self.assertEqual([], result.blockers)
        self.assertEqual([], result.unknowns)
        self.assertTrue(any(check.status == "WARN" for check in result.checks))

    def test_side_is_a_typed_enum(self):
        with self.assertRaisesRegex(ValueError, "side"):
            GlanceCollector(FixtureClient(self.source_fixture), "secret-token")

    def test_api_failures_are_sanitized_and_status_classified(self):
        for status, expected in ((404, "blockers"), (403, "blockers"), (None, "unknowns")):
            with self.subTest(status=status):
                failure = ProbeError(status)
                result, _ = collect_from_fixture(
                    self.source_fixture, self.required(),
                    {("image", "show", "image-1", "-f", "json"): failure},
                )
                serialized = json.dumps(result.to_dict(), sort_keys=True)
                self.assertNotIn("secret-token", serialized)
                self.assertNotIn("evil.invalid", serialized)
                self.assertTrue(getattr(result, expected))

    def test_raw_locations_descriptions_properties_and_secret_sentinels_never_serialize(self):
        fixture = deepcopy(self.source_fixture)
        image = fixture["openstack"][0]["payload"]
        image["direct_url"] = "https://user:secret@glance.invalid/private"
        image["properties"] = {"auth_token": "secret-token", "safe": "value"}
        image["locations"][0]["url"] = "file:///must-not-serialize-secret-token"
        fixture["openstack"][2]["payload"][0]["Description"] = "secret-token"
        result, _ = collect_from_fixture(fixture, self.required())
        serialized = json.dumps(result.to_dict(), sort_keys=True)
        self.assertNotIn("secret-token", serialized)
        self.assertNotIn("must-not-serialize", serialized)
        self.assertNotIn("user:secret", serialized)


if __name__ == "__main__":
    unittest.main()
