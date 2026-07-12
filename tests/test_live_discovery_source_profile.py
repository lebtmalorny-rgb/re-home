import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


class SourceProfileEvidenceTests(unittest.TestCase):
    def _record(self, service, vendor="Keystack", release="2025.1"):
        inspect = [{
            "Config": {
                "Image": f"registry.internal/keystack/{service}:2025.1",
                "Labels": {
                    "org.opencontainers.image.vendor": vendor,
                    "openstack_release": release,
                },
            },
            "Image": "sha256:" + ("a" * 64),
        }]
        return {
            "evidence_id": f"source-image-{service}",
            "command": ["docker", "inspect", service],
            "returncode": 0,
            "stdout": json.dumps(inspect),
            "stderr": "",
        }

    def test_exact_live_labels_prove_canonical_keystack_profile(self):
        from live_discovery.source_profile import build_source_profile

        records = {
            service: self._record(service)
            for service in ("nova_api", "neutron_server", "cinder_api", "glance_api")
        }

        result = build_source_profile(records)

        profile = result["schema_capabilities"]["source-profile"]
        self.assertEqual("PASS", profile["status"])
        self.assertEqual("keystack-2025.1", profile["profile"])
        rendered = json.dumps(result, sort_keys=True)
        self.assertNotIn("stdout", rendered)

    def test_unproven_vendor_is_unknown_not_fabricated(self):
        from live_discovery.source_profile import build_source_profile

        records = {
            service: self._record(service)
            for service in ("nova_api", "neutron_server", "cinder_api", "glance_api")
        }
        records["glance_api"] = self._record("glance_api", vendor="Unknown")

        result = build_source_profile(records)

        profile = result["schema_capabilities"]["source-profile"]
        self.assertEqual("UNKNOWN", profile["status"])
        self.assertIsNone(profile["profile"])

    def test_failed_or_invalid_inspect_is_fail_closed(self):
        from live_discovery.source_profile import build_source_profile

        records = {
            service: self._record(service)
            for service in ("nova_api", "neutron_server", "cinder_api", "glance_api")
        }
        records["nova_api"]["returncode"] = 1
        records["nova_api"]["stderr"] = "permission denied"

        with self.assertRaisesRegex(ValueError, "failed"):
            build_source_profile(records)

    def test_directional_mapping_requires_matching_live_profile_evidence(self):
        import assemble_live_discovery as assembler
        from live_discovery.schema import (
            SchemaColumn,
            SchemaSnapshot,
            schema_capability,
        )

        snapshot = SchemaSnapshot(
            tables={
                "nova.instances": {
                    "id": SchemaColumn("id", 1, "varchar(36)", False, None, ""),
                },
            },
            indexes={},
            foreign_keys={},
            metadata_complete=True,
        )
        metadata = schema_capability(snapshot, {"nova.instances": ["id"]})
        policy = {
            "schema_version": "openstack-rehome-schema-policy/v1alpha1",
            "source_profile": "keystack-2025.1",
            "target_profile": "vanilla-openstack-2025.1-epoxy",
            "source_only_allowlist": [],
            "normalization_columns": [],
        }
        capabilities = {
            "services": {
                "source-information-schema": metadata,
                "target-information-schema": metadata,
            },
        }

        unproven = assembler._directional_mapping(policy, capabilities)

        self.assertIsNone(unproven["source_profile"])
        self.assertIn("not proven", unproven["blockers"][0])

        records = {service: self._record(service) for service in (
            "nova_api", "neutron_server", "cinder_api", "glance_api"
        )}
        from live_discovery.source_profile import build_source_profile
        capabilities["services"].update(build_source_profile(records)["schema_capabilities"])
        proven = assembler._directional_mapping(policy, capabilities)
        self.assertEqual("keystack-2025.1", proven["source_profile"])
        self.assertEqual([], proven["blockers"])


if __name__ == "__main__":
    unittest.main()
