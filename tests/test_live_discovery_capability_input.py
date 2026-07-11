import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from live_discovery.capability_input import build_target_capability
from live_discovery.runner import ProbeFailed
from collect_live_control import _CachedCapabilityRunner


def _record(evidence_id, command, stdout, *, returncode=0, stderr=""):
    return {
        "evidence_id": evidence_id,
        "command": command,
        "returncode": returncode,
        "stdout": stdout,
        "stderr": stderr,
    }


def _live_records(release="2025.1", repository="quay.io/openstack.kolla"):
    management = {
        "nova_api_db_version": _record("manage-nova-api", ["nova-manage", "api_db", "version"], "b30f573d3377\n"),
        "nova_cell_db_version": _record("manage-nova-cell", ["nova-manage", "db", "version"], "b30f573d3377\n"),
        "neutron_heads": _record("manage-neutron", ["neutron-db-manage", "current", "--verbose"], "2025.1-expand\n2025.1-contract\n"),
        "cinder_db_version": _record("manage-cinder", ["cinder-manage", "db", "version"], "2025.1\n"),
        "glance_db_version": _record("manage-glance", ["mysql", "--execute", "SELECT version_num FROM glance.alembic_version;"], "2025.1\n"),
    }
    images = {}
    for service in ("nova_api", "neutron_server", "cinder_api", "glance_api"):
        image = f"{repository}/{service.replace('_', '-') }:{release}-ubuntu-noble"
        inspect = {
            "Config": {
                "Image": image,
                "Labels": {"org.opencontainers.image.version": release},
            },
            "Image": f"sha256:{service}",
        }
        images[service] = _record(
            f"image-{service}", ["docker", "inspect", service], json.dumps([inspect])
        )
    runtime = {
        "runtime-target-virsh-version": _record("runtime-target-virsh-version", ["virsh", "version"], "9.0.0\n"),
        "runtime-target-domcapabilities": _record("runtime-target-domcapabilities", ["virsh", "domcapabilities"], "<domainCapabilities><devices><disk><enum name='bus'><value>virtio</value></enum></disk></devices></domainCapabilities>"),
        "runtime-target-qemu-machine-help": _record("runtime-target-qemu-machine-help", ["qemu-system-x86_64", "-machine", "help"], "Supported machines are:\npc-q35-8.2 live\n"),
    }
    return management, images, runtime


class TargetCapabilityInputTests(unittest.TestCase):
    def test_live_consistent_epoxy_vanilla_evidence_derives_profile(self):
        management, images, runtime = _live_records()
        result = build_target_capability(management, images, runtime)
        self.assertEqual("2025.1", result["target_manage_outputs"]["release"])
        self.assertEqual("vanilla", result["target_manage_outputs"]["distribution"])
        self.assertEqual("b30f573d3377\n", result["target_manage_outputs"]["nova_api_db_version"])
        self.assertEqual(0, result["probe_statuses"]["manage-nova-api"]["returncode"])
        self.assertNotIn("stdout", result["probe_statuses"]["manage-nova-api"])
        self.assertNotIn("Labels", result["target_image_inspects"]["nova_api"]["Config"])

    def test_old_or_vendor_images_do_not_claim_epoxy_vanilla(self):
        for release, repository in (
            ("2024.2", "quay.io/openstack.kolla"),
            ("2025.1", "registry.vendor.example/openstack"),
        ):
            with self.subTest(release=release, repository=repository):
                management, images, runtime = _live_records(release, repository)
                result = build_target_capability(management, images, runtime)
                self.assertIsNone(result["target_manage_outputs"]["release"])
                self.assertIsNone(result["target_manage_outputs"]["distribution"])

    def test_nonzero_partial_stdout_is_preserved_as_failure_but_not_parsed(self):
        management, images, runtime = _live_records()
        management["nova_api_db_version"].update(
            returncode=2, stdout="b30f573d3377\n", stderr="password=secret connection refused"
        )
        result = build_target_capability(management, images, runtime)
        self.assertIsNone(result["target_manage_outputs"]["nova_api_db_version"])
        self.assertIsNone(result["target_manage_outputs"]["release"])
        failure = result["probe_statuses"]["manage-nova-api"]
        self.assertEqual(2, failure["returncode"])
        self.assertEqual("command-failed", failure["failure_class"])
        self.assertNotIn("secret", json.dumps(result))

    def test_mismatched_live_db_version_does_not_claim_epoxy(self):
        management, images, runtime = _live_records()
        management["cinder_db_version"]["stdout"] = "136\n"
        result = build_target_capability(management, images, runtime)
        self.assertIsNone(result["target_manage_outputs"]["release"])
        self.assertIsNone(result["target_manage_outputs"]["distribution"])

    def test_online_migration_evidence_is_optional_and_passed_through(self):
        management, images, runtime = _live_records()
        absent = build_target_capability(management, images, runtime)
        self.assertEqual({}, absent["target_manage_outputs"]["online_migration_evidence"])
        supplied = {
            "nova": {
                "evidence_id": "nova-migrations",
                "timestamp": "2026-07-11T09:00:00Z",
                "returncode": 0,
                "command": ["nova-manage", "db", "online_data_migrations"],
            }
        }
        result = build_target_capability(management, images, runtime, supplied)
        self.assertEqual(supplied, result["target_manage_outputs"]["online_migration_evidence"])

    def test_cached_runner_reproduces_nonzero_without_returning_partial_stdout(self):
        record = _record("runtime-target-virsh-version", ["virsh", "version"], "9.0", returncode=3, stderr="failed")
        runner = _CachedCapabilityRunner({"runtime-target-virsh-version": record})
        with self.assertRaises(ProbeFailed) as caught:
            runner.run(["virsh", "version"], "runtime-target-virsh-version")
        self.assertEqual(3, caught.exception.evidence.returncode)
        self.assertEqual("9.0", caught.exception.evidence.stdout)


if __name__ == "__main__":
    unittest.main()
