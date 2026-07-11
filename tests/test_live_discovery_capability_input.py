import json
import hashlib
from datetime import datetime, timedelta, timezone
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


def _migration_evidence(management):
    return {
        "schema_version": "openstack-rehome-online-migration-evidence/v1alpha1",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "database_revisions": {
            field: record["stdout"].strip().splitlines()
            if field == "neutron_heads" else record["stdout"].strip()
            for field, record in management.items()
        },
        "services": {
            service: {
                "evidence_id": f"{service}-migrations",
                "command": [f"{service}-manage", "db", "online_data_migrations"],
                "returncode": 0,
                "completed": True,
            }
            for service in ("nova", "cinder")
        },
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
        repositories = {
            "nova_api": "nova-api",
            "neutron_server": "neutron-server",
            "cinder_api": "cinder-api",
            "glance_api": "glance-api",
        }
        image = f"{repository}/{repositories[service]}:{release}-ubuntu-noble"
        inspect = {
            "Config": {
                "Image": image,
                "Labels": {"org.opencontainers.image.version": release},
            },
            "Image": "sha256:" + hashlib.sha256(service.encode()).hexdigest(),
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
        result = build_target_capability(
            management, images, runtime, _migration_evidence(management)
        )
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
            ("2025.1-vendor", "quay.io/openstack.kolla"),
        ):
            with self.subTest(release=release, repository=repository):
                management, images, runtime = _live_records(release, repository)
                result = build_target_capability(
                    management, images, runtime, _migration_evidence(management)
                )
                self.assertIsNone(result["target_manage_outputs"]["release"])
                self.assertIsNone(result["target_manage_outputs"]["distribution"])

    def test_nonzero_partial_stdout_is_preserved_as_failure_but_not_parsed(self):
        management, images, runtime = _live_records()
        management["nova_api_db_version"].update(
            returncode=2, stdout="b30f573d3377\n", stderr="password=secret connection refused"
        )
        result = build_target_capability(
            management, images, runtime, _migration_evidence(management)
        )
        self.assertIsNone(result["target_manage_outputs"]["nova_api_db_version"])
        self.assertIsNone(result["target_manage_outputs"]["release"])
        failure = result["probe_statuses"]["manage-nova-api"]
        self.assertEqual(2, failure["returncode"])
        self.assertEqual("command-failed", failure["failure_class"])
        self.assertEqual(
            hashlib.sha256(b"b30f573d3377\n").hexdigest(),
            failure["stdout_sha256"],
        )
        self.assertNotIn("secret", json.dumps(result))

    def test_online_migration_evidence_is_optional_and_passed_through(self):
        management, images, runtime = _live_records()
        absent = build_target_capability(management, images, runtime)
        self.assertEqual({}, absent["target_manage_outputs"]["online_migration_evidence"])
        supplied = _migration_evidence(management)
        result = build_target_capability(management, images, runtime, supplied)
        self.assertEqual(
            {"nova", "cinder"},
            set(result["target_manage_outputs"]["online_migration_evidence"]),
        )

    def test_failed_records_never_retain_raw_stdout_stderr_or_secret_argv(self):
        management, images, runtime = _live_records()
        runtime["runtime-target-virsh-version"].update(
            returncode=1,
            stdout="private-key-material",
            stderr="Authorization: Bearer runtime-secret",
            command=["docker", "exec", "-e", "MYSQL_PWD=mysql-secret", "nova_libvirt", "virsh", "version"],
        )
        result = build_target_capability(
            management, images, runtime, _migration_evidence(management),
            virsh_argv=["docker", "exec", "-e", "MYSQL_PWD=mysql-secret", "nova_libvirt", "virsh"],
        )
        rendered = json.dumps(result)
        for secret in ("private-key-material", "runtime-secret", "mysql-secret"):
            self.assertNotIn(secret, rendered)
        failed = result["target_runtime_outputs"]["runtime-target-virsh-version"]
        self.assertNotIn("stdout", failed)
        self.assertNotIn("stderr", failed)
        self.assertEqual(hashlib.sha256(b"private-key-material").hexdigest(), failed["stdout_sha256"])
        self.assertIn("MYSQL_PWD=[REDACTED]", failed["command"])

    def test_successful_runtime_stdout_with_recursive_secret_is_rejected(self):
        management, images, runtime = _live_records()
        runtime["runtime-target-domcapabilities"]["stdout"] = (
            "<domainCapabilities><secret>runtime-secret</secret></domainCapabilities>"
        )
        with self.assertRaisesRegex(ValueError, "safe stdout"):
            build_target_capability(
                management, images, runtime, _migration_evidence(management)
            )

    def test_wrong_service_repository_or_null_digest_cannot_claim_profile(self):
        for mutation in ("wrong-service", "null-digest", "reused-digest", "wrong-tag"):
            management, images, runtime = _live_records()
            if mutation == "wrong-service":
                images["nova_api"]["stdout"] = images["glance_api"]["stdout"]
            elif mutation in {"null-digest", "reused-digest"}:
                payload = json.loads(images["nova_api"]["stdout"])
                payload[0]["Image"] = (
                    None if mutation == "null-digest"
                    else json.loads(images["glance_api"]["stdout"])[0]["Image"]
                )
                images["nova_api"]["stdout"] = json.dumps(payload)
            else:
                payload = json.loads(images["nova_api"]["stdout"])
                payload[0]["Config"]["Image"] = "quay.io/openstack.kolla/nova-api:2025.1-attacker"
                images["nova_api"]["stdout"] = json.dumps(payload)
            result = build_target_capability(
                management, images, runtime, _migration_evidence(management)
            )
            self.assertIsNone(result["target_manage_outputs"]["release"])

    def test_migration_revision_mismatch_cannot_claim_profile(self):
        management, images, runtime = _live_records()
        evidence = _migration_evidence(management)
        evidence["database_revisions"]["cinder_db_version"] = "different-live-head"
        result = build_target_capability(management, images, runtime, evidence)
        self.assertIsNone(result["target_manage_outputs"]["release"])

    def test_stale_or_incomplete_migration_evidence_cannot_claim_profile(self):
        for mutation in ("stale", "incomplete"):
            management, images, runtime = _live_records()
            evidence = _migration_evidence(management)
            if mutation == "stale":
                evidence["timestamp"] = (
                    datetime.now(timezone.utc) - timedelta(hours=25)
                ).isoformat().replace("+00:00", "Z")
            else:
                evidence["services"]["nova"]["completed"] = False
            result = build_target_capability(management, images, runtime, evidence)
            self.assertIsNone(result["target_manage_outputs"]["release"])

    def test_cached_runner_reproduces_nonzero_without_returning_partial_stdout(self):
        record = {
            "evidence_id": "runtime-target-virsh-version",
            "command": ["virsh", "version"],
            "returncode": 3,
            "failure_class": "command-failed",
            "stdout_sha256": hashlib.sha256(b"9.0").hexdigest(),
            "stderr_sha256": hashlib.sha256(b"failed").hexdigest(),
        }
        runner = _CachedCapabilityRunner({"runtime-target-virsh-version": record})
        with self.assertRaises(ProbeFailed) as caught:
            runner.run(["virsh", "version"], "runtime-target-virsh-version")
        self.assertEqual(3, caught.exception.evidence.returncode)
        self.assertEqual("", caught.exception.evidence.stdout)
        self.assertEqual("[REDACTED]", caught.exception.evidence.stderr)


if __name__ == "__main__":
    unittest.main()
