import unittest
import sys
import hashlib
import hmac
import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from live_discovery import probe_plan
from live_discovery.probe_plan import validate_probe_contract


def glance(images=None):
    return {
        "endpoint_url": "https://glance.example",
        "token_env": "LIVE_DISCOVERY_GLANCE_TOKEN",
        "images": images or [],
        "store_capabilities": [],
    }


class LiveDiscoveryProbePlanTests(unittest.TestCase):
    def plan(self, side, entries=None):
        return {
            "schema_version": "openstack-rehome-probe-config/v1alpha1",
            "storage": entries or [],
            "glance": glance(),
        }

    def backend(self, kind, template=None, source="source-probe", target="target-probe"):
        return {
            "kind": kind,
            "source_delegate": source,
            "target_delegate": target,
            "allowed_scopes": ["source-compute", "target-storage"],
            "probe_template": template or ("nfs" if kind == "file" else kind),
        }

    def test_empty_generic_contract_uses_controllers_and_keeps_storage_unknown(self):
        result = validate_probe_contract({}, self.plan("source"), self.plan("target"), True, "source-control", "target-control", {"source-control", "target-control"})
        self.assertEqual(["source-control"], result["source_delegates"])
        self.assertEqual(["target-control"], result["target_delegates"])
        self.assertEqual([], result["source_groups"][0]["probe_plan"]["storage"])
        self.assertEqual([], result["backend_kinds"])

    def test_nfs_file_rbd_lvm_and_vendor_contracts_are_explicit(self):
        for kind, template in (("nfs", "nfs"), ("file", "nfs"), ("rbd", "rbd"), ("lvm", "lvm"), ("vendor_x", "unsupported")):
            with self.subTest(kind=kind):
                backends = {"backend": self.backend(kind, template)}
                source = self.plan("source", [{"backend_id":"backend", "kind":kind, "scope":"source-compute"}])
                target = self.plan("target", [{"backend_id":"backend", "kind":kind, "scope":"target-storage"}])
                result = validate_probe_contract(backends, source, target, True, "source-control", "target-control", {"source-control", "target-control", "source-probe", "target-probe"})
                self.assertEqual([kind], result["backend_kinds"])
                self.assertEqual(template != "unsupported", result["supported"]["backend"])

    def test_rejects_plan_kind_delegate_scope_and_range_mismatches(self):
        backends = {"backend": self.backend("rbd")}
        good_source = self.plan("source", [{"backend_id":"backend", "kind":"rbd", "scope":"source-compute"}])
        good_target = self.plan("target", [{"backend_id":"backend", "kind":"rbd", "scope":"target-storage"}])
        bad_kind = self.plan("source", [{"backend_id":"backend", "kind":"lvm", "scope":"source-compute"}])
        with self.assertRaises(ValueError):
            validate_probe_contract(backends, bad_kind, good_target, True, "source-control", "target-control", {"source-probe", "target-probe"})
        bad_delegate = {"backend": {**self.backend("rbd"), "source_delegate":"missing"}}
        with self.assertRaises(ValueError):
            validate_probe_contract(bad_delegate, good_source, good_target, True, "source-control", "target-control", {"source-probe", "target-probe"})
        ranged = self.plan("source"); ranged["glance"] = glance([{"image_id":"x"}])
        with self.assertRaises(ValueError):
            validate_probe_contract({}, ranged, self.plan("target"), False, "source-control", "target-control", {"source-control", "target-control"})

    def test_mixed_nfs_rbd_lvm_probes_are_grouped_per_delegate_deterministically(self):
        backends = {
            "rbd-a": self.backend("rbd", source="source-rbd", target="target-rbd"),
            "nfs-a": self.backend("nfs", source="source-nfs", target="target-nfs"),
            "lvm-a": self.backend("lvm", source="source-lvm", target="target-lvm"),
        }
        source = self.plan("source", [
            {"backend_id": backend_id, "kind": kind, "scope": "source-compute", "resource": backend_id}
            for backend_id, kind in (("nfs-a", "nfs"), ("rbd-a", "rbd"), ("lvm-a", "lvm"))
        ])
        target = self.plan("target", [
            {"backend_id": backend_id, "kind": kind, "scope": "target-storage", "resource": backend_id}
            for backend_id, kind in (("rbd-a", "rbd"), ("lvm-a", "lvm"), ("nfs-a", "nfs"))
        ])
        hosts = {
            "source-control", "target-control", "source-nfs", "source-rbd",
            "source-lvm", "target-nfs", "target-rbd", "target-lvm",
        }

        result = validate_probe_contract(
            backends, source, target, True,
            "source-control", "target-control", hosts,
        )

        self.assertNotIn("source_delegate", result)
        self.assertNotIn("target_delegate", result)
        self.assertEqual(
            ["source-lvm", "source-nfs", "source-rbd"],
            result["source_delegates"],
        )
        self.assertEqual(
            ["target-lvm", "target-nfs", "target-rbd"],
            result["target_delegates"],
        )
        self.assertEqual(
            [
                {"delegate": item["delegate"], "phase_id": item["phase_id"]}
                for item in result["source_groups"]
            ],
            result["source_phase_manifest"],
        )
        for side, scope in (("source", "source-compute"), ("target", "target-storage")):
            groups = result[f"{side}_groups"]
            self.assertEqual(result[f"{side}_delegates"], [item["delegate"] for item in groups])
            self.assertEqual(len(groups), len({item["phase_id"] for item in groups}))
            for group in groups:
                self.assertEqual(64, len(group["phase_id"]))
                self.assertEqual(
                    group["backend_ids"],
                    sorted({item["backend_id"] for item in group["probe_plan"]["storage"]}),
                )
                self.assertTrue(all(item["scope"] == scope for item in group["probe_plan"]["storage"]))
                self.assertEqual(source["glance"] if side == "source" else target["glance"], group["probe_plan"]["glance"])

    def test_signed_delegate_phases_merge_storage_and_bind_provenance(self):
        key = b"0123456789abcdef0123456789abcdef"
        side = "source"
        api_common = {
            "rehome_host": "compute-1",
            "instances": [],
            "roots": {"hosts": ["compute-1"]},
            "available_tables": ["nova.instances"],
            "openstack": [],
            "image_store_ids": {},
            "glance_catalog_origin": "https://glance.example",
        }
        filters = {
            "schema_version": "openstack-rehome-uuid-filters/v1alpha1",
            "side": side,
            "filters": [],
        }
        plan = {
            "schema_version": "openstack-rehome-db-query-plan/v1alpha1",
            "side": side,
            "queries": [],
        }
        glance = [{
            "image_id": "11111111-1111-4111-8111-111111111111",
            "endpoint_origin": "https://glance.example", "expected_size": 1,
            "observed_size": 1, "required": True, "store_ids": ["store-a"],
            "evidence_id": "glance-range:11111111-1111-4111-8111-111111111111",
            "status": "PASS", "reason": "ok",
        }]

        def canonical(value):
            return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))

        def write_phase(root, delegate, backend):
            phase_id = hashlib.sha256(f"{side}\0{delegate}".encode()).hexdigest()
            directory = root / phase_id
            directory.mkdir()
            api = {
                "schema_version": "openstack-rehome-control-api-result/v1alpha1",
                "side": side,
                "api_result": {
                    **api_common,
                    "storage_probe_results": [{
                        "volume_id": f"{len(backend):08d}-1111-4111-8111-111111111111",
                        "scope": "source-compute", "kind": backend,
                        "backend_identity": backend, "resource_identity": backend,
                        "resource_fingerprint": hashlib.sha256(f"{backend}:{backend}".encode()).hexdigest(),
                        "expected_size": 1, "observed_size": 1,
                        "evidence_id": f"storage:{backend}", "status": "PASS", "reason": "ok",
                    }],
                    "glance_data_probe_results": glance,
                    "glance_store_capabilities": [{"store_id": "store-a", "backend_type": "rbd"}],
                },
            }
            binding = hmac.new(
                key,
                ("openstack-rehome-phase:live:v1\n" + canonical({
                    "api_result": api,
                    "uuid_filters": filters,
                    "db_query_plan": plan,
                })).encode(),
                hashlib.sha256,
            ).hexdigest()
            for name, payload in (
                ("api-result.json", {**api, "binding_sha256": binding}),
                ("uuid-filters.json", {**filters, "binding_sha256": binding}),
                ("db-query-plan.json", {**plan, "binding_sha256": binding}),
            ):
                (directory / name).write_text(json.dumps(payload), encoding="utf-8")
            return {"delegate": delegate, "phase_id": phase_id, "directory": str(directory)}

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            phases = [
                write_phase(root, "source-rbd", "rbd"),
                write_phase(root, "source-nfs", "nfs"),
                write_phase(root, "source-lvm", "lvm"),
            ]
            output = root / "merged"
            key_file = root / "phase-hmac.key"
            key_file.write_bytes(key)
            completed = subprocess.run(
                [
                    sys.executable, str(ROOT / "scripts/live_discovery/probe_plan.py"),
                    "merge-phases", "--side", side,
                    "--phase-key-file", str(key_file),
                    "--phases-json", json.dumps([
                        {"delegate": item["delegate"], "phase_id": item["phase_id"]}
                        for item in reversed(phases)
                    ]),
                    "--phase-root", str(root),
                    "--out", str(output),
                ],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
            merged = json.loads((output / "api-result.json").read_text(encoding="utf-8"))

        self.assertEqual(
            ["storage:lvm", "storage:nfs", "storage:rbd"],
            [item["evidence_id"] for item in merged["api_result"]["storage_probe_results"]],
        )
        provenance = merged["api_result"]["probe_delegate_provenance"]
        self.assertEqual(["source-lvm", "source-nfs", "source-rbd"], [item["delegate"] for item in provenance])
        self.assertTrue(all(len(item["phase_binding_sha256"]) == 64 for item in provenance))
        self.assertEqual(glance, merged["api_result"]["glance_data_probe_results"])

    def test_merge_rejects_tampered_delegate_binding(self):
        with self.assertRaises(ValueError):
            probe_plan.merge_probe_documents(
                "source", b"0123456789abcdef",
                [{
                    "delegate": "source-nfs", "phase_id": "invalid",
                    "api-result.json": {}, "uuid-filters.json": {}, "db-query-plan.json": {},
                }],
            )
