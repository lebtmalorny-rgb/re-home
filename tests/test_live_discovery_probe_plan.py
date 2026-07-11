import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

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

    def backend(self, kind, template=None):
        return {
            "kind": kind,
            "source_delegate": "source-probe",
            "target_delegate": "target-probe",
            "allowed_scopes": ["source-compute", "target-storage"],
            "probe_template": template or ("nfs" if kind == "file" else kind),
        }

    def test_empty_generic_contract_uses_controllers_and_keeps_storage_unknown(self):
        result = validate_probe_contract({}, self.plan("source"), self.plan("target"), True, "source-control", "target-control", {"source-control", "target-control"})
        self.assertEqual("source-control", result["source_delegate"])
        self.assertEqual("target-control", result["target_delegate"])
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
