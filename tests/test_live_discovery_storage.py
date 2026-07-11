import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from live_discovery.storage import probe_storage


class Evidence:
    def __init__(self, stdout, evidence_id="storage-probe"):
        self.stdout = stdout
        self.evidence_id = evidence_id


class RecordingRunner:
    def __init__(self, stdout="{\"size\": 1073741824}", error=None):
        self.stdout = stdout
        self.error = error
        self.commands = []

    def run(self, argv, evidence_id):
        self.commands.append(list(argv))
        if self.error:
            raise self.error
        return Evidence(self.stdout, evidence_id)


class StorageProbeTests(unittest.TestCase):
    def test_nfs_probe_uses_stat_without_mounting(self):
        runner = RecordingRunner()
        check = probe_storage(
            "nfs",
            {"path": "/srv/cinder/volume-volume-1", "expected_size": 1073741824},
            runner,
        )
        self.assertEqual("PASS", check.status)
        self.assertEqual(
            ["stat", "--format", "%s", "/srv/cinder/volume-volume-1"],
            runner.commands[0],
        )

    def test_rbd_probe_uses_info_only(self):
        runner = RecordingRunner('{"size": 1073741824}')
        check = probe_storage(
            "rbd", {"pool": "volumes", "image": "volume-volume-1", "expected_size": 1073741824}, runner
        )
        self.assertEqual("PASS", check.status)
        self.assertEqual(["rbd", "info", "--format", "json", "volumes/volume-volume-1"], runner.commands[0])

    def test_lvm_probe_uses_lvs_without_activation(self):
        runner = RecordingRunner(json.dumps({"report": [{"lv": [{"lv_size": "1073741824"}]}]}))
        check = probe_storage(
            "lvm", {"vg": "cinder-volumes", "lv": "volume-volume-1", "expected_size": 1073741824}, runner
        )
        self.assertEqual("PASS", check.status)
        self.assertEqual(
            ["lvs", "--reportformat", "json", "--units", "b", "--nosuffix", "cinder-volumes/volume-volume-1"],
            runner.commands[0],
        )

    def test_unknown_storage_driver_is_unknown(self):
        check = probe_storage("vendor-array-x", {"id": "volume-1"}, RecordingRunner())
        self.assertEqual("UNKNOWN", check.status)

    def test_malformed_paths_and_names_block_without_probe(self):
        cases = [
            ("nfs", {"path": "/srv/cinder/../etc/passwd"}),
            ("nfs", {"path": "relative/volume"}),
            ("rbd", {"pool": "volumes/other", "image": "volume-1"}),
            ("lvm", {"vg": "cinder volumes", "lv": "volume-1"}),
        ]
        for kind, resource in cases:
            with self.subTest(kind=kind, resource=resource):
                runner = RecordingRunner()
                check = probe_storage(kind, resource, runner)
                self.assertEqual("BLOCKED", check.status)
                self.assertEqual([], runner.commands)

    def test_size_mismatch_is_blocked(self):
        check = probe_storage(
            "rbd", {"pool": "volumes", "image": "volume-volume-1", "expected_size": 2}, RecordingRunner('{"size": 1}')
        )
        self.assertEqual("BLOCKED", check.status)
        self.assertEqual("backing object size mismatch", check.reason)

    def test_unreadable_probe_exception_is_sanitized(self):
        runner = RecordingRunner(error=RuntimeError("password=do-not-leak"))
        check = probe_storage(
            "nfs", {"path": "/srv/cinder/volume-volume-1"}, runner
        )
        self.assertEqual("BLOCKED", check.status)
        self.assertNotIn("do-not-leak", json.dumps(check.to_dict()))

    def test_malformed_probe_output_is_blocked(self):
        check = probe_storage(
            "rbd", {"pool": "volumes", "image": "volume-volume-1"}, RecordingRunner("not-json-secret")
        )
        self.assertEqual("BLOCKED", check.status)
        self.assertNotIn("not-json-secret", json.dumps(check.to_dict()))


if __name__ == "__main__":
    unittest.main()
