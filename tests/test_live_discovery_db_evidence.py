import hashlib
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from live_discovery.db_evidence import build_db_evidence


class DbEvidenceSidecarTests(unittest.TestCase):
    def test_failed_query_sidecar_hashes_stderr_and_preserves_rc(self):
        record = {
            "side": "source",
            "query_id": "0001-nova-instances",
            "returncode": 7,
            "observed_at": "2026-07-12T09:00:07Z",
            "stderr": "database unavailable password=must-not-leak",
        }

        result = build_db_evidence(record)

        self.assertEqual(7, result["returncode"])
        self.assertEqual("command-failed", result["failure_class"])
        self.assertEqual(
            hashlib.sha256(record["stderr"].encode()).hexdigest(),
            result["stderr_sha256"],
        )
        self.assertNotIn("must-not-leak", json.dumps(result))
        self.assertEqual(
            "protected://source/db-stderr/0001-nova-instances.stderr",
            result["raw_artifact_ref"],
        )

    def test_sidecar_rejects_invalid_identity_or_naive_timestamp(self):
        base = {
            "side": "source",
            "query_id": "0001-nova-instances",
            "returncode": 0,
            "observed_at": "2026-07-12T09:00:07Z",
            "stderr": "",
        }
        for patch in (
            {"query_id": "../escape"},
            {"observed_at": "2026-07-12T09:00:07"},
            {"returncode": True},
        ):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                build_db_evidence({**base, **patch})


if __name__ == "__main__":
    unittest.main()
