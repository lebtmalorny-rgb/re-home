import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from live_discovery.run_owner import acquire_owner, cleanup_owner, complete_owner, verify_owner


class RunOwnerTests(unittest.TestCase):
    def test_acquire_is_exclusive_and_cleanup_requires_exact_token(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner = Path(temporary) / "owners" / "run-1"
            owner.parent.mkdir()
            acquire_owner(owner, "run-1", "token-one")
            with self.assertRaisesRegex(ValueError, "already exists"):
                acquire_owner(owner, "run-1", "token-two")
            with self.assertRaisesRegex(ValueError, "ownership"):
                cleanup_owner(owner, "run-1", "wrong-token")
            self.assertTrue(owner.is_dir())
            cleanup_owner(owner, "run-1", "token-one")
            self.assertFalse(owner.exists())

    def test_completion_removes_frozen_secrets_but_preserves_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner = Path(temporary) / "owners" / "run-1"
            owner.parent.mkdir()
            acquire_owner(owner, "run-1", "token-one")
            protected = owner / "protected"
            protected.mkdir(mode=0o700)
            (protected / "secret").write_text("secret", encoding="utf-8")
            complete_owner(owner, "run-1", "token-one")
            self.assertFalse(protected.exists())
            self.assertEqual("completed", verify_owner(owner, "run-1", "token-one"))
            self.assertTrue((owner / "completed.json").is_file())

    def test_failed_atomic_acquire_does_not_leave_incomplete_owner(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner = Path(temporary) / "owners" / "run-1"
            owner.parent.mkdir()
            with self.assertRaises(ValueError):
                acquire_owner(owner, "run-1", "")
            self.assertFalse(owner.exists())

    def test_each_post_lock_stage_can_remove_only_its_owned_incomplete_lock(self):
        stages = ("initialize", "source", "target", "runtime", "capability", "probe", "assemble")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for stage in stages:
                owner = root / stage
                acquire_owner(owner, stage, f"token-{stage}")
                cleanup_owner(owner, stage, f"token-{stage}")
                self.assertFalse(owner.exists(), stage)


if __name__ == "__main__":
    unittest.main()
