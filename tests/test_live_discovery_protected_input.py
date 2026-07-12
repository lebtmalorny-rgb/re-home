import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from live_discovery.protected_input import freeze_protected_inputs


class ProtectedInputFreezeTests(unittest.TestCase):
    def _file(self, root, name, content=b"value"):
        path = root / name
        path.write_bytes(content)
        path.chmod(0o600)
        return path

    def test_freezes_owned_regular_input_once_and_ignores_later_swap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self._file(root, "token", b"first-token")
            destination = root / "owned" / "protected"
            destination.parent.mkdir(mode=0o700)
            result = freeze_protected_inputs(
                [{"key": "token", "path": str(source), "type": "token", "required": True}],
                destination,
            )
            source.write_bytes(b"replacement-token")
            self.assertEqual(b"first-token", Path(result["token"]).read_bytes())
            self.assertEqual(0o600, stat.S_IMODE(Path(result["token"]).stat().st_mode))
            self.assertEqual(0o700, stat.S_IMODE(destination.stat().st_mode))

    def test_rejects_wrong_owner_and_type_specific_oversize_before_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self._file(root, "hmac", b"x" * 4097)
            entry = [{"key": "hmac", "path": str(source), "type": "hmac", "required": True}]
            with self.assertRaisesRegex(ValueError, "size"):
                freeze_protected_inputs(entry, root / "oversized")
            source.write_bytes(b"x" * 32)
            with self.assertRaisesRegex(ValueError, "owner"):
                freeze_protected_inputs(entry, root / "wrong-owner", expected_uid=os.geteuid() + 1)
            migration = self._file(root, "migration", b"x" * (1024 * 1024 + 1))
            with self.assertRaisesRegex(ValueError, "size"):
                freeze_protected_inputs(
                    [{"key": "migration", "path": str(migration), "type": "migration", "required": True}],
                    root / "oversized-migration",
                )

    def test_rejects_symlink_and_unsafe_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = self._file(root, "real", b"{}")
            link = root / "link"
            link.symlink_to(real)
            entry = [{"key": "plan", "path": str(link), "type": "json", "required": True}]
            with self.assertRaisesRegex(ValueError, "symlink"):
                freeze_protected_inputs(entry, root / "linked")
            real.chmod(0o640)
            entry[0]["path"] = str(real)
            with self.assertRaisesRegex(ValueError, "mode"):
                freeze_protected_inputs(entry, root / "bad-mode")

    def test_optional_empty_path_is_not_materialized(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = freeze_protected_inputs(
                [{"key": "optional", "path": "", "type": "json", "required": False}],
                Path(temporary) / "protected",
            )
            self.assertEqual({}, result)


if __name__ == "__main__":
    unittest.main()
