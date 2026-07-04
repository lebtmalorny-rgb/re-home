import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_target_preimport_guard


def write_rows(root, service, content):
    rows_dir = root / "rows"
    rows_dir.mkdir(parents=True, exist_ok=True)
    (rows_dir / f"{service}.tsv").write_text(content, encoding="utf-8")
    (rows_dir / f"{service}.rc").write_text("0\n", encoding="utf-8")


class TargetPreImportGuardTests(unittest.TestCase):
    def test_empty_target_rows_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            write_rows(root, "neutron", "BEGIN neutron.ports\nEND neutron.ports\n")

            report = check_target_preimport_guard.build_report(root)

            self.assertTrue(report["passed"])
            self.assertEqual(report["summary"]["conflicting_rows"], 0)

    def test_existing_target_rows_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            write_rows(
                root,
                "neutron",
                "BEGIN neutron.ports\n"
                "0333a723-8f93-4d00-a9c6-9a8af62c4c68\te1c2f8d7-33b8-44b8-8ea7-222b6be4c62b\n"
                "END neutron.ports\n",
            )

            report = check_target_preimport_guard.build_report(root)

            self.assertFalse(report["passed"])
            self.assertEqual(report["summary"]["conflicting_rows"], 1)
            self.assertEqual(report["conflicts"][0]["table"], "neutron.ports")
            self.assertEqual(report["conflicts"][0]["service"], "neutron")


if __name__ == "__main__":
    unittest.main()
