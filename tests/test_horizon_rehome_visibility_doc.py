import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
DOC = ROOT / "horizon-rehome-visibility-ru.md"


class HorizonRehomeVisibilityDocTests(unittest.TestCase):
    def test_doc_records_project_scope_failure_mode(self):
        text = DOC.read_text(encoding="utf-8")

        self.assertIn("/project/instances/", text)
        self.assertIn("server list --all-projects", text)
        self.assertIn("project_id", text)
        self.assertIn("role assignment", text)
        self.assertIn("source Horizon", text)
        self.assertIn("project-level visibility", text)


if __name__ == "__main__":
    unittest.main()
