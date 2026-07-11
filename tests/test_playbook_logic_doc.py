import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
DOC = ROOT / "playbook-logic-ru.md"
PLAYBOOK_DIR = ROOT / "playbooks"


class PlaybookLogicDocTests(unittest.TestCase):
    def test_every_top_level_playbook_has_a_section(self):
        text = DOC.read_text(encoding="utf-8")
        playbooks = sorted(path.name for path in PLAYBOOK_DIR.glob("*.yml"))

        for playbook in playbooks:
            with self.subTest(playbook=playbook):
                self.assertIn(f"### `{playbook}`", text)

    def test_live_discovery_section_matches_actual_orchestration(self):
        text = DOC.read_text(encoding="utf-8")
        section = text.split("### `02b-discover-live-resource-graph.yml`", 1)[1].split("\n### `", 1)[0]
        for needle in (
            "семь plays", "--phase api", "--phase verify", "--phase combine",
            "verify-before-SQL", "source-control.json", "target-control.json",
            "runtime.json", "READY_WITH_WARNINGS=0", "UNKNOWN=2", "BLOCKED=3",
        ):
            self.assertIn(needle, section)


if __name__ == "__main__":
    unittest.main()
