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


if __name__ == "__main__":
    unittest.main()
