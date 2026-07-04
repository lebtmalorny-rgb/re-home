import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / "playbooks" / "04g-apply-target-sql.yml"


class ApplyTargetSqlPlaybookTests(unittest.TestCase):
    def test_playbook_requires_apply_flag_and_uses_socket_import(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("target_db_import_apply: false", text)
        self.assertIn("target_db_import_strip_hard_stop: false", text)
        self.assertIn("10-keystone-projects-users-optional.sql", text)
        self.assertIn("prepare_target_sql_import.py", text)
        self.assertIn("--socket={{ target_db_import_socket | quote }}", text)
        self.assertIn("--replace-literal", text)
        self.assertIn("--replace-column", text)


if __name__ == "__main__":
    unittest.main()
