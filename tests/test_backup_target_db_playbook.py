import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / "playbooks" / "04f-backup-target-db.yml"


class TargetDbBackupPlaybookTests(unittest.TestCase):
    def test_kolla_dump_defaults_to_container_socket(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn('target_db_backup_socket: "/run/mysqld/mysqld.sock"', text)
        self.assertIn("dump_connection_args=(--socket={{ target_db_backup_socket | quote }})", text)
        self.assertNotIn('target_db_backup_host: "127.0.0.1"', text)


if __name__ == "__main__":
    unittest.main()
