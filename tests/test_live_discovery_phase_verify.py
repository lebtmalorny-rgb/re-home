import json
import tempfile
import unittest
from pathlib import Path
import sys
import subprocess

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import collect_live_control as control
from live_discovery.mysql_json import verify_plan_marker


FIXTURES = ROOT / "tests/fixtures/live_discovery/full-run"


class LiveDiscoveryVerifyPhaseTests(unittest.TestCase):
    def make_api(self, root):
        args = type("Args", (), {
            "fixture": FIXTURES / "api-input.json",
            "side": "source",
            "out": root / "api",
            "rehome_host": None,
            "cloud": None,
            "clouds_file": None,
            "container": None,
            "information_schema": None,
            "root_manifest": None,
            "probe_config": None,
            "capability_config": None,
            "phase_key_file": None,
            "phase_key_env": None,
        })()
        control._api_phase(args)
        return args.out

    def verify_args(self, api, out):
        return type("Args", (), {
            "side": "source",
            "api_result": api / "api-result.json",
            "information_schema": FIXTURES / "control-information-schema.tsv",
            "phase_key_file": None,
            "phase_key_env": None,
            "fixture_phase": True,
            "out": out,
        })()

    def test_verify_phase_writes_digest_marker_and_generated_sql(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            api = self.make_api(root)
            out = root / "verified"
            control._verify_phase(self.verify_args(api, out))
            marker = json.loads((out / "verified-plan.json").read_text())
            self.assertEqual("openstack-rehome-verified-plan/v1alpha1", marker["schema_version"])
            self.assertTrue(marker["plan_sha256"])
            self.assertEqual(
                sorted(marker["query_ids"]),
                sorted(path.stem for path in out.glob("*.sql")),
            )

    def test_tampered_signed_plan_fails_before_any_sql_is_written(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            api = self.make_api(root)
            plan_path = api / "db-query-plan.json"
            plan = json.loads(plan_path.read_text())
            plan["queries"][0]["sql"] += " SELECT 1;"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            out = root / "verified"
            with self.assertRaises(ValueError):
                control._verify_phase(self.verify_args(api, out))
            self.assertFalse(out.exists())

    def test_verified_marker_is_bound_to_the_same_plan_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            api = self.make_api(root)
            out = root / "verified"
            control._verify_phase(self.verify_args(api, out))
            plan_path = api / "db-query-plan.json"
            verify_plan_marker(plan_path, out / "verified-plan.json")
            plan = json.loads(plan_path.read_text())
            plan["queries"][0]["filters"] = {"uuid": ["00000000-0000-0000-0000-000000000000"]}
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            with self.assertRaises(ValueError):
                verify_plan_marker(plan_path, out / "verified-plan.json")

    def test_public_verify_phase_accepts_only_verified_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            api = self.make_api(root)
            process = subprocess.run(
                [sys.executable, "scripts/collect_live_control.py", "--phase", "verify",
                 "--fixture-phase", "--side", "source", "--api-result", str(api / "api-result.json"),
                 "--information-schema", str(FIXTURES / "control-information-schema.tsv"),
                 "--out", str(root / "verified-public")],
                cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(0, process.returncode, process.stderr)
            self.assertIn("PHASE=verify SIDE=source STATUS=OK", process.stdout)
