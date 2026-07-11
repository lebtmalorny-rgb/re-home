import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "live_discovery" / "full-run"


class LiveDiscoveryCliTests(unittest.TestCase):
    def run_assembler(self, fixture, out):
        return subprocess.run([sys.executable, "scripts/assemble_live_discovery.py", "--fixture-dir", str(FIXTURES / fixture), "--out-dir", str(out)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)

    def test_fixture_verdict_exit_codes_and_artifact_set(self):
        expected = {"ready": 0, "warnings": 0, "unknown": 2, "blocked": 3}
        with tempfile.TemporaryDirectory() as temporary:
            for name, code in expected.items():
                with self.subTest(name=name):
                    out = Path(temporary) / name
                    proc = self.run_assembler(name, out)
                    self.assertEqual(code, proc.returncode, proc.stderr)
                    self.assertTrue((out / "readiness-report.md").is_file())
                    self.assertEqual(code, json.loads((out / "readiness-report.json").read_text())["exit_code"])

    def test_fixture_and_live_arguments_are_mutually_exclusive(self):
        proc = subprocess.run([sys.executable, "scripts/assemble_live_discovery.py", "--fixture-dir", str(FIXTURES / "ready"), "--source-control", "a", "--target-control", "b", "--runtime", "c", "--schema-policy", "d", "--out-dir", "/tmp/no-write"], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertNotEqual(0, proc.returncode)
        self.assertNotIn("Traceback", proc.stderr)

    def test_collect_api_builds_scoped_select_only_plan(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / "out"
            proc = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "api", "--side", "source", "--fixture", str(FIXTURES / "api-input.json"), "--out", str(out)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(0, proc.returncode, proc.stderr)
            plan = json.loads((out / "db-query-plan.json").read_text())
            self.assertTrue(plan["queries"])
            for query in plan["queries"]:
                self.assertTrue(query["filters"])
                self.assertTrue(query["sql"].lstrip().upper().startswith("SELECT JSON_OBJECT"))
                self.assertIn(" WHERE ", " ".join(query["sql"].split()).upper())

    def test_combine_rejects_missing_and_nonzero_rc(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            api = root / "api"
            proc = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "api", "--side", "source", "--fixture", str(FIXTURES / "api-input.json"), "--out", str(api)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(0, proc.returncode, proc.stderr)
            db = root / "db"
            db.mkdir()
            combine = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "combine", "--side", "source", "--api-result", str(api / "api-result.json"), "--db-jsonl-dir", str(db), "--information-schema", str(FIXTURES / "information-schema.jsonl"), "--schema-policy", str(FIXTURES / "schema-policy.json"), "--out", str(root / "combined")], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertNotEqual(0, combine.returncode)
            self.assertNotIn("Traceback", combine.stderr)

    def test_collect_rejects_symlink_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            link = Path(temporary) / "fixture.json"
            link.symlink_to(FIXTURES / "api-input.json")
            proc = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "api", "--side", "source", "--fixture", str(link), "--out", str(Path(temporary) / "out")], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertNotEqual(0, proc.returncode)

    def test_collect_fixture_and_live_arguments_are_mutually_exclusive(self):
        with tempfile.TemporaryDirectory() as temporary:
            proc = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "api", "--side", "source", "--fixture", str(FIXTURES / "api-input.json"), "--rehome-host", "compute-023", "--cloud", "cloud", "--clouds-file", "/clouds.yaml", "--container", "toolbox", "--out", str(Path(temporary) / "out")], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertNotEqual(0, proc.returncode)

    def test_combine_rejects_query_plan_sql_tampering(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            api = root / "api"
            proc = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "api", "--side", "source", "--fixture", str(FIXTURES / "api-input.json"), "--out", str(api)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(0, proc.returncode, proc.stderr)
            plan_path = api / "db-query-plan.json"
            plan = json.loads(plan_path.read_text())
            query = plan["queries"][0]
            query["sql"] = query["sql"].replace("11111111-1111-1111-1111-111111111111", "99999999-9999-9999-9999-999999999999")
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            db = root / "db"
            db.mkdir()
            (db / query["rc_file"]).write_text("0\n", encoding="ascii")
            (db / query["jsonl_file"]).write_text(json.dumps({"_schema": "nova", "_table": "instances", "row": {"uuid": "11111111-1111-1111-1111-111111111111"}}) + "\n", encoding="utf-8")
            combine = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "combine", "--side", "source", "--api-result", str(api / "api-result.json"), "--db-jsonl-dir", str(db), "--information-schema", str(FIXTURES / "information-schema.jsonl"), "--schema-policy", str(FIXTURES / "schema-policy.json"), "--out", str(root / "combined")], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertNotEqual(0, combine.returncode)

    def test_combine_rejects_unplanned_output_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            api = root / "api"
            proc = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "api", "--side", "source", "--fixture", str(FIXTURES / "api-input.json"), "--out", str(api)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(0, proc.returncode, proc.stderr)
            query = json.loads((api / "db-query-plan.json").read_text())["queries"][0]
            db = root / "db"
            db.mkdir()
            (db / query["rc_file"]).write_text("0\n", encoding="ascii")
            (db / query["jsonl_file"]).write_text(json.dumps({"_schema": "nova", "_table": "instances", "row": {"uuid": "11111111-1111-1111-1111-111111111111"}}) + "\n", encoding="utf-8")
            (db / "unplanned.jsonl").write_text("{}\n", encoding="utf-8")
            combine = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "combine", "--side", "source", "--api-result", str(api / "api-result.json"), "--db-jsonl-dir", str(db), "--information-schema", str(ROOT / "tests/fixtures/live_discovery/source-information-schema.tsv"), "--schema-policy", str(FIXTURES / "schema-policy.json"), "--out", str(root / "combined")], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertNotEqual(0, combine.returncode)

    def test_combine_accepts_exact_jsonl_envelope_and_writes_assembler_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            api = root / "api"
            create = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "api", "--side", "source", "--fixture", str(FIXTURES / "api-input.json"), "--out", str(api)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(0, create.returncode, create.stderr)
            query = json.loads((api / "db-query-plan.json").read_text())["queries"][0]
            db = root / "db"
            db.mkdir()
            (db / query["rc_file"]).write_text("0\n", encoding="ascii")
            (db / query["jsonl_file"]).write_text(json.dumps({"_schema": "nova", "_table": "instances", "row": {"uuid": "11111111-1111-1111-1111-111111111111"}}) + "\n", encoding="utf-8")
            out = root / "combined"
            combine = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "combine", "--side", "source", "--api-result", str(api / "api-result.json"), "--db-jsonl-dir", str(db), "--information-schema", str(ROOT / "tests/fixtures/live_discovery/source-information-schema.tsv"), "--schema-policy", str(FIXTURES / "schema-policy.json"), "--out", str(out)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(0, combine.returncode, combine.stderr)
            bundle = json.loads((out / "control-result.json").read_text())
            self.assertEqual("openstack-rehome-control-bundle/v1alpha1", bundle["schema_version"])
            self.assertTrue(bundle["collectors"])
            self.assertEqual({"source", "target"}, set(bundle["uuid_filters"]))

    def test_combine_rejects_nonzero_malformed_and_provenance_mismatch(self):
        for mode in ("nonzero", "malformed", "provenance"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                api = root / "api"
                create = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "api", "--side", "source", "--fixture", str(FIXTURES / "api-input.json"), "--out", str(api)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                self.assertEqual(0, create.returncode, create.stderr)
                query = json.loads((api / "db-query-plan.json").read_text())["queries"][0]
                db = root / "db"
                db.mkdir()
                (db / query["rc_file"]).write_text("9\n" if mode == "nonzero" else "0\n", encoding="ascii")
                record = {"_schema": "wrong" if mode == "provenance" else "nova", "_table": "instances", "row": {"uuid": "11111111-1111-1111-1111-111111111111"}}
                (db / query["jsonl_file"]).write_text("not-json\n" if mode == "malformed" else json.dumps(record) + "\n", encoding="utf-8")
                combine = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "combine", "--side", "source", "--api-result", str(api / "api-result.json"), "--db-jsonl-dir", str(db), "--information-schema", str(ROOT / "tests/fixtures/live_discovery/source-information-schema.tsv"), "--schema-policy", str(FIXTURES / "schema-policy.json"), "--out", str(root / "combined")], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                self.assertNotEqual(0, combine.returncode)
                self.assertNotIn("Traceback", combine.stderr)

    def test_all_normal_outputs_are_resanitized_and_sensitive_is_separate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = root / "fixture"
            fixture.mkdir()
            bundle = json.loads((FIXTURES / "ready/bundle.json").read_text())
            bundle["schema_capabilities"]["nova"]["api_token"] = "chap-secret-value"
            bundle["sensitive_evidence"] = {"attachment-1": {"connection_info": "chap-secret-value"}}
            (fixture / "bundle.json").write_text(json.dumps(bundle), encoding="utf-8")
            (fixture / "schema-policy.json").write_text((FIXTURES / "schema-policy.json").read_text(), encoding="utf-8")
            out = root / "out"
            proc = subprocess.run([sys.executable, "scripts/assemble_live_discovery.py", "--fixture-dir", str(fixture), "--out-dir", str(out)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(0, proc.returncode, proc.stderr)
            normal = "\n".join(path.read_text(encoding="utf-8") for path in out.rglob("*") if path.is_file() and "sensitive" not in path.parts)
            self.assertNotIn("chap-secret-value", normal)
            self.assertIn("[REDACTED]", normal)
            self.assertIn("chap-secret-value", (out / "sensitive/evidence.json").read_text())

    def test_live_assembler_builds_directional_mapping_from_schema_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = json.loads((FIXTURES / "ready/bundle.json").read_text())
            column = {"name": "id", "ordinal": 1, "column_type": "varchar(36)", "nullable": False, "default": None, "extra": ""}
            bundle["schema_capabilities"].update({
                "source-information-schema": {"tables": {"nova.instances": {"id": column}}, "used_columns": {"nova.instances": ["id"]}},
                "target-information-schema": {"tables": {"nova.instances": {"id": column}}, "used_columns": {"nova.instances": ["id"]}},
            })
            for name in ("source.json", "target.json", "runtime.json"):
                (root / name).write_text(json.dumps(bundle), encoding="utf-8")
            out = root / "out"
            proc = subprocess.run([sys.executable, "scripts/assemble_live_discovery.py", "--source-control", str(root / "source.json"), "--target-control", str(root / "target.json"), "--runtime", str(root / "runtime.json"), "--schema-policy", str(ROOT / "inventory/live-discovery-schema-policy.json"), "--out-dir", str(out)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(2, proc.returncode, proc.stderr)
            mapping = json.loads((out / "schema-mapping.json").read_text())
            self.assertEqual("openstack-rehome-directional-schema-mapping/v1alpha1", mapping["schema_version"])
            self.assertEqual("COMMON_COMPATIBLE", mapping["tables"]["nova.instances"][0]["classification"])

    def test_live_assembler_accepts_raw_runtime_collector_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle_text = (FIXTURES / "ready/bundle.json").read_text()
            (root / "source.json").write_text(bundle_text, encoding="utf-8")
            (root / "target.json").write_text(bundle_text, encoding="utf-8")
            runtime = {"schema_version":"openstack-rehome-live-discovery/v1alpha1","service":"runtime","side":"source","nodes":[{"kind":"runtime_evidence","id":"source-runtime-raw","side":"source","facts":{},"evidence_ids":[],"key":"runtime_evidence:source-runtime-raw"}],"edges":[],"checks":[],"unknowns":[],"blockers":[],"evidence":[]}
            (root / "runtime.json").write_text(json.dumps(runtime), encoding="utf-8")
            out = root / "out"
            proc = subprocess.run([sys.executable, "scripts/assemble_live_discovery.py", "--source-control", str(root / "source.json"), "--target-control", str(root / "target.json"), "--runtime", str(root / "runtime.json"), "--schema-policy", str(FIXTURES / "schema-policy.json"), "--out-dir", str(out)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(2, proc.returncode, proc.stderr)
            self.assertTrue((out / "resource-graph.json").is_file())


if __name__ == "__main__":
    unittest.main()
