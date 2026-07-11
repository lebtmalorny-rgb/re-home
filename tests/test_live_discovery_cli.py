import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "live_discovery" / "full-run"
sys.path.insert(0, str(ROOT / "scripts"))

from live_discovery.contract import CheckResult, CollectorResult, ResourceNode
from collect_live_control import _CombinedClient, _TABLE_ROOT_FILTERS, _api_phase, _collector_table_catalog, _execute_probe_config, _expected_plan_tables, _integrate_storage_readiness
from live_discovery.cinder import CORE_TABLES as CINDER_CORE, OPTIONAL_TABLES as CINDER_OPTIONAL
from live_discovery.neutron import CORE_TABLES as NEUTRON_CORE, OPTIONAL_TABLE_FAMILIES as NEUTRON_OPTIONAL
from live_discovery.nova import DB_SCHEMAS, DB_TABLES


class LiveDiscoveryCliTests(unittest.TestCase):
    def test_live_like_api_acquisition_builds_complete_nova_plan_from_live_schema(self):
        instance_id = "11111111-1111-1111-1111-111111111111"
        service_id = "88888888-8888-8888-8888-888888888888"
        compute_id = "99999999-9999-9999-9999-999999999999"
        class Client:
            def __init__(self, *args): pass
            def json(self, command, evidence_id):
                if command[:2] == ["server", "list"]:
                    payload = [{"id": instance_id, "host": "compute-023"}]
                elif command[:3] == ["compute", "service", "list"]:
                    payload = [{"uuid": service_id, "host": "compute-023"}]
                elif command[:2] == ["hypervisor", "show"]:
                    payload = {"uuid": compute_id, "host": "compute-023"}
                elif command[:3] == ["resource", "provider", "list"]:
                    payload = [{"uuid": compute_id, "name": "compute-023"}]
                elif command[:2] == ["server", "show"]:
                    payload = {"id": instance_id, "project_id": "77777777-7777-7777-7777-777777777777", "image": {"id": "44444444-4444-4444-4444-444444444444"}}
                elif command[:2] == ["port", "list"] or command[:3] == ["server", "volume", "list"]:
                    payload = []
                else:
                    raise AssertionError(command)
                return payload, {"id": evidence_id}
        with tempfile.TemporaryDirectory() as temporary:
            args = type("Args", (), {
                "fixture": None, "rehome_host": "compute-023", "cloud": "cloud",
                "clouds_file": Path("/clouds.yaml"), "container": "toolbox",
                "side": "source", "information_schema": FIXTURES / "control-information-schema.tsv",
                "root_manifest": None, "probe_config": None, "capability_config": None,
                "out": Path(temporary) / "api",
            })()
            with mock.patch("live_discovery.openstack.OpenStackClient", Client):
                _api_phase(args)
            plan = json.loads((args.out / "db-query-plan.json").read_text())
            self.assertEqual(_collector_table_catalog()["nova"], {f"{item['schema']}.{item['table']}" for item in plan["queries"]})
            self.assertTrue(all(item["filters"] for item in plan["queries"]))
    def test_full_root_plan_catalog_equals_all_collector_db_table_calls(self):
        catalog = _collector_table_catalog()
        self.assertEqual({f"{DB_SCHEMAS[table]}.{table}" for table in DB_TABLES}, catalog["nova"])
        self.assertEqual({f"neutron.{table}" for table in set(NEUTRON_CORE) | {table for family in NEUTRON_OPTIONAL.values() for table in family}}, catalog["neutron"])
        self.assertEqual({f"cinder.{table}" for table in set(CINDER_CORE) | set(CINDER_OPTIONAL)}, catalog["cinder"])
        roots = {
            category: ["11111111-1111-1111-1111-111111111111"]
            for choices in _TABLE_ROOT_FILTERS.values()
            for category, _ in choices
        }
        expected = _expected_plan_tables("source", roots, set().union(*catalog.values()))
        self.assertEqual(set().union(*catalog.values()), expected)
    def test_task7_and_task8_probe_results_are_typed_and_handed_to_collectors(self):
        volume_id = "22222222-2222-2222-2222-222222222222"
        image_id = "44444444-4444-4444-4444-444444444444"
        api_result = {
            "openstack": [],
            "glance_store_capabilities": [{"store_id": "store-1", "backend_type": "rbd"}],
            "glance_data_probe_results": [{"image_id": image_id, "status": "PASS", "reason": "Glance image data byte is readable"}],
            "storage_probe_results": [
                {"volume_id": volume_id, "scope": "source-compute", "kind": "nfs", "status": "PASS", "reason": "backing object is readable with expected size"},
                {"volume_id": volume_id, "scope": "target-storage", "kind": "rbd", "status": "PASS", "reason": "backing object is readable with expected size"},
                {"volume_id": volume_id, "scope": "target-storage", "kind": "lvm", "status": "PASS", "reason": "backing object is readable with expected size"},
                {"volume_id": volume_id, "scope": "target-storage", "kind": "vendor-san", "status": "UNKNOWN", "reason": "storage driver is unsupported"},
            ],
        }
        client = _CombinedClient("source", api_result, [], [])
        capabilities, evidence = client.glance_store_capabilities("glance-source-store-capabilities")
        self.assertEqual("rbd", capabilities[0]["backend_type"])
        self.assertEqual("glance-source-store-capabilities", evidence["evidence_id"])
        self.assertEqual("PASS", client.probe_image_data(image_id, 1, True).status)
        cinder = CollectorResult(service="cinder", side="source", nodes=[ResourceNode("volume", volume_id, "source")])
        _integrate_storage_readiness(cinder, [volume_id], api_result)
        self.assertEqual({"nfs", "rbd", "lvm", "vendor-san"}, {check.check_id.rsplit(".", 1)[-1] for check in cinder.checks})
        self.assertIn("storage driver is unsupported", cinder.unknowns)

    def test_missing_required_storage_and_glance_probe_results_fail_closed(self):
        volume_id = "22222222-2222-2222-2222-222222222222"
        image_id = "44444444-4444-4444-4444-444444444444"
        cinder = CollectorResult(service="cinder", side="source", nodes=[ResourceNode("volume", volume_id, "source")])
        _integrate_storage_readiness(cinder, [volume_id], {})
        self.assertTrue(any("storage probe evidence missing" in value for value in cinder.unknowns))
        client = _CombinedClient("source", {"openstack": []}, [], [])
        self.assertEqual("UNKNOWN", client.probe_image_data(image_id, 1, True).status)

    def test_probe_config_executes_storage_and_ephemeral_glance_token_is_not_serialized(self):
        from io import BytesIO
        volume_id = "22222222-2222-2222-2222-222222222222"
        image_id = "44444444-4444-4444-4444-444444444444"
        class Runner:
            def run(self, argv, evidence_id):
                if argv[0] == "stat": stdout = "1"
                elif argv[0] == "rbd": stdout = '{"size":1}'
                else: stdout = '{"report":[{"lv":[{"lv_size":"1.00"}]}]}'
                return type("Evidence", (), {"stdout": stdout, "evidence_id": evidence_id})()
        class Response:
            status = 206
            headers = {"Content-Range": "bytes 0-0/1", "Content-Length": "1"}
            def read(self, size): return b"x"[:size]
            def geturl(self): return f"https://glance.example/v2/images/{image_id}/file"
            def close(self): pass
        class Opener:
            def open(self, request, timeout=None):
                self.authorization = request.headers["X-auth-token"]
                return Response()
        config = {
            "schema_version": "openstack-rehome-probe-config/v1alpha1",
            "storage": [
                {"volume_id":volume_id,"scope":"source-compute","kind":"file","resource":{"path":"/srv/cinder/volume-1","allowed_roots":["/srv/cinder"],"expected_size":1}},
                {"volume_id":volume_id,"scope":"target-storage","kind":"rbd","resource":{"pool":"volumes","allowed_pools":["volumes"],"image":"volume-1","expected_size":1}},
                {"volume_id":volume_id,"scope":"target-storage","kind":"lvm","resource":{"vg":"cinder-volumes","allowed_vgs":["cinder-volumes"],"lv":"volume-1","expected_size":1}},
                {"volume_id":volume_id,"scope":"target-storage","kind":"vendor-san","resource":{"expected_size":1}}
            ],
            "glance": {"endpoint_url":"https://glance.example","token_file":"/secure/token","images":[{"image_id":image_id,"expected_size":1,"required":True}],"store_capabilities":[{"store_id":"store-1","backend_type":"rbd"}]}
        }
        opener = Opener()
        results = _execute_probe_config(config, Runner(), opener=opener, token_loader=lambda path: "ephemeral-token-value")
        self.assertEqual(["PASS", "PASS", "PASS", "UNKNOWN"], [item["status"] for item in results["storage_probe_results"]])
        self.assertEqual("PASS", results["glance_data_probe_results"][0]["status"])
        self.assertEqual("ephemeral-token-value", opener.authorization)
        self.assertNotIn("ephemeral-token-value", json.dumps(results))
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
            api = json.loads((out / "api-result.json").read_text())
            filters = json.loads((out / "uuid-filters.json").read_text())
            self.assertEqual(api["binding_sha256"], filters["binding_sha256"])
            self.assertEqual(api["binding_sha256"], plan["binding_sha256"])
            self.assertRegex(api["binding_sha256"], r"^[0-9a-f]{64}$")
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
            combine = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "combine", "--side", "source", "--api-result", str(api / "api-result.json"), "--db-jsonl-dir", str(db), "--information-schema", str(FIXTURES / "control-information-schema.tsv"), "--schema-policy", str(FIXTURES / "schema-policy.json"), "--out", str(root / "combined")], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
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
            combine = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "combine", "--side", "source", "--api-result", str(api / "api-result.json"), "--db-jsonl-dir", str(db), "--information-schema", str(FIXTURES / "control-information-schema.tsv"), "--schema-policy", str(FIXTURES / "schema-policy.json"), "--out", str(root / "combined")], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertNotEqual(0, combine.returncode)

    def test_combine_rejects_api_filter_and_binding_substitution(self):
        for mode in ("api", "filters", "binding"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                api_dir = root / "api"
                create = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "api", "--side", "source", "--fixture", str(FIXTURES / "api-input.json"), "--out", str(api_dir)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                self.assertEqual(0, create.returncode, create.stderr)
                if mode == "api":
                    path = api_dir / "api-result.json"
                    payload = json.loads(path.read_text())
                    payload["api_result"]["rehome_host"] = "substituted-host"
                elif mode == "filters":
                    path = api_dir / "uuid-filters.json"
                    payload = json.loads(path.read_text())
                    payload["filters"][0]["filters"]["uuid"] = ["99999999-9999-9999-9999-999999999999"]
                else:
                    path = api_dir / "db-query-plan.json"
                    payload = json.loads(path.read_text())
                    payload["binding_sha256"] = "f" * 64
                path.write_text(json.dumps(payload), encoding="utf-8")
                db = root / "db"
                db.mkdir()
                plan = json.loads((api_dir / "db-query-plan.json").read_text())
                for query in plan["queries"]:
                    (db / query["rc_file"]).write_text("0\n", encoding="ascii")
                    (db / query["jsonl_file"]).write_text("", encoding="utf-8")
                combine = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "combine", "--side", "source", "--api-result", str(api_dir / "api-result.json"), "--db-jsonl-dir", str(db), "--information-schema", str(ROOT / "tests/fixtures/live_discovery/full-run/control-information-schema.tsv"), "--schema-policy", str(FIXTURES / "schema-policy.json"), "--out", str(root / "combined")], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                self.assertNotEqual(0, combine.returncode)

    def test_combine_rejects_extra_or_missing_selected_columns(self):
        for mode in ("extra", "missing"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                api = root / "api"
                create = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "api", "--side", "source", "--fixture", str(FIXTURES / "api-input.json"), "--out", str(api)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                self.assertEqual(0, create.returncode, create.stderr)
                query = json.loads((api / "db-query-plan.json").read_text())["queries"][0]
                row = {column: None for column in query["columns"]}
                row["uuid"] = "11111111-1111-1111-1111-111111111111"
                if mode == "extra":
                    row["unexpected"] = "value"
                else:
                    row.pop(query["columns"][-1])
                db = root / "db"
                db.mkdir()
                (db / query["rc_file"]).write_text("0\n", encoding="ascii")
                (db / query["jsonl_file"]).write_text(json.dumps({"_schema": "nova", "_table": "instances", "row": row}) + "\n", encoding="utf-8")
                combine = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "combine", "--side", "source", "--api-result", str(api / "api-result.json"), "--db-jsonl-dir", str(db), "--information-schema", str(ROOT / "tests/fixtures/live_discovery/full-run/control-information-schema.tsv"), "--schema-policy", str(FIXTURES / "schema-policy.json"), "--out", str(root / "combined")], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                self.assertNotEqual(0, combine.returncode)

    def test_api_fixture_cannot_bypass_composition_with_cached_collectors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = json.loads((FIXTURES / "api-input.json").read_text())
            payload["api_result"]["collectors"] = json.loads((FIXTURES / "ready/source-control.json").read_text())["collectors"]
            fixture = root / "fixture.json"
            fixture.write_text(json.dumps(payload), encoding="utf-8")
            proc = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "api", "--side", "source", "--fixture", str(fixture), "--out", str(root / "out")], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertNotEqual(0, proc.returncode)

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
            combine = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "combine", "--side", "source", "--api-result", str(api / "api-result.json"), "--db-jsonl-dir", str(db), "--information-schema", str(ROOT / "tests/fixtures/live_discovery/full-run/control-information-schema.tsv"), "--schema-policy", str(FIXTURES / "schema-policy.json"), "--out", str(root / "combined")], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertNotEqual(0, combine.returncode)

    def test_combine_accepts_exact_jsonl_envelope_and_writes_assembler_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            api = root / "api"
            create = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "api", "--side", "source", "--fixture", str(FIXTURES / "api-input.json"), "--out", str(api)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(0, create.returncode, create.stderr)
            queries = json.loads((api / "db-query-plan.json").read_text())["queries"]
            db = root / "db"
            db.mkdir()
            for query in queries:
                row = {column: None for column in query["columns"]}
                filter_column, values = next(iter(query["filters"].items()))
                row[filter_column] = values[0]
                (db / query["rc_file"]).write_text("0\n", encoding="ascii")
                (db / query["jsonl_file"]).write_text(json.dumps({"_schema": query["schema"], "_table": query["table"], "row": row}) + "\n", encoding="utf-8")
            out = root / "combined"
            combine = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "combine", "--side", "source", "--api-result", str(api / "api-result.json"), "--db-jsonl-dir", str(db), "--information-schema", str(ROOT / "tests/fixtures/live_discovery/full-run/control-information-schema.tsv"), "--schema-policy", str(FIXTURES / "schema-policy.json"), "--out", str(out)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
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
                combine = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "combine", "--side", "source", "--api-result", str(api / "api-result.json"), "--db-jsonl-dir", str(db), "--information-schema", str(ROOT / "tests/fixtures/live_discovery/full-run/control-information-schema.tsv"), "--schema-policy", str(FIXTURES / "schema-policy.json"), "--out", str(root / "combined")], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                self.assertNotEqual(0, combine.returncode)
                self.assertNotIn("Traceback", combine.stderr)

    def test_all_normal_outputs_are_resanitized_and_sensitive_is_separate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = root / "fixture"
            fixture.mkdir()
            source = json.loads((FIXTURES / "ready/source-control.json").read_text())
            target = json.loads((FIXTURES / "ready/target-control.json").read_text())
            target["schema_capabilities"]["nova"]["api_token"] = "chap-secret-value"
            target["sensitive_evidence"] = {"attachment-1": {"connection_info": "chap-secret-value"}}
            (fixture / "source-control.json").write_text(json.dumps(source), encoding="utf-8")
            (fixture / "target-control.json").write_text(json.dumps(target), encoding="utf-8")
            (fixture / "runtime.json").write_text((FIXTURES / "ready/runtime.json").read_text(), encoding="utf-8")
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
            source = json.loads((FIXTURES / "ready/source-control.json").read_text())
            target = json.loads((FIXTURES / "ready/target-control.json").read_text())
            column = {"name": "id", "ordinal": 1, "column_type": "varchar(36)", "nullable": False, "default": None, "extra": ""}
            source["schema_capabilities"]["source-information-schema"] = {"tables": {"nova.instances": {"id": column}}, "used_columns": {"nova.instances": ["id"]}}
            target["schema_capabilities"]["target-information-schema"] = {"tables": {"nova.instances": {"id": column}}, "used_columns": {"nova.instances": ["id"]}}
            (root / "source.json").write_text(json.dumps(source), encoding="utf-8")
            (root / "target.json").write_text(json.dumps(target), encoding="utf-8")
            (root / "runtime.json").write_text((FIXTURES / "ready/runtime.json").read_text(), encoding="utf-8")
            out = root / "out"
            proc = subprocess.run([sys.executable, "scripts/assemble_live_discovery.py", "--source-control", str(root / "source.json"), "--target-control", str(root / "target.json"), "--runtime", str(root / "runtime.json"), "--schema-policy", str(ROOT / "inventory/live-discovery-schema-policy.json"), "--out-dir", str(out)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(0, proc.returncode, proc.stderr)
            mapping = json.loads((out / "schema-mapping.json").read_text())
            self.assertEqual("openstack-rehome-directional-schema-mapping/v1alpha1", mapping["schema_version"])
            self.assertEqual("COMMON_COMPATIBLE", mapping["tables"]["nova.instances"][0]["classification"])

    def test_live_assembler_accepts_raw_runtime_collector_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "source.json").write_text((FIXTURES / "ready/source-control.json").read_text(), encoding="utf-8")
            (root / "target.json").write_text((FIXTURES / "ready/target-control.json").read_text(), encoding="utf-8")
            runtime = {"schema_version":"openstack-rehome-live-discovery/v1alpha1","service":"runtime","side":"source","nodes":[{"kind":"runtime_evidence","id":"source-runtime-raw","side":"source","facts":{},"evidence_ids":[],"key":"runtime_evidence:source-runtime-raw"}],"edges":[],"checks":[],"unknowns":[],"blockers":[],"evidence":[]}
            (root / "runtime.json").write_text(json.dumps(runtime), encoding="utf-8")
            out = root / "out"
            proc = subprocess.run([sys.executable, "scripts/assemble_live_discovery.py", "--source-control", str(root / "source.json"), "--target-control", str(root / "target.json"), "--runtime", str(root / "runtime.json"), "--schema-policy", str(FIXTURES / "schema-policy.json"), "--out-dir", str(out)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertTrue((out / "resource-graph.json").is_file())

    def test_assembler_rejects_swapped_mixed_and_wrong_runtime_roles(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = json.loads((FIXTURES / "ready/source-control.json").read_text())
            target = json.loads((FIXTURES / "ready/target-control.json").read_text())
            runtime = json.loads((FIXTURES / "ready/runtime.json").read_text())
            for name, payload in (("source.json", source), ("target.json", target), ("runtime.json", runtime)):
                (root / name).write_text(json.dumps(payload), encoding="utf-8")
            cases = {
                "swapped": (root / "target.json", root / "source.json", root / "runtime.json"),
                "mixed": (root / "source.json", root / "source.json", root / "runtime.json"),
                "runtime": (root / "source.json", root / "target.json", root / "target.json"),
            }
            for name, (source_path, target_path, runtime_path) in cases.items():
                with self.subTest(name=name):
                    out = root / ("out-" + name)
                    proc = subprocess.run([sys.executable, "scripts/assemble_live_discovery.py", "--source-control", str(source_path), "--target-control", str(target_path), "--runtime", str(runtime_path), "--schema-policy", str(FIXTURES / "schema-policy.json"), "--out-dir", str(out)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                    self.assertEqual(3, proc.returncode)
                    self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
