import json
import hashlib
import inspect
import os
from copy import deepcopy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "live_discovery" / "full-run"
sys.path.insert(0, str(ROOT / "scripts"))

import collect_live_control as control
from live_discovery.contract import CheckResult, CollectorResult, DependencyEdge, ResourceNode
from collect_live_control import _CombinedClient, _TABLE_ROOT_FILTERS, _api_phase, _collector_table_catalog, _execute_probe_config, _expected_plan_tables, _integrate_storage_readiness, _phase_binding, _read_protected_json, _root_filter_values
from live_discovery.cinder import CORE_TABLES as CINDER_CORE, OPTIONAL_TABLES as CINDER_OPTIONAL
from live_discovery.db_evidence import build_db_evidence
from live_discovery.neutron import CORE_TABLES as NEUTRON_CORE, OPTIONAL_TABLE_FAMILIES as NEUTRON_OPTIONAL
from live_discovery.nova import DB_SCHEMAS, DB_TABLES
from live_discovery.schema import SchemaSnapshot


def _write_db_evidence(directory, query, side="source", returncode=0, stderr=""):
    payload = build_db_evidence({
        "side": side,
        "query_id": query["query_id"],
        "returncode": returncode,
        "observed_at": "2026-07-12T09:00:00Z",
        "stderr": stderr,
    })
    (directory / f"{query['query_id']}.evidence.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )


def _api_evidence(evidence_id):
    return {
        "evidence_id": evidence_id,
        "returncode": 0,
        "failure_class": None,
        "stderr_sha256": hashlib.sha256(b"").hexdigest(),
    }


def _probe_metadata(side, category, evidence_id):
    return {
        "observed_at": "2026-07-12T09:00:00Z",
        "returncode": 0,
        "failure_class": None,
        "stderr_sha256": hashlib.sha256(b"").hexdigest(),
        "raw_artifact_ref": f"protected://{side}/{category}/{evidence_id}",
    }


class LiveDiscoveryCliTests(unittest.TestCase):
    def test_empty_target_records_expected_absence_without_aborting_api_phase(self):
        instance_id = "11111111-1111-1111-1111-111111111111"
        port_id = "33333333-3333-3333-3333-333333333333"
        volume_id = "22222222-2222-2222-2222-222222222222"
        image_id = "44444444-4444-4444-4444-444444444444"

        class Client:
            def __init__(self, *args):
                pass

            def json(self, command, evidence_id):
                if command[:2] == ["server", "list"]:
                    return [], _api_evidence(evidence_id)
                if command[:3] in (
                    ["compute", "service", "list"],
                    ["resource", "provider", "list"],
                ):
                    return [], _api_evidence(evidence_id)
                evidence = control.CommandEvidence(
                    evidence_id,
                    [str(value) for value in command],
                    1,
                    "",
                    "HTTP 404 object not found",
                )
                error = control.ProbeFailed(evidence)
                error.status_code = 404
                raise error

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "roots.json"
            manifest.write_text(json.dumps({
                "schema_version": "openstack-rehome-root-manifest/v1alpha1",
                "side": "target",
                "roots": {
                    "instances": [instance_id],
                    "ports": [port_id],
                    "volumes": [volume_id],
                    "images": [image_id],
                },
            }), encoding="utf-8")
            manifest.chmod(0o600)
            schema = root / "information-schema.tsv"
            lines = ["SERVICE:all", "SECTION:COLUMNS"]
            for identity in sorted(set().union(*_collector_table_catalog().values())):
                schema_name, table = identity.split(".", 1)
                columns = {"id", *(column for _, column in _TABLE_ROOT_FILTERS[identity])}
                for ordinal, column in enumerate(sorted(columns), start=1):
                    lines.append(
                        f"{schema_name}\t{table}\t{ordinal}\t{column}"
                        "\tvarchar(255)\tYES\tNULL\t\\N"
                    )
            schema.write_text("\n".join(lines) + "\n", encoding="utf-8")
            args = type("Args", (), {
                "fixture": None,
                "rehome_host": "compute-023",
                "cloud": "target",
                "clouds_file": Path("/clouds.yaml"),
                "container": "toolbox",
                "side": "target",
                "information_schema": schema,
                "root_manifest": manifest,
                "probe_config": None,
                "capability_config": None,
                "phase_key_file": None,
                "phase_key_env": "LIVE_DISCOVERY_TEST_KEY",
                "out": root / "out",
            })()
            with (
                mock.patch("live_discovery.openstack.OpenStackClient", Client),
                mock.patch.dict(os.environ, {
                    "LIVE_DISCOVERY_TEST_KEY": "test-phase-anchor-at-least-sixteen",
                }),
            ):
                _api_phase(args)

            document = json.loads((root / "out" / "api-result.json").read_text())
            absences = document["api_result"]["expected_absences"]
            absent_ids = {item["resource_id"] for item in absences}
            self.assertTrue({instance_id, port_id, volume_id, image_id}.issubset(absent_ids))
            self.assertTrue(all(item["status_code"] == 404 for item in absences))
            self.assertTrue((root / "out" / "db-query-plan.json").is_file())

    def test_target_404_absence_becomes_typed_readiness_check(self):
        resource_id = "11111111-1111-1111-1111-111111111111"
        api_result = {
            "expected_absences": [{
                "evidence_id": f"nova-target-server-show-{resource_id}",
                "command": ["server", "show", resource_id, "-f", "json"],
                "resource_id": resource_id,
                "status_code": 404,
                "failure_class": "not-found",
                "observed_at": "2026-07-12T09:00:00Z",
                "stderr_sha256": hashlib.sha256(b"not found").hexdigest(),
                "raw_artifact_ref": (
                    f"protected://target/api-failure/"
                    f"nova-target-server-show-{resource_id}"
                ),
            }],
        }

        checks = control._target_absence_checks("target", api_result)

        self.assertEqual(1, len(checks))
        self.assertEqual("UNKNOWN", checks[0]["status"])
        self.assertEqual([resource_id], checks[0]["resource_ids"])
        self.assertEqual(
            [f"nova-target-server-show-{resource_id}"],
            checks[0]["evidence_ids"],
        )

    def test_empty_preimport_target_fixture_still_emits_typed_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = root / "empty-target"
            fixture.mkdir()
            source = json.loads((FIXTURES / "ready/source-control.json").read_text())
            target = json.loads((FIXTURES / "ready/target-control.json").read_text())
            resource_id = "11111111-1111-1111-1111-111111111111"
            evidence_id = f"nova-target-server-show-{resource_id}"
            for collector in target["collectors"]:
                if collector["service"] in {"neutron", "cinder", "glance"}:
                    collector["nodes"] = []
                    collector["edges"] = []
                    collector["checks"] = []
                    collector["unknowns"] = []
                    collector["blockers"] = []
                    collector["evidence"] = []
            target["checks"].append({
                "check_id": "target.object-absence.0001",
                "status": "UNKNOWN",
                "reason": "source-scoped object is not present on the pre-import target",
                "resource_ids": [resource_id],
                "evidence_ids": [evidence_id],
            })
            target["evidence_index"].append({
                "evidence_id": evidence_id,
                "kind": "api-absence",
                "side": "target",
                "service": "target-object-existence",
                "command": ["server", "show", resource_id, "-f", "json"],
                "resource_id": resource_id,
                "status_code": 404,
                "observed_at": "2026-07-12T09:00:00Z",
                "returncode": 1,
                "failure_class": "not-found",
                "stderr_sha256": hashlib.sha256(b"not found").hexdigest(),
                "raw_artifact_ref": f"protected://target/{evidence_id}",
            })
            (fixture / "source-control.json").write_text(json.dumps(source), encoding="utf-8")
            (fixture / "target-control.json").write_text(json.dumps(target), encoding="utf-8")
            (fixture / "runtime.json").write_text((FIXTURES / "ready/runtime.json").read_text(), encoding="utf-8")
            (fixture / "schema-policy.json").write_text((FIXTURES / "schema-policy.json").read_text(), encoding="utf-8")
            out = root / "out"

            process = subprocess.run(
                [sys.executable, "scripts/assemble_live_discovery.py", "--fixture-dir", str(fixture), "--out-dir", str(out)],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(2, process.returncode, process.stderr)
            report = json.loads((out / "readiness-report.json").read_text())
            self.assertEqual("UNKNOWN", report["verdict"])
            self.assertIn("target.object-absence.0001", {
                item["check_id"] for item in report["checks"]
            })

    def test_multi_cell_catalog_uses_live_cell_schema_names(self):
        available = {
            "nova_api.host_mappings",
            "nova_api.instance_mappings",
            "nova_api.request_specs",
            *{
                f"nova_cell1.{table}"
                for table, schema in DB_SCHEMAS.items()
                if schema == "nova"
            },
        }

        catalog = _collector_table_catalog(available)["nova"]

        self.assertIn("nova_cell1.instances", catalog)
        self.assertNotIn("nova.instances", catalog)

        available.update({
            f"nova_cell2.{table}"
            for table, schema in DB_SCHEMAS.items()
            if schema == "nova"
        })
        roots = {
            "hosts": ["compute-023"],
            "instances": ["11111111-1111-1111-1111-111111111111"],
            "services": ["22222222-2222-2222-2222-222222222222"],
            "compute_nodes": ["33333333-3333-3333-3333-333333333333"],
        }
        selected = _expected_plan_tables(
            "source", roots, available, cell_schema="nova_cell1"
        )
        self.assertTrue(any(item.startswith("nova_cell1.") for item in selected))
        self.assertFalse(any(item.startswith("nova_cell2.") for item in selected))

    def test_fixture_combine_requires_explicit_cli_trust_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            api = root / "api"
            created = subprocess.run([sys.executable,"scripts/collect_live_control.py","--phase","api","--side","source","--fixture",str(FIXTURES/"api-input.json"),"--out",str(api)],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
            self.assertEqual(0, created.returncode)
            plan = json.loads((api/"db-query-plan.json").read_text())
            db = root / "db"
            db.mkdir()
            for query in plan["queries"]:
                (db/query["rc_file"]).write_text("0\n",encoding="ascii")
                (db/query["jsonl_file"]).write_text("",encoding="utf-8")
                _write_db_evidence(db, query)
            rejected = subprocess.run([sys.executable,"scripts/collect_live_control.py","--phase","combine","--side","source","--api-result",str(api/"api-result.json"),"--db-jsonl-dir",str(db),"--information-schema",str(FIXTURES/"control-information-schema.tsv"),"--schema-policy",str(FIXTURES/"schema-policy.json"),"--out",str(root/"out")],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
            self.assertEqual(3, rejected.returncode)
            with mock.patch.dict("os.environ",{"LIVE_PHASE_KEY":"fixture-only-phase-integrity-anchor-v1"}):
                downgraded = subprocess.run([sys.executable,"scripts/collect_live_control.py","--phase","combine","--side","source","--phase-key-env","LIVE_PHASE_KEY","--api-result",str(api/"api-result.json"),"--db-jsonl-dir",str(db),"--information-schema",str(FIXTURES/"control-information-schema.tsv"),"--schema-policy",str(FIXTURES/"schema-policy.json"),"--out",str(root/"downgraded")],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,env={**os.environ,"LIVE_PHASE_KEY":"fixture-only-phase-integrity-anchor-v1"})
            self.assertEqual(3,downgraded.returncode)

    def test_missing_capability_evidence_is_not_fabricated(self):
        collector = {"side":"target","service":"target-profile","nodes":[{"evidence_ids":["target-profile-real"]}],"checks":[]}
        with self.assertRaises(ValueError):
            control._build_evidence_index("target", [collector], {"openstack":[]}, [])

    def test_evidence_index_has_acquisition_outcome_and_protected_raw_reference(self):
        evidence_id = "nova-source-server-list-compute-023"
        collector = {
            "side": "source",
            "service": "nova",
            "nodes": [{"evidence_ids": [evidence_id]}],
            "checks": [],
            "evidence": [],
        }
        api_result = {
            "observed_at": "2026-07-12T09:00:00Z",
            "openstack": [{
                "command": ["server", "list", "-f", "json"],
                "payload": [],
                "evidence": {
                    "evidence_id": evidence_id,
                    "returncode": 0,
                    "failure_class": None,
                    "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                    "observed_at": "2026-07-12T09:00:00Z",
                    "raw_artifact_ref": f"protected://source/{evidence_id}",
                },
            }],
        }

        entry = control._build_evidence_index(
            "source", [collector], api_result, []
        )[0]

        self.assertEqual("2026-07-12T09:00:00Z", entry["observed_at"])
        self.assertEqual(0, entry["returncode"])
        self.assertIsNone(entry["failure_class"])
        self.assertEqual(hashlib.sha256(b"").hexdigest(), entry["stderr_sha256"])
        self.assertEqual(
            f"protected://source/{evidence_id}", entry["raw_artifact_ref"]
        )

    def test_db_evidence_preserves_failed_sidecar_metadata_and_rejects_missing(self):
        stderr_digest = hashlib.sha256(b"database unavailable").hexdigest()
        failed = {
            "evidence_id": "source-db:0001-nova-instances",
            "kind": "db-jsonl",
            "schema": "nova",
            "table": "instances",
            "filters": {"uuid": ["11111111-1111-1111-1111-111111111111"]},
            "observed_at": "2026-07-12T09:00:07Z",
            "returncode": 7,
            "failure_class": "command-failed",
            "stderr_sha256": stderr_digest,
            "raw_artifact_ref": (
                "protected://source/db-stderr/0001-nova-instances.stderr"
            ),
        }

        entry = control._build_evidence_index(
            "source",
            [],
            {"observed_at": "2026-07-12T09:00:00Z", "openstack": []},
            [failed],
        )[0]

        self.assertEqual(7, entry["returncode"])
        self.assertEqual("command-failed", entry["failure_class"])
        self.assertEqual(stderr_digest, entry["stderr_sha256"])
        self.assertEqual(failed["raw_artifact_ref"], entry["raw_artifact_ref"])

        missing = dict(failed)
        del missing["stderr_sha256"]
        with self.assertRaisesRegex(ValueError, "metadata"):
            control._build_evidence_index(
                "source",
                [],
                {"observed_at": "2026-07-12T09:00:00Z", "openstack": []},
                [missing],
            )

    def test_storage_pass_cannot_cross_backend_kind_or_resource(self):
        volume_id = "22222222-2222-2222-2222-222222222222"
        result = CollectorResult(service="cinder", side="source", nodes=[ResourceNode("volume",volume_id,"source",{"size":1,"storage_backend_id":"rbd-backend","backend_kind":"rbd","resource_identity":"volumes/volume-2","resource_fingerprint":hashlib.sha256(b"rbd:volumes/volume-2").hexdigest(),"connection_evidence_ids":["connection-1"]})])
        api = {"storage_probe_results":[{"volume_id":volume_id,"scope":"source-compute","kind":"nfs","backend_identity":"rbd-backend","resource_identity":"/srv/nfs/volume-2","resource_fingerprint":hashlib.sha256(b"nfs:/srv/nfs/volume-2").hexdigest(),"expected_size":1073741824,"observed_size":1073741824,"evidence_id":"storage-cross-kind","status":"PASS","reason":"ok",**_probe_metadata("source","storage","storage-cross-kind")}]}
        _integrate_storage_readiness(result,[volume_id],api)
        self.assertEqual("BLOCKED", result.checks[0].status)
        result2=CollectorResult(service="cinder",side="source",nodes=[ResourceNode("volume",volume_id,"source",{"size":1,"storage_backend_id":"rbd-backend","backend_kind":"rbd","resource_identity":"volumes/expected","resource_fingerprint":hashlib.sha256(b"rbd:volumes/expected").hexdigest(),"connection_evidence_ids":["connection-1"]})])
        api2={"storage_probe_results":[{**api["storage_probe_results"][0],"kind":"rbd","resource_identity":"volumes/attacker"}]}
        _integrate_storage_readiness(result2,[volume_id],api2)
        self.assertEqual("BLOCKED",result2.checks[0].status)

    def test_glance_probe_requires_independent_catalog_origin_and_actual_stores(self):
        parameters = inspect.signature(_execute_probe_config).parameters
        self.assertIn("catalog_origin", parameters)
        self.assertIn("image_store_ids", parameters)

    def test_glance_probe_accepts_only_catalog_origin_and_actual_image_stores(self):
        image_id = "44444444-4444-4444-4444-444444444444"
        class Response:
            status=206
            headers={"Content-Range":"bytes 0-0/1","Content-Length":"1"}
            def read(self,size): return b"x"
            def geturl(self): return f"https://glance.example/v2/images/{image_id}/file"
            def close(self): pass
        class Opener:
            def open(self,request,timeout=None): return Response()
        config={"schema_version":"openstack-rehome-probe-config/v1alpha1","storage":[],"glance":{"endpoint_url":"https://glance.example","token_env":"GLANCE_TEST_TOKEN","images":[{"image_id":image_id,"expected_size":1,"required":True,"store_ids":["real-store"]}],"store_capabilities":[{"store_id":"real-store","backend_type":"rbd"}]}}
        with mock.patch.dict("os.environ",{"GLANCE_TEST_TOKEN":"ephemeral-token-value"}):
            result = _execute_probe_config(config,object(),opener=Opener(),catalog_origin="https://glance.example",image_store_ids={image_id:["real-store"]})
        self.assertEqual("PASS", result["glance_data_probe_results"][0]["status"])
        attacker = json.loads(json.dumps(config))
        attacker["glance"]["endpoint_url"] = "https://attacker.example"
        with mock.patch.dict("os.environ",{"GLANCE_TEST_TOKEN":"ephemeral-token-value"}), self.assertRaises(ValueError):
            _execute_probe_config(attacker,object(),opener=Opener(),catalog_origin="https://glance.example",image_store_ids={image_id:["real-store"]})
        store_attacker=json.loads(json.dumps(config))
        store_attacker["glance"]["images"][0]["store_ids"]=["fake-store"]
        with mock.patch.dict("os.environ",{"GLANCE_TEST_TOKEN":"ephemeral-token-value"}), self.assertRaises(ValueError):
            _execute_probe_config(store_attacker,object(),opener=Opener(),catalog_origin="https://glance.example",image_store_ids={image_id:["real-store"]})

    def test_root_manifest_requires_protected_single_fd_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "roots.json"
            manifest.write_text(json.dumps({"schema_version":"openstack-rehome-root-manifest/v1alpha1","side":"source","roots":{}}),encoding="utf-8")
            args = type("Args",(),{"fixture":None,"rehome_host":"compute-023","cloud":"cloud","clouds_file":Path("/clouds.yaml"),"container":"toolbox","side":"source","information_schema":FIXTURES/"control-information-schema.tsv","root_manifest":manifest,"probe_config":None,"capability_config":None,"phase_key_file":None,"phase_key_env":"LIVE_DISCOVERY_TEST_KEY","out":root/"out"})()
            class Client:
                def __init__(self,*args): pass
                def json(self,command,evidence_id): return [], {"id":evidence_id}
            with mock.patch("live_discovery.openstack.OpenStackClient",Client), mock.patch.dict("os.environ",{"LIVE_DISCOVERY_TEST_KEY":"test-phase-anchor-at-least-sixteen"}), self.assertRaises(ValueError):
                _api_phase(args)

    def test_protected_cinder_connection_evidence_loader_is_available(self):
        self.assertTrue(hasattr(control, "_load_cinder_sensitive_evidence"))

    def test_cinder_connection_evidence_is_mode_checked_and_raw_only_in_sensitive_output(self):
        volume_id="22222222-2222-2222-2222-222222222222"
        attachment_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        payload={"schema_version":"openstack-rehome-cinder-sensitive-evidence/v1alpha1","side":"source","entries":[{"evidence_id":"cinder-sensitive-attachment","volume_id":volume_id,"attachment_id":attachment_id,"backend_kind":"rbd","backend_id":"rbd-backend","resource_identity":"volumes/volume-2","connector":{"attachment_id":attachment_id,"volume_id":volume_id,"host":"compute-023","auth_password":"connector-secret"},"connection_info":{"driver_volume_type":"rbd","data":{"pool":"volumes","image":"volume-2","secret_uuid":"connection-secret"}}}]}
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/"cinder-sensitive.json"
            path.write_text(json.dumps(payload),encoding="utf-8")
            path.chmod(0o600)
            summaries,sensitive=control._load_cinder_sensitive_evidence(path,"source")
            self.assertEqual("rbd",summaries[0]["backend_kind"])
            self.assertNotIn("connector-secret",json.dumps(summaries))
            self.assertIn("connector-secret",json.dumps(sensitive))
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                control._load_cinder_sensitive_evidence(path,"source")

    def test_cinder_resource_identity_is_derived_and_multiattach_is_independent(self):
        volume_id="22222222-2222-2222-2222-222222222222"
        attachments=["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"]
        entries=[]
        for index,attachment_id in enumerate(attachments):
            entries.append({"evidence_id":f"cinder-sensitive-{index}","volume_id":volume_id,"attachment_id":attachment_id,"backend_kind":"rbd","backend_id":"rbd-backend","resource_identity":"volumes/volume-2","connector":{"attachment_id":attachment_id,"volume_id":volume_id,"host":f"compute-{index}"},"connection_info":{"driver_volume_type":"rbd","data":{"pool":"volumes","image":"volume-2"}}})
        payload={"schema_version":"openstack-rehome-cinder-sensitive-evidence/v1alpha1","side":"source","entries":entries}
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/"multiattach.json"
            path.write_text(json.dumps(payload),encoding="utf-8"); path.chmod(0o600)
            summaries,_=control._load_cinder_sensitive_evidence(path,"source")
            self.assertEqual(2,len(summaries))
            self.assertEqual(set(attachments),{item["attachment_id"] for item in summaries})
            self.assertTrue(all(item["resource_identity"]=="volumes/volume-2" and len(item["resource_fingerprint"])==64 for item in summaries))
            forged=json.loads(json.dumps(payload)); forged["entries"][0]["resource_identity"]="attacker/forged"
            path.write_text(json.dumps(forged),encoding="utf-8"); path.chmod(0o600)
            with self.assertRaises(ValueError): control._load_cinder_sensitive_evidence(path,"source")
            wrong=json.loads(json.dumps(payload)); wrong["entries"][0]["connector"]["attachment_id"]=attachments[1]
            path.write_text(json.dumps(wrong),encoding="utf-8"); path.chmod(0o600)
            with self.assertRaises(ValueError): control._load_cinder_sensitive_evidence(path,"source")

    def test_nfs_and_lvm_resource_identity_are_derived_from_connection_data(self):
        volume_id="22222222-2222-2222-2222-222222222222"
        cases=[("nfs","/var/lib/nova/mnt/export/volume-2",{"driver_volume_type":"nfs","data":{"device_path":"/var/lib/nova/mnt/export/volume-2"}}),("lvm","cinder-volumes/volume-2",{"driver_volume_type":"lvm","data":{"volume_group":"cinder-volumes","logical_volume":"volume-2"}})]
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/"derived.json"
            for index,(kind,identity,connection) in enumerate(cases):
                attachment=f"{index+1:08d}-aaaa-4aaa-8aaa-{index+1:012d}"
                payload={"schema_version":"openstack-rehome-cinder-sensitive-evidence/v1alpha1","side":"source","entries":[{"evidence_id":f"derived-{kind}","volume_id":volume_id,"attachment_id":attachment,"backend_kind":kind,"backend_id":f"{kind}-backend","resource_identity":identity,"connector":{"attachment_id":attachment,"volume_id":volume_id},"connection_info":connection}]}
                path.write_text(json.dumps(payload),encoding="utf-8"); path.chmod(0o600)
                summaries,_=control._load_cinder_sensitive_evidence(path,"source")
                self.assertEqual(identity,summaries[0]["resource_identity"])

    def test_multiattach_summaries_bind_each_attachment_node_independently(self):
        volume="22222222-2222-2222-2222-222222222222"; backend="rbd-backend"
        attachments=["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"]
        result=CollectorResult(service="cinder",side="source",nodes=[ResourceNode("volume",volume,"source",{"size":1,"storage_backend_id":backend}),ResourceNode("storage_backend",backend,"source"),*[ResourceNode("volume_attachment",item,"source",{"volume_id":volume,"connection_summary":{"driver_type":"rbd"}}) for item in attachments]],edges=[*[DependencyEdge(f"volume:{volume}",f"volume_attachment:{item}","has_attachment",True) for item in attachments],DependencyEdge(f"volume:{volume}",f"storage_backend:{backend}","has_backing_backend",True)])
        fingerprint=hashlib.sha256(b"rbd:volumes/volume-2").hexdigest()
        summaries=[{"volume_id":volume,"attachment_id":item,"evidence_id":f"evidence-{index}","backend_kind":"rbd","backend_id":backend,"resource_identity":"volumes/volume-2","resource_fingerprint":fingerprint} for index,item in enumerate(attachments)]
        control._bind_cinder_connection_summaries(result,summaries)
        attachment_nodes={node.id:node for node in result.nodes if node.kind=="volume_attachment"}
        self.assertEqual(["evidence-0"],attachment_nodes[attachments[0]].evidence_ids)
        self.assertEqual(["evidence-1"],attachment_nodes[attachments[1]].evidence_ids)
        volume_node=next(node for node in result.nodes if node.kind=="volume")
        self.assertEqual(["evidence-0","evidence-1"],volume_node.facts["connection_evidence_ids"])
        self.assertEqual([],result.blockers)
        incomplete=CollectorResult(service="cinder",side="source",nodes=[ResourceNode("volume",volume,"source",{"size":1,"storage_backend_id":backend}),ResourceNode("storage_backend",backend,"source"),*[ResourceNode("volume_attachment",item,"source",{"volume_id":volume,"connection_summary":{"driver_type":"rbd"}}) for item in attachments]],edges=[*[DependencyEdge(f"volume:{volume}",f"volume_attachment:{item}","has_attachment",True) for item in attachments],DependencyEdge(f"volume:{volume}",f"storage_backend:{backend}","has_backing_backend",True)])
        control._bind_cinder_connection_summaries(incomplete,summaries[:1])
        self.assertIn(f"Cinder protected attachment evidence missing: {attachments[1]}",incomplete.blockers)

    def test_cinder_summary_backend_must_match_volume_graph(self):
        volume="22222222-2222-2222-2222-222222222222"; attachment="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        expected_backend="rbd-backend"; unrelated_backend="other-backend"
        result=CollectorResult(service="cinder",side="source",nodes=[ResourceNode("volume",volume,"source",{"size":1,"storage_backend_id":expected_backend}),ResourceNode("storage_backend",expected_backend,"source"),ResourceNode("storage_backend",unrelated_backend,"source"),ResourceNode("volume_attachment",attachment,"source",{"volume_id":volume,"connection_summary":{"driver_type":"rbd"}})],edges=[DependencyEdge(f"volume:{volume}",f"volume_attachment:{attachment}","has_attachment",True),DependencyEdge(f"volume:{volume}",f"storage_backend:{expected_backend}","has_backing_backend",True)])
        fingerprint=hashlib.sha256(b"rbd:volumes/volume-2").hexdigest()
        summary={"volume_id":volume,"attachment_id":attachment,"evidence_id":"evidence-0","backend_kind":"rbd","backend_id":unrelated_backend,"resource_identity":"volumes/volume-2","resource_fingerprint":fingerprint}
        control._bind_cinder_connection_summaries(result,[summary])
        self.assertIn(f"Cinder protected attachment evidence mismatch: {attachment}",result.blockers)

    def test_cinder_post_bind_requires_existing_exact_driver_without_mutation(self):
        volume="22222222-2222-4222-8222-222222222222"; attachment="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"; backend="rbd-backend"
        fingerprint=hashlib.sha256(b"rbd:volumes/volume-1").hexdigest()
        summary={"volume_id":volume,"attachment_id":attachment,"evidence_id":"protected-1","backend_kind":"rbd","backend_id":backend,"resource_identity":"volumes/volume-1","resource_fingerprint":fingerprint}
        def result_for(connection_summary=Ellipsis):
            facts={"volume_id":volume}
            if connection_summary is not Ellipsis: facts["connection_summary"]=deepcopy(connection_summary)
            return CollectorResult(service="cinder",side="source",nodes=[ResourceNode("volume",volume,"source",{"size":1,"storage_backend_id":backend}),ResourceNode("storage_backend",backend,"source"),ResourceNode("volume_attachment",attachment,"source",facts)],edges=[DependencyEdge(f"volume:{volume}",f"volume_attachment:{attachment}","has_attachment",True),DependencyEdge(f"volume:{volume}",f"storage_backend:{backend}","has_backing_backend",True)])
        for label,connection_summary in (("missing",Ellipsis),("malformed","rbd"),("mismatch",{"driver_type":"lvm"})):
            with self.subTest(label=label):
                result=result_for(connection_summary)
                attachment_node=next(node for node in result.nodes if node.kind=="volume_attachment")
                before=deepcopy(attachment_node.facts)
                control._bind_cinder_connection_summaries(result,[summary])
                self.assertIn(f"Cinder protected attachment evidence mismatch: {attachment}",result.blockers)
                self.assertEqual(before,attachment_node.facts)
                self.assertNotIn("protected-1",attachment_node.evidence_ids)
        exact=result_for({"driver_type":"rbd","target_count":1,"multipath":None})
        exact_node=next(node for node in exact.nodes if node.kind=="volume_attachment")
        before=deepcopy(exact_node.facts)
        control._bind_cinder_connection_summaries(exact,[summary])
        self.assertEqual([],exact.blockers); self.assertEqual(before,exact_node.facts)
        self.assertEqual(["protected-1"],exact_node.evidence_ids)

    def test_protected_cinder_overlay_is_ephemeral_and_exact(self):
        volume="22222222-2222-4222-8222-222222222222"; attachment="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        stored=[{"_schema":"cinder","_table":"volume_attachment","row":{"id":attachment,"volume_id":volume,"attach_status":"attached"}}]
        class Base:
            def db_records(self,table,filters=None):
                return deepcopy(stored),{"evidence_id":"source-db:cinder.volume_attachment","schema":"cinder","table":table,"filters":deepcopy(filters)}
        summary={"volume_id":volume,"attachment_id":attachment,"evidence_id":"protected-1","backend_kind":"rbd","backend_id":"rbd-backend","resource_identity":"volumes/volume-1","resource_fingerprint":hashlib.sha256(b"rbd:volumes/volume-1").hexdigest()}
        sensitive={"protected-1":{"volume_id":volume,"attachment_id":attachment,"connector":{"volume_id":volume,"attachment_id":attachment,"host":"compute-1"},"connection_info":{"driver_volume_type":"rbd","data":{"pool":"volumes","image":"volume-1","hosts":["10.0.0.10"]}}}}
        client=control._ProtectedCinderClient(Base(),[summary],sensitive)
        rows,_=client.db_records("volume_attachment",{"volume_id":[volume]})
        self.assertEqual("rbd",rows[0]["row"]["connection_info"]["driver_volume_type"])
        self.assertNotIn("connection_info",stored[0]["row"])
        wrong=deepcopy(sensitive); wrong["protected-1"]["connector"]["attachment_id"]="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        with self.assertRaises(ValueError): control._ProtectedCinderClient(Base(),[summary],wrong)

    def test_root_manifest_is_merged_before_recursive_api_closure(self):
        ids = {name: f"{index:08d}-1111-4111-8111-{index:012d}" for index, name in enumerate((
            "instance","port","child_port","network","subnet","security_group","qos","trunk","floating","router","address_group","volume","type","attachment","snapshot","secret","image","flavor"
        ), start=1)}
        roots = {
            "instances":[ids["instance"]],"ports":[ids["port"]],"networks":[ids["network"]],"subnets":[ids["subnet"]],
            "security_groups":[ids["security_group"]],"qos_policies":[ids["qos"]],"trunks":[ids["trunk"]],"floating_ips":[ids["floating"]],
            "routers":[ids["router"]],"address_groups":[ids["address_group"]],"volumes":[ids["volume"]],"volume_types":[ids["type"]],
            "attachments":[ids["attachment"]],"snapshots":[ids["snapshot"]],"images":[ids["image"]],"flavors":[ids["flavor"]],
        }
        calls = []
        class Client:
            def __init__(self, *args): pass
            def json(self, command, evidence_id):
                calls.append(tuple(command))
                if command[:2] == ["server","list"] or command[:3] == ["compute","service","list"] or command[:3] == ["resource","provider","list"] or command[:3] == ["image","stores","info"] or command[:3] == ["volume","service","list"]:
                    payload = []
                elif command[:2] == ["port","list"] or command[:3] == ["server","volume","list"] or command[:3] == ["image","member","list"]:
                    payload = []
                elif command[:2] == ["server","show"]:
                    payload = {"id":ids["instance"],"flavor":{"id":ids["flavor"]},"image":{"id":ids["image"]}}
                elif command[:2] == ["volume","show"]:
                    payload = {"id":ids["volume"],"volume_type_id":ids["type"],"snapshot_id":ids["snapshot"],"encryption_key_id":ids["secret"],"attachments":[{"id":ids["attachment"]}]}
                elif command[:3] == ["network","trunk","show"]:
                    payload = {"id":ids["trunk"],"sub_ports":[{"port_id":ids["child_port"]}]}
                else:
                    payload = {"id": command[-4] if len(command) > 4 else ids["instance"]}
                return payload, _api_evidence(evidence_id)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "roots.json"
            manifest.write_text(json.dumps({"schema_version":"openstack-rehome-root-manifest/v1alpha1","side":"source","roots":roots}),encoding="utf-8")
            manifest.chmod(0o600)
            schema = root / "information-schema.tsv"
            lines = ["SERVICE:all", "SECTION:COLUMNS"]
            for identity in sorted(set().union(*_collector_table_catalog().values())):
                schema_name, table = identity.split(".", 1)
                columns = {"id", *(column for _, column in _TABLE_ROOT_FILTERS[identity])}
                for ordinal, column in enumerate(sorted(columns), start=1):
                    lines.append(f"{schema_name}\t{table}\t{ordinal}\t{column}\tvarchar(255)\tYES\tNULL\t\\N")
            schema.write_text("\n".join(lines) + "\n", encoding="utf-8")
            args = type("Args",(),{"fixture":None,"rehome_host":"compute-023","cloud":"cloud","clouds_file":Path("/clouds.yaml"),"container":"toolbox","side":"source","information_schema":schema,"root_manifest":manifest,"probe_config":None,"capability_config":None,"phase_key_file":None,"phase_key_env":"LIVE_DISCOVERY_TEST_KEY","out":root/"out"})()
            with mock.patch("live_discovery.openstack.OpenStackClient",Client), mock.patch.dict("os.environ",{"LIVE_DISCOVERY_TEST_KEY":"test-phase-anchor-at-least-sixteen"}):
                _api_phase(args)
        expected = [
            ("server","show",ids["instance"]),("flavor","show",ids["flavor"]),("port","show",ids["port"]),
            ("port","show",ids["child_port"]),
            ("network","show",ids["network"]),("subnet","show",ids["subnet"]),("network","trunk","show",ids["trunk"]),
            ("router","show",ids["router"]),("floating","ip","show",ids["floating"]),("volume","attachment","show",ids["attachment"]),
            ("volume","type","show",ids["type"]),("volume","snapshot","show",ids["snapshot"]),("secret","get",ids["secret"]),
            ("image","show",ids["image"]),("image","member","list",ids["image"]),
        ]
        for prefix in expected:
            self.assertTrue(any(command[:len(prefix)] == prefix for command in calls), prefix)

    def test_phase_binding_is_externally_keyed(self):
        documents = ({"a": 1}, {"b": 2}, {"c": 3})
        first = _phase_binding(*documents, key=b"first-trust-anchor")
        second = _phase_binding(*documents, key=b"second-trust-anchor")
        self.assertNotEqual(first, second)
        self.assertRegex(first, r"^[0-9a-f]{64}$")

    def test_db_cache_allows_only_proven_planned_superset(self):
        one = "11111111-1111-1111-1111-111111111111"
        two = "22222222-2222-2222-2222-222222222222"
        records = [{"schema":"neutron","table":"ports","filters":{"id":[one,two]},"rows":[
            {"_schema":"neutron","_table":"ports","row":{"id":one}},
            {"_schema":"neutron","_table":"ports","row":{"id":two}},
        ]}]
        evidence = [{"evidence_id":"source-db:neutron.ports","kind":"db-jsonl","schema":"neutron","table":"ports","filters":{"id":[one,two]}}]
        client = _CombinedClient("source", {"openstack":[],"roots":{"ports":[one,two]}}, records, evidence)
        rows, proof = client.db_records("neutron", "ports", {"id":[one]})
        self.assertEqual([one], [item["row"]["id"] for item in rows])
        self.assertEqual({"id":[one]}, proof["filters"])
        missing, _ = client.db_records("neutron", "ports", {"id":["33333333-3333-3333-3333-333333333333"]})
        self.assertEqual([], missing)

    def test_db_cache_miss_is_typed_and_recorded(self):
        port_id="33333333-3333-3333-3333-333333333333"
        client=_CombinedClient("source",{"openstack":[],"roots":{"ports":[port_id]}},[],[])
        rows,_=client.db_records("neutron","ports",{"id":[port_id]})
        self.assertEqual([],rows)
        self.assertEqual([{"schema":"neutron","table":"ports","filters":{"id":[port_id]}}],client.db_cache_misses)

    def test_db_cache_identity_is_schema_qualified_for_services(self):
        nova_service="11111111-1111-4111-8111-111111111111"
        cinder_service="22222222-2222-4222-8222-222222222222"
        records=[
            {"schema":"nova","table":"services","filters":{"uuid":[nova_service]},"rows":[{"_schema":"nova","_table":"services","row":{"uuid":nova_service}}]},
            {"schema":"cinder","table":"services","filters":{"uuid":[cinder_service]},"rows":[{"_schema":"cinder","_table":"services","row":{"uuid":cinder_service}}]},
        ]
        evidence=[{"evidence_id":f"source-db:{item['schema']}.services","kind":"db-jsonl","schema":item["schema"],"table":"services","filters":deepcopy(item["filters"])} for item in records]
        client=_CombinedClient("source",{"openstack":[],"roots":{"services":[nova_service],"cinder_services":[cinder_service]}},records,evidence)
        nova_rows,nova_proof=client.db_records("nova","services",{"uuid":[nova_service]})
        cinder_rows,cinder_proof=client.db_records("cinder","services",{"uuid":[cinder_service]})
        self.assertEqual(nova_service,nova_rows[0]["row"]["uuid"])
        self.assertEqual(cinder_service,cinder_rows[0]["row"]["uuid"])
        self.assertEqual("nova",nova_proof["schema"]); self.assertEqual("cinder",cinder_proof["schema"])
        wrong_only=_CombinedClient("source",{"openstack":[],"roots":{"services":[nova_service]}},records[1:],evidence[1:])
        missing,proof=wrong_only.db_records("nova","services",{"uuid":[nova_service]})
        self.assertEqual([],missing); self.assertEqual("source-db:unknown.nova.services",proof["evidence_id"])
        self.assertEqual([{"schema":"nova","table":"services","filters":{"uuid":[nova_service]}}],wrong_only.db_cache_misses)
        empty_row=deepcopy(records[0]); empty_row["rows"]=[]
        empty=_CombinedClient("source",{"openstack":[],"roots":{"services":[nova_service]}},[empty_row],[evidence[0]])
        empty_rows,empty_proof=empty.db_records("nova","services",{"uuid":[nova_service]})
        self.assertEqual([],empty_rows); self.assertEqual("source-db:unknown.nova.services",empty_proof["evidence_id"])
        self.assertEqual([{"schema":"nova","table":"services","filters":{"uuid":[nova_service]}}],empty.db_cache_misses)

    def test_api_and_db_closure_misses_emit_distinct_unknown_checks(self):
        checks=control._closure_checks("source",[["port","show","missing"]],[{"schema":"neutron","table":"ports","filters":{"id":["33333333-3333-3333-3333-333333333333"]}}])
        self.assertEqual(["control.source.api-closure","control.source.db-closure"],[item["check_id"] for item in checks])
        self.assertTrue(all(item["status"]=="UNKNOWN" for item in checks))

    def test_root_manifest_categories_are_canonical(self):
        valid = {"roots":{"hosts":["compute-023.example"],"ports":["11111111-1111-1111-1111-111111111111"]}}
        self.assertEqual(2, len(_root_filter_values(valid)))
        for invalid in (
            {"roots":{"ports":[1]}},
            {"roots":{"ports":["NOT-A-UUID"]}},
            {"roots":{"hosts":["bad host"]}},
        ):
            with self.assertRaises(ValueError):
                _root_filter_values(invalid)

    def test_protected_json_uses_open_descriptor_not_path_open(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "protected.json"
            path.write_text('{"safe":true}', encoding="utf-8")
            path.chmod(0o600)
            with mock.patch.object(Path, "open", side_effect=AssertionError("path reopen")), mock.patch.object(Path, "read_text", side_effect=AssertionError("path reopen")):
                self.assertEqual({"safe": True}, _read_protected_json(path))
            link = Path(temporary) / "protected-link.json"
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                _read_protected_json(link)

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
                elif command[:4] == ["resource", "provider", "allocation", "show"]:
                    payload = {"allocations": {compute_id: {"resources": {"VCPU": 1}}}}
                elif command[:2] == ["server", "show"]:
                    payload = {"id": instance_id, "project_id": "77777777-7777-7777-7777-777777777777", "image": {"id": "44444444-4444-4444-4444-444444444444"}}
                elif command[:2] == ["port", "list"] or command[:3] == ["server", "volume", "list"]:
                    payload = []
                elif command[:3] == ["image", "stores", "info"] or command[:2] == ["image", "member"]:
                    payload = []
                elif command[:3] == ["catalog", "show", "glance"]:
                    payload = {"public":"https://glance.example"}
                elif command[:2] == ["image", "show"]:
                    payload = {"id":"44444444-4444-4444-4444-444444444444"}
                else:
                    raise AssertionError(command)
                return payload, _api_evidence(evidence_id)
        with tempfile.TemporaryDirectory() as temporary:
            args = type("Args", (), {
                "fixture": None, "rehome_host": "compute-023", "cloud": "cloud",
                "clouds_file": Path("/clouds.yaml"), "container": "toolbox",
                "side": "source", "information_schema": FIXTURES / "control-information-schema.tsv",
                "root_manifest": None, "probe_config": None, "capability_config": None,
                "phase_key_file": None, "phase_key_env": "LIVE_DISCOVERY_TEST_KEY",
                "out": Path(temporary) / "api",
            })()
            with mock.patch("live_discovery.openstack.OpenStackClient", Client), mock.patch.dict("os.environ", {"LIVE_DISCOVERY_TEST_KEY":"test-phase-anchor-at-least-sixteen"}):
                _api_phase(args)
            plan = json.loads((args.out / "db-query-plan.json").read_text())
            self.assertEqual(_collector_table_catalog()["nova"], {f"{item['schema']}.{item['table']}" for item in plan["queries"]})
            self.assertTrue(all(item["filters"] for item in plan["queries"]))
    def test_full_root_plan_catalog_equals_all_collector_db_table_calls(self):
        catalog = _collector_table_catalog()
        self.assertEqual(
            {f"{DB_SCHEMAS[table]}.{table}" for table in DB_TABLES if table != "cell_mappings"},
            catalog["nova"],
        )
        self.assertEqual({f"neutron.{table}" for table in set(NEUTRON_CORE) | {table for family in NEUTRON_OPTIONAL.values() for table in family}}, catalog["neutron"])
        self.assertEqual({f"cinder.{table}" for table in set(CINDER_CORE) | set(CINDER_OPTIONAL)}, catalog["cinder"])
        roots = {
            category: ["11111111-1111-1111-1111-111111111111"]
            for choices in _TABLE_ROOT_FILTERS.values()
            for category, _ in choices
        }
        expected = _expected_plan_tables("source", roots, set().union(*catalog.values()))
        self.assertEqual(set().union(*catalog.values()), expected)

    def test_target_live_like_all_collectors_have_zero_cache_misses_and_real_evidence(self):
        manage=json.loads((ROOT/"tests/fixtures/live_discovery/openstack-command-results.json").read_text())["manage_outputs"]
        capability_ids = ("nova-online-data-migrations", "cinder-online-data-migrations")
        api={"observed_at":"2026-07-12T09:00:00Z","openstack":[],"roots":{"ports":[],"volumes":[],"images":[],"projects":[]},"target_manage_outputs":manage,"target_image_inspects":{},"target_runtime_outputs":{"runtime-target-virsh-version":"9.0.0","runtime-target-domcapabilities":"<domainCapabilities><devices><disk><enum name='bus'><value>virtio</value></enum></disk></devices></domainCapabilities>","runtime-target-qemu-machine-help":"Supported machines are:\npc-q35-8.2 fixture\n"},"target_virsh_argv":["virsh"],"target_qemu_argv":["qemu-system-x86_64"],"capability_evidence":[{"evidence_id":"nova-online-data-migrations","kind":"runtime-command","side":"target","service":"target-profile","command":["nova-manage","db","online_data_migrations"]},{"evidence_id":"cinder-online-data-migrations","kind":"runtime-command","side":"target","service":"target-profile","command":["cinder-manage","db","online_data_migrations"]}],"probe_statuses":{identity:{"returncode":0,"failure_class":None,"stderr_sha256":hashlib.sha256(b"").hexdigest()} for identity in capability_ids}}
        for identity in (
            "runtime-target-virsh-version",
            "runtime-target-domcapabilities",
            "runtime-target-qemu-machine-help",
        ):
            api["capability_evidence"].append({
                "evidence_id": identity,
                "kind": "runtime-command",
                "side": "target",
                "service": "runtime-capabilities",
                "command": [identity],
            })
            api["probe_statuses"][identity] = {
                "returncode": 0,
                "failure_class": None,
                "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            }
        collectors,misses,db_misses=control._compose_collectors("target",api,[],[],SchemaSnapshot(tables={}))
        self.assertEqual([],misses)
        self.assertEqual([],db_misses)
        self.assertEqual({"target-profile","runtime-capabilities","neutron","cinder","glance"},{item["service"] for item in collectors})
        index=control._build_evidence_index("target",collectors,api,[])
        identities={item["evidence_id"] for item in index}
        self.assertIn("runtime-target-virsh-version",identities)
        self.assertIn("nova-online-data-migrations",identities)

    def test_nonempty_source_and_target_phase_composition_is_schema_qualified(self):
        from tests import test_live_discovery_neutron as neutron_test
        from tests import test_live_discovery_cinder as cinder_test

        ids={
            "instance":"11111111-1111-4111-8111-111111111111","volume":"10000000-0000-4000-8000-000000000001",
            "attachment":"10000000-0000-4000-8000-000000000002","volume_type":"10000000-0000-4000-8000-000000000003",
            "attachment2":"10000000-0000-4000-8000-000000000011",
            "cinder_service":"10000000-0000-4000-8000-000000000004","secret":"10000000-0000-4000-8000-000000000005",
            "port":"00000000-0000-4000-8000-000000000001","network":"00000000-0000-4000-8000-000000000002",
            "subnet":"00000000-0000-4000-8000-000000000004","segment":"00000000-0000-4000-8000-000000000005",
            "image":"44444444-4444-4444-8444-444444444444","project":"77777777-7777-4777-8777-777777777777",
            "member":"88888888-8888-4888-8888-888888888888","flavor":"55555555-5555-4555-8555-555555555555",
            "nova_service":"cccccccc-cccc-4ccc-8ccc-cccccccccccc","compute":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "provider":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","cell":"99999999-9999-4999-8999-999999999999",
        }
        host="compute-023"
        neutron_fixture=neutron_test.canonical_uuid_fixture(json.loads((ROOT/"tests/fixtures/live_discovery/neutron-ovs-source.json").read_text()))
        neutron_aliases={neutron_test.UUID_ALIASES["port-1"]:ids["port"],neutron_test.UUID_ALIASES["network-1"]:ids["network"],neutron_test.UUID_ALIASES["subnet-1"]:ids["subnet"],neutron_test.UUID_ALIASES["segment-1"]:ids["segment"],neutron_test.UUID_ALIASES["instance-1"]:ids["instance"]}
        cinder_fixture=cinder_test.canonical_fixture(json.loads((ROOT/"tests/fixtures/live_discovery/cinder-source.json").read_text()))
        cinder_aliases={cinder_test.CANONICAL_IDS["volume-1"]:ids["volume"],cinder_test.CANONICAL_IDS["attachment-1"]:ids["attachment"],cinder_test.CANONICAL_IDS["type-1"]:ids["volume_type"],cinder_test.CANONICAL_IDS["service-1"]:ids["cinder_service"],cinder_test.CANONICAL_IDS["key-1"]:ids["secret"],cinder_test.CANONICAL_IDS["instance-1"]:ids["instance"]}
        def replace(value,mapping):
            if isinstance(value,str):
                for old,new in mapping.items(): value=value.replace(old,new)
                return value
            if isinstance(value,list): return [replace(item,mapping) for item in value]
            if isinstance(value,dict): return {key:replace(item,mapping) for key,item in value.items()}
            return value
        neutron_fixture=replace(neutron_fixture,neutron_aliases)
        cinder_fixture=replace(cinder_fixture,cinder_aliases)
        neutron_tables={table:deepcopy(neutron_fixture["tables"].get(table,[])) for table in neutron_fixture["schema_tables"]}
        for row in neutron_tables.get("ports",[]): row["device_id"]=ids["instance"]
        cinder_tables={table:deepcopy(cinder_fixture["tables"].get(table,[])) for table in cinder_fixture["schema_tables"]}
        volume_row=cinder_tables["volumes"][0]; volume_row.update({"storage_backend_id":"rbd-backend","host":"cinder@backend#rbd","cluster_name":"cluster@backend"})
        service_row=cinder_tables["services"][0]; service_row.update({"host":"cinder@backend#rbd","cluster_name":"cluster@backend"})
        attachment_row=cinder_tables["volume_attachment"][0]
        attachment_row["connection_info"]=json.dumps({"driver_volume_type":"rbd","data":{"name":f"volumes/volume-{ids['volume']}","pool":"volumes","image":f"volume-{ids['volume']}","hosts":["10.0.0.10"]}})
        attachment_row["connector"]=json.dumps({"host":host,"attachment_id":ids["attachment"],"volume_id":ids["volume"]})
        attachment_row2=deepcopy(attachment_row); attachment_row2["id"]=ids["attachment2"]
        attachment_row2["connector"]=json.dumps({"host":host,"attachment_id":ids["attachment2"],"volume_id":ids["volume"]})
        cinder_tables["volume_attachment"].append(attachment_row2)
        cinder_tables["volume_types"][0]["name"]="encrypted-rbd"
        cinder_tables["volume_glance_metadata"][0]["value"]=ids["image"]
        nova_tables={
            "nova_api.host_mappings":[{"id":5,"host":host,"cell_id":ids["cell"]}],
            "nova_api.instance_mappings":[{"id":11,"instance_uuid":ids["instance"],"cell_id":ids["cell"],"project_id":ids["project"]}],
            "nova_api.request_specs":[{"id":12,"instance_uuid":ids["instance"],"spec":json.dumps({"instance_uuid":ids["instance"]})}],
            "nova.instances":[{"id":21,"uuid":ids["instance"],"host":host,"project_id":ids["project"],"user_id":"user-1","instance_type_id":ids["flavor"],"image_ref":ids["image"],"deleted":0}],
            "nova.block_device_mapping":[{"id":31,"instance_uuid":ids["instance"],"volume_id":ids["volume"],"boot_index":0,"source_type":"volume","destination_type":"volume","deleted":0}],
            "nova.instance_info_caches":[{"id":32,"instance_uuid":ids["instance"],"network_info":json.dumps([{"id":ids["port"]}]),"deleted":0}],
            "nova.compute_nodes":[{"id":7,"uuid":ids["compute"],"service_id":42,"hypervisor_hostname":host,"host":host,"vcpus":16,"memory_mb":32768}],
            "nova.services":[{"id":42,"uuid":ids["nova_service"],"host":host,"binary":"nova-compute","disabled":0,"deleted":0}],
        }
        table_rows={**nova_tables,**{f"neutron.{table}":rows for table,rows in neutron_tables.items()},**{f"cinder.{table}":rows for table,rows in cinder_tables.items()}}
        available=set(table_rows)
        for table in DB_TABLES: available.add(f"{DB_SCHEMAS[table]}.{table}")
        available.update(f"neutron.{table}" for table in neutron_fixture["schema_tables"])
        available.update(f"cinder.{table}" for table in cinder_fixture["schema_tables"])
        responses={
            ("server","list","--all-projects","--host",host,"--long","-f","json"):[{"ID":ids["instance"],"Host":host,"Status":"ACTIVE"}],
            ("compute","service","list","--host",host,"-f","json"):[{"UUID":ids["nova_service"],"ID":42,"Binary":"nova-compute","Host":host,"Status":"enabled","State":"up"}],
            ("hypervisor","show",host,"-f","json"):{"uuid":ids["compute"],"hypervisor_hostname":host,"status":"enabled","state":"up"},
            ("resource","provider","list","--name",host,"-f","json"):[{"uuid":ids["provider"],"name":host}],
            ("server","show",ids["instance"],"-f","json"):{"id":ids["instance"],"status":"ACTIVE","OS-EXT-SRV-ATTR:host":host,"project_id":ids["project"],"user_id":"user-1","flavor":{"id":ids["flavor"]},"image":{"id":ids["image"]}},
            ("resource","provider","allocation","show",ids["instance"],"-f","json"):{"allocations":{ids["provider"]:{"resources":{"VCPU":1,"MEMORY_MB":2048}}}},
            ("port","list","--server",ids["instance"],"-f","json"):[{"id":ids["port"]}],
            ("server","volume","list",ids["instance"],"-f","json"):[{"id":ids["volume"]}],
            ("flavor","show",ids["flavor"],"-f","json"):{"id":ids["flavor"],"name":"m1.small","vcpus":1,"ram":2048,"disk":20},
            ("port","show",ids["port"],"-f","json"):{"id":ids["port"],"network_id":ids["network"],"subnet_id":ids["subnet"],"security_group_ids":[neutron_test.UUID_ALIASES["sg-1"]],"device_id":ids["instance"],"device_owner":"compute:nova","binding_host_id":host,"binding_vif_type":"ovs","mac_address":"fa:16:3e:12:34:56"},
            ("network","show",ids["network"],"-f","json"):{"id":ids["network"],"name":"tenant-net","subnets":[ids["subnet"]]},
            ("network","show",neutron_test.UUID_ALIASES["network-external"],"-f","json"):{"id":neutron_test.UUID_ALIASES["network-external"],"name":"external-net"},
            ("subnet","show",ids["subnet"],"-f","json"):{"id":ids["subnet"],"network_id":ids["network"],"cidr":"192.0.2.0/24"},
            ("security","group","show",neutron_test.UUID_ALIASES["sg-1"],"-f","json"):{"id":neutron_test.UUID_ALIASES["sg-1"],"name":"default"},
            ("network","qos","policy","show",neutron_test.UUID_ALIASES["qos-1"],"-f","json"):{"id":neutron_test.UUID_ALIASES["qos-1"],"name":"gold"},
            ("network","trunk","show",neutron_test.UUID_ALIASES["trunk-1"],"-f","json"):{"id":neutron_test.UUID_ALIASES["trunk-1"],"port_id":ids["port"],"sub_ports":[]},
            ("floating","ip","show",neutron_test.UUID_ALIASES["fip-1"],"-f","json"):{"id":neutron_test.UUID_ALIASES["fip-1"],"port_id":ids["port"],"router_id":neutron_test.UUID_ALIASES["router-1"],"floating_network_id":neutron_test.UUID_ALIASES["network-external"]},
            ("router","show",neutron_test.UUID_ALIASES["router-1"],"-f","json"):{"id":neutron_test.UUID_ALIASES["router-1"],"name":"router"},
            ("address","group","show",neutron_test.UUID_ALIASES["address-group-1"],"-f","json"):{"id":neutron_test.UUID_ALIASES["address-group-1"],"name":"trusted"},
            ("volume","show",ids["volume"],"-f","json"):{"id":ids["volume"],"status":"in-use","size":1,"volume_type_id":ids["volume_type"],"service_uuid":ids["cinder_service"],"host":"cinder@backend#rbd","cluster_name":"cluster@backend","encryption_key_id":ids["secret"],"attachments":[{"id":ids["attachment"]},{"id":ids["attachment2"]}]},
            ("volume","attachment","show",ids["attachment"],"-f","json"):{"id":ids["attachment"],"volume_id":ids["volume"],"server_id":ids["instance"],"status":"attached","attach_mode":"rw"},
            ("volume","attachment","show",ids["attachment2"],"-f","json"):{"id":ids["attachment2"],"volume_id":ids["volume"],"server_id":ids["instance"],"status":"attached","attach_mode":"rw"},
            ("volume","type","show",ids["volume_type"],"-f","json"):{"id":ids["volume_type"],"name":"encrypted-rbd","is_public":False,"qos_specs_id":cinder_test.CANONICAL_IDS["qos-1"]},
            ("volume","qos","show",cinder_test.CANONICAL_IDS["qos-1"],"-f","json"):{"id":cinder_test.CANONICAL_IDS["qos-1"],"name":"gold","consumer":"both"},
            ("volume","service","list","--long","-f","json"):[{"id":ids["cinder_service"],"uuid":ids["cinder_service"],"host":"cinder@backend#rbd","cluster_name":"cluster@backend","binary":"cinder-volume","status":"enabled","state":"up"}],
            ("secret","get",ids["secret"],"-f","json"):{"id":ids["secret"],"status":"ACTIVE"},
            ("image","show",ids["image"],"-f","json"):{"id":ids["image"],"name":"epoxy-base","status":"active","size":1024,"visibility":"shared","owner":ids["project"],"disk_format":"qcow2","container_format":"bare","protected":False,"min_disk":1,"min_ram":256,"os_hash_algo":"sha256","os_hash_value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","checksum":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","tags":["base","epoxy"],"stores":["rbd"],"locations":[{"url":f"rbd://cluster/pool/{ids['image']}/snap","metadata":{"store":"rbd"}}]},
            ("image","member","list",ids["image"],"-f","json"):[{"image_id":ids["image"],"member_id":ids["project"],"status":"accepted"}],
            ("image","stores","info","-f","json"):[{"ID":"rbd","Description":"Ceph RBD","Default":True}],
            ("catalog","show","glance","-f","json"):{"endpoints":[{"interface":"public","url":"https://glance.example"}]},
        }
        class ApiClient:
            def __init__(self,*args): pass
            def json(self,command,evidence_id,required=True):
                del required
                key=tuple(command)
                if key not in responses: raise AssertionError(f"unexpected OpenStack command: {command}")
                return deepcopy(responses[key]),_api_evidence(evidence_id)
        class Runner:
            side="target"
            def run(self,argv,evidence_id,*args,**kwargs):
                del argv,args,kwargs
                return type("Evidence",(),{"stdout":json.dumps({"size":1024**3}),"stderr":"","returncode":0,"evidence_id":evidence_id})()
        def write_schema(path):
            lines=["SERVICE:all","SECTION:COLUMNS"]
            for identity in sorted(available):
                schema,table=identity.split(".",1); columns=set()
                for row in table_rows.get(identity,[]): columns.update(row)
                columns.update(column for _,column in _TABLE_ROOT_FILTERS.get(identity, ()))
                for ordinal,column in enumerate(sorted(columns),start=1): lines.append(f"{schema}\t{table}\t{ordinal}\t{column}\tvarchar(255)\tYES\tNULL\t\\N")
            lines.extend(["SECTION:STATISTICS", "SECTION:FOREIGN_KEYS"])
            path.write_text("\n".join(lines)+"\n",encoding="utf-8")
        def write_db(plan,path,side_name,missing_service_schema=None):
            path.mkdir()
            for query in plan:
                rows=[]
                for candidate in table_rows.get(f"{query['schema']}.{query['table']}",[]):
                    if query["schema"]==missing_service_schema and query["table"]=="services": continue
                    if any(candidate.get(column) in values for column,values in query["filters"].items()): rows.append({column:candidate.get(column) for column in query["columns"]})
                (path/query["rc_file"]).write_text("0\n",encoding="ascii")
                (path/query["jsonl_file"]).write_text("".join(json.dumps({"_schema":query["schema"],"_table":query["table"],"row":row})+"\n" for row in rows),encoding="utf-8")
                _write_db_evidence(path, query, side=side_name)
        with tempfile.TemporaryDirectory() as temporary, mock.patch("live_discovery.openstack.OpenStackClient",ApiClient), mock.patch.object(control,"ReadOnlyRunner",Runner), mock.patch.object(control,"probe_image_data",return_value=CheckResult("glance.data","PASS","image byte is readable")), mock.patch.dict(os.environ,{"LIVE_DISCOVERY_PHASE_KEY":"phase-anchor-at-least-sixteen","LIVE_DISCOVERY_GLANCE_TOKEN":"ephemeral-token"}):
            root=Path(temporary); schema=root/"information-schema.tsv"; write_schema(schema)
            policy=FIXTURES/"schema-policy.json"
            combined_by_side={}
            for side in ("source","target"):
                side_root=root/side; side_root.mkdir()
                root_manifest={"schema_version":"openstack-rehome-root-manifest/v1alpha1","side":side,"roots":{"ports":[ids["port"]],"networks":[ids["network"],neutron_test.UUID_ALIASES["network-external"]],"subnets":[ids["subnet"]],"security_groups":[neutron_test.UUID_ALIASES["sg-1"]],"qos_policies":[neutron_test.UUID_ALIASES["qos-1"]],"trunks":[neutron_test.UUID_ALIASES["trunk-1"]],"floating_ips":[neutron_test.UUID_ALIASES["fip-1"]],"routers":[neutron_test.UUID_ALIASES["router-1"]],"address_groups":[neutron_test.UUID_ALIASES["address-group-1"]],"qos_specs":[cinder_test.CANONICAL_IDS["qos-1"]]}}
                root_path=side_root/"roots.json"; root_path.write_text(json.dumps(root_manifest),encoding="utf-8"); root_path.chmod(0o600)
                probe={"schema_version":"openstack-rehome-probe-config/v1alpha1","storage":[{"volume_id":ids["volume"],"scope":"source-compute" if side=="source" else "target-storage","kind":"rbd","backend_id":"rbd-backend","resource":{"pool":"volumes","image":f"volume-{ids['volume']}","allowed_pools":["volumes"],"expected_size":1024**3}}],"glance":{"endpoint_url":"https://glance.example","token_env":"LIVE_DISCOVERY_GLANCE_TOKEN","images":[{"image_id":ids["image"],"expected_size":1024,"required":True,"store_ids":["rbd"]}],"store_capabilities":[{"store_id":"rbd","backend_type":"rbd"}]}}
                probe_path=side_root/"probe.json"; probe_path.write_text(json.dumps(probe),encoding="utf-8"); probe_path.chmod(0o600)
                capability_path=None
                if side=="target":
                    manage=json.loads((ROOT/"tests/fixtures/live_discovery/openstack-command-results.json").read_text())["manage_outputs"]
                    capability={"schema_version":"openstack-rehome-target-capability-input/v1alpha1","target_manage_outputs":manage,"target_image_inspects":{"nova_api":{"Config":{"Image":"quay.io/openstack.kolla/nova-api:2025.1-ubuntu-noble"},"Image":"sha256:nova-api"}},"target_runtime_outputs":{"runtime-target-virsh-version":"9.0.0","runtime-target-domcapabilities":"<domainCapabilities><devices><disk><enum name='bus'><value>virtio</value></enum></disk></devices></domainCapabilities>","runtime-target-qemu-machine-help":"Supported machines are:\npc-q35-8.2 fixture\n"},"target_virsh_argv":["virsh"],"target_qemu_argv":["qemu-system-x86_64"],"schema_capabilities":{"nova":{"release":"2025.1","distribution":"vanilla"}},"capability_evidence":[{"evidence_id":"nova-online-data-migrations","kind":"runtime-command","side":"target","service":"target-profile","command":["nova-manage","db","online_data_migrations"]},{"evidence_id":"cinder-online-data-migrations","kind":"runtime-command","side":"target","service":"target-profile","command":["cinder-manage","db","online_data_migrations"]}],"probe_statuses":{identity:{"returncode":0,"failure_class":None,"stderr_sha256":hashlib.sha256(b"").hexdigest()} for identity in ("nova-online-data-migrations","cinder-online-data-migrations")}}
                    for identity in (
                        "runtime-target-virsh-version",
                        "runtime-target-domcapabilities",
                        "runtime-target-qemu-machine-help",
                    ):
                        capability["capability_evidence"].append({
                            "evidence_id": identity,
                            "kind": "runtime-command",
                            "side": "target",
                            "service": "runtime-capabilities",
                            "command": [identity],
                        })
                        capability["probe_statuses"][identity] = {
                            "returncode": 0,
                            "failure_class": None,
                            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                        }
                    capability_path=side_root/"capability.json"; capability_path.write_text(json.dumps(capability),encoding="utf-8"); capability_path.chmod(0o600)
                api_dir=side_root/"api"
                args=type("Args",(),{"fixture":None,"rehome_host":host,"cloud":"cloud","clouds_file":Path("/clouds.yaml"),"container":"toolbox","side":side,"information_schema":schema,"root_manifest":root_path,"probe_config":probe_path,"capability_config":capability_path,"phase_key_file":None,"phase_key_env":"LIVE_DISCOVERY_PHASE_KEY","out":api_dir})()
                _api_phase(args)
                api_document=json.loads((api_dir/"api-result.json").read_text())
                for category,values in api_document["api_result"]["roots"].items():
                    if category not in {"hosts","glance_stores"}:
                        self.assertTrue(all(control._canonical_uuid(value) is not None for value in values),(side,category,values))
                plan=json.loads((api_dir/"db-query-plan.json").read_text())["queries"]
                if side=="source": self.assertTrue({("nova","services"),("cinder","services")}.issubset({(item["schema"],item["table"]) for item in plan}))
                db_dir=side_root/"db"; write_db(plan,db_dir,side)
                protected_entries=[{"evidence_id":f"cinder-{side}-connection-{attachment_id}","volume_id":ids["volume"],"attachment_id":attachment_id,"backend_kind":"rbd","backend_id":"rbd-backend","resource_identity":f"volumes/volume-{ids['volume']}","connector":{"host":host,"attachment_id":attachment_id,"volume_id":ids["volume"]},"connection_info":{"driver_volume_type":"rbd","data":{"name":f"volumes/volume-{ids['volume']}","pool":"volumes","image":f"volume-{ids['volume']}","hosts":["10.0.0.10"]}}} for attachment_id in (ids["attachment"],ids["attachment2"])]
                sensitive={"schema_version":"openstack-rehome-cinder-sensitive-evidence/v1alpha1","side":side,"entries":protected_entries}
                sensitive_path=side_root/"cinder-sensitive.json"; sensitive_path.write_text(json.dumps(sensitive),encoding="utf-8"); sensitive_path.chmod(0o600)
                out=side_root/"combined"
                combine_values={"api_result":api_dir/"api-result.json","side":side,"fixture_phase":False,"phase_key_file":None,"phase_key_env":"LIVE_DISCOVERY_PHASE_KEY","cinder_sensitive_evidence":sensitive_path,"db_jsonl_dir":db_dir,"information_schema":schema,"schema_policy":policy,"out":out}
                combine=type("Args",(),combine_values)()
                control._combine_phase(combine)
                bundle=json.loads((out/"control-result.json").read_text())
                combined_by_side[side]=out/"control-result.json"
                self.assertEqual({},bundle["sensitive_evidence"])
                normal_bundle=(out/"control-result.json").read_text()
                self.assertNotIn("driver_volume_type",normal_bundle); self.assertNotIn("10.0.0.10",normal_bundle)
                self.assertEqual([],bundle["checks"]); self.assertTrue(bundle["evidence_index"])
                services={item["service"]:item for item in bundle["collectors"]}
                for service,collector in services.items():
                    self.assertEqual([],collector["blockers"],(side,service,collector["blockers"]))
                    self.assertEqual([],collector["unknowns"],(side,service,collector["unknowns"]))
                for service in ("neutron","cinder","glance"):
                    self.assertTrue(services[service]["nodes"] and services[service]["edges"],(side,service,services[service]["blockers"],services[service]["unknowns"]))
                if side=="source": self.assertTrue(services["nova"]["nodes"] and services["nova"]["edges"])
                self.assertTrue(any(item["kind"]=="storage-probe" and item["status"]=="PASS" for item in bundle["evidence_index"]))
                connection_entries=[item for item in bundle["evidence_index"] if item["kind"]=="cinder-connection"]
                self.assertEqual({ids["attachment"],ids["attachment2"]},{item["attachment_id"] for item in connection_entries})
                self.assertTrue(any(item["check_id"].startswith("cinder.storage.") and item["status"]=="PASS" for item in services["cinder"]["checks"]),services["cinder"]["blockers"])
                attachment_nodes={item["id"]:item for item in services["cinder"]["nodes"] if item["kind"]=="volume_attachment"}
                self.assertEqual({ids["attachment"],ids["attachment2"]},set(attachment_nodes))
                for attachment_id,node in attachment_nodes.items(): self.assertIn(f"cinder-{side}-connection-{attachment_id}",node["evidence_ids"])
                attachment_edges={item["target"] for item in services["cinder"]["edges"] if item["relation"]=="has_attachment" and item["required"]}
                self.assertEqual({f"volume_attachment:{ids['attachment']}",f"volume_attachment:{ids['attachment2']}"},attachment_edges)
                evidence_ids={item["evidence_id"] for item in bundle["evidence_index"]}
                referenced={evidence_id for collector in bundle["collectors"] for node in collector["nodes"] for evidence_id in node["evidence_ids"]}
                self.assertTrue(referenced.issubset(evidence_ids))
                if side=="source":
                    for missing_schema in ("nova","cinder"):
                        missing_db=side_root/f"db-missing-{missing_schema}"; write_db(plan,missing_db,side,missing_schema)
                        missing_out=side_root/f"combined-missing-{missing_schema}"
                        missing_args=type("Args",(),{**combine_values,"db_jsonl_dir":missing_db,"out":missing_out})()
                        control._combine_phase(missing_args)
                        missing_bundle=json.loads((missing_out/"control-result.json").read_text())
                        self.assertIn("control.source.db-closure",[item["check_id"] for item in missing_bundle["checks"]],missing_schema)
                    for removed_attachment in (ids["attachment"],ids["attachment2"]):
                        removed=deepcopy(sensitive); removed["entries"]=[item for item in removed["entries"] if item["attachment_id"]!=removed_attachment]
                        removed_path=side_root/f"cinder-sensitive-removed-{removed_attachment}.json"; removed_path.write_text(json.dumps(removed),encoding="utf-8"); removed_path.chmod(0o600)
                        removed_out=side_root/f"combined-removed-{removed_attachment}"
                        removed_args=type("Args",(),{**combine_values,"cinder_sensitive_evidence":removed_path,"out":removed_out})()
                        control._combine_phase(removed_args)
                        removed_bundle=json.loads((removed_out/"control-result.json").read_text())
                        removed_cinder=next(item for item in removed_bundle["collectors"] if item["service"]=="cinder")
                        self.assertIn(f"Cinder protected attachment evidence missing: {removed_attachment}",removed_cinder["blockers"])
                    swapped=deepcopy(sensitive)
                    swapped["entries"][0]["connector"],swapped["entries"][1]["connector"]=swapped["entries"][1]["connector"],swapped["entries"][0]["connector"]
                    swapped_path=side_root/"cinder-sensitive-swapped.json"; swapped_path.write_text(json.dumps(swapped),encoding="utf-8"); swapped_path.chmod(0o600)
                    swapped_args=type("Args",(),{**combine_values,"cinder_sensitive_evidence":swapped_path,"out":side_root/"combined-swapped-attachment"})()
                    with self.assertRaisesRegex(ValueError,"Cinder sensitive evidence identity is invalid"):
                        control._combine_phase(swapped_args)
            assembled_fixture=root/"assembled-fixture"; assembled_fixture.mkdir()
            (assembled_fixture/"source-control.json").write_text(combined_by_side["source"].read_text(),encoding="utf-8")
            (assembled_fixture/"target-control.json").write_text(combined_by_side["target"].read_text(),encoding="utf-8")
            (assembled_fixture/"runtime.json").write_text((FIXTURES/"ready/runtime.json").read_text(),encoding="utf-8")
            (assembled_fixture/"schema-policy.json").write_text(policy.read_text(),encoding="utf-8")
            assembled_out=root/"assembled-ready"
            assembled=subprocess.run([sys.executable,"scripts/assemble_live_discovery.py","--fixture-dir",str(assembled_fixture),"--out-dir",str(assembled_out)],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
            report=json.loads((assembled_out/"readiness-report.json").read_text())
            self.assertEqual(0,assembled.returncode,json.dumps(report,indent=2)+assembled.stdout+assembled.stderr)
            self.assertEqual("READY",report["verdict"])
            normal="\n".join(path.read_text(encoding="utf-8") for path in assembled_out.rglob("*") if path.is_file() and "sensitive" not in path.parts)
            self.assertNotIn("driver_volume_type",normal); self.assertNotIn("10.0.0.10",normal)
            file_root=root/"file-source"; file_root.mkdir()
            file_manifest=deepcopy(root_manifest); file_manifest["side"]="source"
            file_roots=file_root/"roots.json"; file_roots.write_text(json.dumps(file_manifest),encoding="utf-8"); file_roots.chmod(0o600)
            file_path=f"/srv/cinder/volume-{ids['volume']}"
            file_probe={"schema_version":"openstack-rehome-probe-config/v1alpha1","storage":[{"volume_id":ids["volume"],"scope":"source-compute","kind":"file","backend_id":"rbd-backend","resource":{"path":file_path,"allowed_roots":["/srv/cinder"],"expected_size":1024**3}}],"glance":{"endpoint_url":"https://glance.example","token_env":"LIVE_DISCOVERY_GLANCE_TOKEN","images":[{"image_id":ids["image"],"expected_size":1024,"required":True,"store_ids":["rbd"]}],"store_capabilities":[{"store_id":"rbd","backend_type":"rbd"}]}}
            file_probe_path=file_root/"probe.json"; file_probe_path.write_text(json.dumps(file_probe),encoding="utf-8"); file_probe_path.chmod(0o600)
            file_api=file_root/"api"
            file_api_args=type("Args",(),{"fixture":None,"rehome_host":host,"cloud":"cloud","clouds_file":Path("/clouds.yaml"),"container":"toolbox","side":"source","information_schema":schema,"root_manifest":file_roots,"probe_config":file_probe_path,"capability_config":None,"phase_key_file":None,"phase_key_env":"LIVE_DISCOVERY_PHASE_KEY","out":file_api})()
            _api_phase(file_api_args)
            file_plan=json.loads((file_api/"db-query-plan.json").read_text())["queries"]
            file_db=file_root/"db"; write_db(file_plan,file_db,"source")
            file_entries=[{"evidence_id":f"cinder-source-file-{attachment_id}","volume_id":ids["volume"],"attachment_id":attachment_id,"backend_kind":"file","backend_id":"rbd-backend","resource_identity":file_path,"connector":{"host":host,"attachment_id":attachment_id,"volume_id":ids["volume"]},"connection_info":{"driver_volume_type":"file","data":{"path":file_path}}} for attachment_id in (ids["attachment"],ids["attachment2"])]
            file_sensitive=file_root/"cinder-sensitive.json"; file_sensitive.write_text(json.dumps({"schema_version":"openstack-rehome-cinder-sensitive-evidence/v1alpha1","side":"source","entries":file_entries}),encoding="utf-8"); file_sensitive.chmod(0o600)
            file_out=file_root/"combined"
            file_combine=type("Args",(),{"api_result":file_api/"api-result.json","side":"source","fixture_phase":False,"phase_key_file":None,"phase_key_env":"LIVE_DISCOVERY_PHASE_KEY","cinder_sensitive_evidence":file_sensitive,"db_jsonl_dir":file_db,"information_schema":schema,"schema_policy":policy,"out":file_out})()
            control._combine_phase(file_combine)
            file_bundle=json.loads((file_out/"control-result.json").read_text())
            file_cinder=next(item for item in file_bundle["collectors"] if item["service"]=="cinder")
            self.assertEqual([],file_cinder["blockers"]); self.assertEqual([],file_cinder["unknowns"])
            file_attachments=[item for item in file_cinder["nodes"] if item["kind"]=="volume_attachment"]
            self.assertTrue(file_attachments and all(item["facts"]["connection_summary"]["driver_type"]=="nfs" for item in file_attachments))
            self.assertTrue(any(item["check_id"].startswith("cinder.storage.") and item["status"]=="PASS" for item in file_cinder["checks"]))
    def test_task7_and_task8_probe_results_are_typed_and_handed_to_collectors(self):
        volume_id = "22222222-2222-2222-2222-222222222222"
        image_id = "44444444-4444-4444-4444-444444444444"
        api_result = {
            "openstack": [],
            "glance_store_capabilities": [{"store_id": "store-1", "backend_type": "rbd"}],
            "glance_catalog_origin":"https://glance.example",
            "image_store_ids":{image_id:["store-1"]},
            "glance_data_probe_results": [{"image_id": image_id, "endpoint_origin":"https://glance.example","expected_size":1,"observed_size":1,"required":True,"store_ids":["store-1"],"evidence_id":f"glance-range:{image_id}","status": "PASS", "reason": "Glance image data byte is readable",**_probe_metadata("source","glance",f"glance-range:{image_id}")}],
            "storage_probe_results": [
                {"volume_id": volume_id, "scope": "source-compute", "kind": "nfs", "backend_identity":"rbd-backend","resource_identity":"/srv/volume","expected_size":1073741824,"observed_size":1073741824,"evidence_id":"storage:nfs", "status": "PASS", "reason": "backing object is readable with expected size"},
                {"volume_id": volume_id, "scope": "target-storage", "kind": "rbd", "backend_identity":"rbd-backend","resource_identity":"volumes/volume","expected_size":1073741824,"observed_size":1073741824,"evidence_id":"storage:rbd", "status": "PASS", "reason": "backing object is readable with expected size"},
                {"volume_id": volume_id, "scope": "target-storage", "kind": "lvm", "backend_identity":"rbd-backend","resource_identity":"cinder/volume","expected_size":1073741824,"observed_size":1073741824,"evidence_id":"storage:lvm", "status": "PASS", "reason": "backing object is readable with expected size"},
                {"volume_id": volume_id, "scope": "target-storage", "kind": "vendor-san", "backend_identity":"rbd-backend","resource_identity":"vendor","expected_size":1073741824,"observed_size":None,"evidence_id":"storage:vendor", "status": "UNKNOWN", "reason": "storage driver is unsupported"},
            ],
        }
        for item in api_result["storage_probe_results"]:
            item["resource_fingerprint"] = hashlib.sha256(f"{item['kind']}:{item['resource_identity']}".encode()).hexdigest()
            item.update(_probe_metadata("source", "storage", item["evidence_id"]))
        client = _CombinedClient("source", api_result, [], [])
        capabilities, evidence = client.glance_store_capabilities("glance-source-store-capabilities")
        self.assertEqual("rbd", capabilities[0]["backend_type"])
        self.assertEqual("glance-source-stores-info", evidence["evidence_id"])
        self.assertEqual("PASS", client.probe_image_data(image_id, 1, True).status)
        cinder = CollectorResult(service="cinder", side="source", nodes=[ResourceNode("volume", volume_id, "source", {"size":1,"storage_backend_id":"rbd-backend","backend_kind":"nfs","resource_identity":"/srv/volume","resource_fingerprint":hashlib.sha256(b"nfs:/srv/volume").hexdigest(),"connection_evidence_ids":["connection-1"]})])
        _integrate_storage_readiness(cinder, [volume_id], api_result)
        self.assertTrue(all(any(f".{kind}." in check.check_id for check in cinder.checks) for kind in {"nfs", "rbd", "lvm", "vendor-san"}))
        self.assertIn("backing object probe is not bound to Cinder size and backend", cinder.blockers)

    def test_image_pass_cannot_be_reused_for_different_size_or_requirement(self):
        image_id = "44444444-4444-4444-4444-444444444444"
        result = {"image_id":image_id,"endpoint_origin":"https://glance.example","expected_size":1,"observed_size":1,"required":True,"store_ids":["store-1"],"evidence_id":f"glance-range:{image_id}","status":"PASS","reason":"ok",**_probe_metadata("source","glance",f"glance-range:{image_id}")}
        client = _CombinedClient("source", {"openstack":[],"glance_catalog_origin":"https://glance.example","image_store_ids":{image_id:["store-1"]},"glance_store_capabilities":[{"store_id":"store-1","backend_type":"rbd"}],"glance_data_probe_results":[result]}, [], [])
        self.assertEqual("PASS", client.probe_image_data(image_id, 1, True).status)
        self.assertEqual("UNKNOWN", client.probe_image_data(image_id, 2, True).status)
        self.assertEqual("UNKNOWN", client.probe_image_data(image_id, 1, False).status)

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
                {"volume_id":volume_id,"scope":"source-compute","kind":"file","backend_id":"rbd-backend","resource":{"path":"/srv/cinder/volume-1","allowed_roots":["/srv/cinder"],"expected_size":1}},
                {"volume_id":volume_id,"scope":"target-storage","kind":"rbd","backend_id":"rbd-backend","resource":{"pool":"volumes","allowed_pools":["volumes"],"image":"volume-1","expected_size":1}},
                {"volume_id":volume_id,"scope":"target-storage","kind":"lvm","backend_id":"rbd-backend","resource":{"vg":"cinder-volumes","allowed_vgs":["cinder-volumes"],"lv":"volume-1","expected_size":1}},
                {"volume_id":volume_id,"scope":"target-storage","kind":"vendor-san","backend_id":"rbd-backend","resource":{"expected_size":1}}
            ],
            "glance": {"endpoint_url":"https://glance.example","token_file":"/secure/token","images":[{"image_id":image_id,"expected_size":1,"required":True,"store_ids":["store-1"]}],"store_capabilities":[{"store_id":"store-1","backend_type":"rbd"}]}
        }
        opener = Opener()
        results = _execute_probe_config(config, Runner(), opener=opener, token_loader=lambda path: "ephemeral-token-value", catalog_origin="https://glance.example", image_store_ids={image_id:["store-1"]})
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

    def test_realistic_source_target_fixtures_have_canonical_cross_service_closure(self):
        source=json.loads((FIXTURES/"ready/source-control.json").read_text())
        target=json.loads((FIXTURES/"ready/target-control.json").read_text())
        expected_source={"instance","port","network","volume","volume_attachment","storage_backend","image","image_member","glance_store"}
        source_nodes=[node for collector in source["collectors"] for node in collector["nodes"]]
        target_nodes=[node for collector in target["collectors"] for node in collector["nodes"]]
        self.assertTrue(expected_source.issubset({node["kind"] for node in source_nodes}))
        self.assertTrue({"port","network","volume","volume_attachment","storage_backend","image","image_member","glance_store"}.issubset({node["kind"] for node in target_nodes}))
        canonical_kinds={"instance","port","network","volume","image"}
        for node in [*source_nodes,*target_nodes]:
            if node["kind"] in canonical_kinds:
                self.assertEqual(node["id"],str(__import__("uuid").UUID(node["id"])))
        required_edges=[edge for bundle in (source,target) for collector in bundle["collectors"] for edge in collector["edges"] if edge["required"]]
        self.assertTrue(any(edge["source"].startswith("instance:") and edge["target"].startswith("port:") for edge in required_edges))
        self.assertTrue(any(edge["source"].startswith("instance:") and edge["target"].startswith("volume:") for edge in required_edges))
        self.assertTrue(any(edge["source"].startswith("volume:") and edge["target"].startswith("storage_backend:") for edge in required_edges))
        self.assertTrue(any(edge["source"].startswith("volume:") and edge["target"].startswith("volume_attachment:") for edge in required_edges))
        self.assertTrue(any(edge["source"].startswith("image:") and edge["target"].startswith("glance_store:") for edge in required_edges))
        self.assertTrue(any(edge["source"].startswith("image:") and edge["target"].startswith("image_member:") for edge in required_edges))
        self.assertTrue(source["evidence_index"] and target["evidence_index"])

    def test_assembler_rejects_missing_or_wrong_service_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("source-control.json", "target-control.json", "runtime.json"):
                (root / name).write_text((FIXTURES / "ready" / name).read_text(), encoding="utf-8")
            source = json.loads((root / "source-control.json").read_text())
            source["evidence_index"] = []
            (root / "source-control.json").write_text(json.dumps(source), encoding="utf-8")
            proc = subprocess.run([sys.executable,"scripts/assemble_live_discovery.py","--source-control",str(root/"source-control.json"),"--target-control",str(root/"target-control.json"),"--runtime",str(root/"runtime.json"),"--schema-policy",str(FIXTURES/"schema-policy.json"),"--out-dir",str(root/"out")],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
            self.assertEqual(3, proc.returncode)
            self.assertFalse((root / "out").exists())

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
            combine = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "combine", "--fixture-phase", "--side", "source", "--api-result", str(api / "api-result.json"), "--db-jsonl-dir", str(db), "--information-schema", str(FIXTURES / "control-information-schema.tsv"), "--schema-policy", str(FIXTURES / "schema-policy.json"), "--out", str(root / "combined")], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
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

    def test_fixture_rejects_probe_capability_root_and_phase_key_inputs(self):
        for option in ("--probe-config", "--capability-config", "--root-manifest", "--phase-key-file", "--phase-key-env"):
            with self.subTest(option=option), tempfile.TemporaryDirectory() as temporary:
                proc = subprocess.run([sys.executable,"scripts/collect_live_control.py","--phase","api","--side","source","--fixture",str(FIXTURES/"api-input.json"),option,"UNTRUSTED_VALUE","--out",str(Path(temporary)/"out")],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
                self.assertEqual(3, proc.returncode)

    def test_coordinated_plain_hash_substitution_cannot_replace_hmac(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            api_dir = root / "api"
            create = subprocess.run([sys.executable,"scripts/collect_live_control.py","--phase","api","--side","source","--fixture",str(FIXTURES/"api-input.json"),"--out",str(api_dir)],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
            self.assertEqual(0, create.returncode, create.stderr)
            names = ("api-result.json","uuid-filters.json","db-query-plan.json")
            documents = [json.loads((api_dir/name).read_text()) for name in names]
            documents[0]["api_result"]["rehome_host"] = "coordinated-substitution"
            bases = [{key:value for key,value in document.items() if key != "binding_sha256"} for document in documents]
            plain = hashlib.sha256(json.dumps({"api_result":bases[0],"uuid_filters":bases[1],"db_query_plan":bases[2]},ensure_ascii=True,sort_keys=True,separators=(",",":")).encode()).hexdigest()
            for name, document in zip(names, documents):
                document["binding_sha256"] = plain
                (api_dir/name).write_text(json.dumps(document),encoding="utf-8")
            db = root / "db"
            db.mkdir()
            proc = subprocess.run([sys.executable,"scripts/collect_live_control.py","--phase","combine","--fixture-phase","--side","source","--api-result",str(api_dir/"api-result.json"),"--db-jsonl-dir",str(db),"--information-schema",str(FIXTURES/"control-information-schema.tsv"),"--schema-policy",str(FIXTURES/"schema-policy.json"),"--out",str(root/"combined")],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
            self.assertEqual(3, proc.returncode)

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
            _write_db_evidence(db, query)
            combine = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "combine", "--fixture-phase", "--side", "source", "--api-result", str(api / "api-result.json"), "--db-jsonl-dir", str(db), "--information-schema", str(FIXTURES / "control-information-schema.tsv"), "--schema-policy", str(FIXTURES / "schema-policy.json"), "--out", str(root / "combined")], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
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
                    _write_db_evidence(db, query)
                combine = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "combine", "--fixture-phase", "--side", "source", "--api-result", str(api_dir / "api-result.json"), "--db-jsonl-dir", str(db), "--information-schema", str(ROOT / "tests/fixtures/live_discovery/full-run/control-information-schema.tsv"), "--schema-policy", str(FIXTURES / "schema-policy.json"), "--out", str(root / "combined")], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
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
                _write_db_evidence(db, query)
                combine = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "combine", "--fixture-phase", "--side", "source", "--api-result", str(api / "api-result.json"), "--db-jsonl-dir", str(db), "--information-schema", str(ROOT / "tests/fixtures/live_discovery/full-run/control-information-schema.tsv"), "--schema-policy", str(FIXTURES / "schema-policy.json"), "--out", str(root / "combined")], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
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
            _write_db_evidence(db, query)
            (db / "unplanned.jsonl").write_text("{}\n", encoding="utf-8")
            combine = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "combine", "--fixture-phase", "--side", "source", "--api-result", str(api / "api-result.json"), "--db-jsonl-dir", str(db), "--information-schema", str(ROOT / "tests/fixtures/live_discovery/full-run/control-information-schema.tsv"), "--schema-policy", str(FIXTURES / "schema-policy.json"), "--out", str(root / "combined")], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
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
                _write_db_evidence(db, query)
            out = root / "combined"
            combine = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "combine", "--fixture-phase", "--side", "source", "--api-result", str(api / "api-result.json"), "--db-jsonl-dir", str(db), "--information-schema", str(ROOT / "tests/fixtures/live_discovery/full-run/control-information-schema.tsv"), "--schema-policy", str(FIXTURES / "schema-policy.json"), "--out", str(out)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(0, combine.returncode, combine.stderr)
            bundle = json.loads((out / "control-result.json").read_text())
            self.assertEqual("openstack-rehome-control-bundle/v1alpha1", bundle["schema_version"])
            self.assertTrue(bundle["collectors"])
            self.assertEqual([], bundle["checks"], "source live-like fixture must have zero API cache misses")
            self.assertFalse(any("cached" in reason for collector in bundle["collectors"] for reason in [*collector["unknowns"],*collector["blockers"]]))
            missing_fixture=json.loads((FIXTURES/"api-input.json").read_text())
            missing_fixture["api_result"]["openstack"]=missing_fixture["api_result"]["openstack"][1:]
            missing_path=root/"missing-fixture.json"
            missing_path.write_text(json.dumps(missing_fixture),encoding="utf-8")
            missing_api=root/"missing-api"
            recreate=subprocess.run([sys.executable,"scripts/collect_live_control.py","--phase","api","--side","source","--fixture",str(missing_path),"--out",str(missing_api)],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
            self.assertEqual(0,recreate.returncode,recreate.stderr)
            missing_out=root/"missing-combined"
            missing_combine=subprocess.run([sys.executable,"scripts/collect_live_control.py","--phase","combine","--fixture-phase","--side","source","--api-result",str(missing_api/"api-result.json"),"--db-jsonl-dir",str(db),"--information-schema",str(ROOT/"tests/fixtures/live_discovery/full-run/control-information-schema.tsv"),"--schema-policy",str(FIXTURES/"schema-policy.json"),"--out",str(missing_out)],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
            self.assertEqual(0,missing_combine.returncode,missing_combine.stderr)
            missing_bundle=json.loads((missing_out/"control-result.json").read_text())
            self.assertEqual("UNKNOWN",missing_bundle["checks"][0]["status"])
            self.assertEqual({"source", "target"}, set(bundle["uuid_filters"]))

    def test_combine_preserves_failed_query_and_rejects_malformed_or_mismatched_output(self):
        for mode in ("nonzero", "malformed", "provenance"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                api = root / "api"
                create = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "api", "--side", "source", "--fixture", str(FIXTURES / "api-input.json"), "--out", str(api)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                self.assertEqual(0, create.returncode, create.stderr)
                queries = json.loads((api / "db-query-plan.json").read_text())["queries"]
                query = queries[0]
                db = root / "db"
                db.mkdir()
                for index, current in enumerate(queries):
                    returncode = 7 if mode == "nonzero" and index == 0 else 0
                    (db / current["rc_file"]).write_text(
                        f"{returncode}\n", encoding="ascii"
                    )
                    row = {column: None for column in current["columns"]}
                    filter_column, values = next(iter(current["filters"].items()))
                    row[filter_column] = values[0]
                    record = {
                        "_schema": (
                            "wrong" if mode == "provenance" and index == 0
                            else current["schema"]
                        ),
                        "_table": current["table"],
                        "row": row,
                    }
                    output = (
                        "not-json\n" if mode == "malformed" and index == 0
                        else json.dumps(record) + "\n"
                    )
                    (db / current["jsonl_file"]).write_text(
                        output, encoding="utf-8"
                    )
                    _write_db_evidence(
                        db, current, returncode=returncode,
                        stderr="database unavailable" if returncode else "",
                    )
                out = root / "combined"
                combine = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "combine", "--fixture-phase", "--side", "source", "--api-result", str(api / "api-result.json"), "--db-jsonl-dir", str(db), "--information-schema", str(ROOT / "tests/fixtures/live_discovery/full-run/control-information-schema.tsv"), "--schema-policy", str(FIXTURES / "schema-policy.json"), "--out", str(out)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                if mode == "nonzero":
                    self.assertEqual(0, combine.returncode, combine.stderr)
                    bundle = json.loads((out / "control-result.json").read_text())
                    failed = next(
                        item for item in bundle["evidence_index"]
                        if item["evidence_id"] == f"source-db:{query['query_id']}"
                    )
                    self.assertEqual(7, failed["returncode"])
                    self.assertEqual("command-failed", failed["failure_class"])
                    self.assertEqual(
                        hashlib.sha256(b"database unavailable").hexdigest(),
                        failed["stderr_sha256"],
                    )
                    self.assertTrue(any(
                        check["status"] == "BLOCKED"
                        and failed["evidence_id"] in check["evidence_ids"]
                        for check in bundle["checks"]
                    ))
                else:
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
            metadata = {
                "tables": {"nova.instances": {"id": column}},
                "indexes": {"nova.instances": {"PRIMARY": {"name": "PRIMARY", "unique": True, "columns": ["id"], "index_type": "BTREE"}}},
                "foreign_keys": {},
                "used_columns": {"nova.instances": ["id"]},
            }
            source["schema_capabilities"]["source-information-schema"] = metadata
            target["schema_capabilities"]["target-information-schema"] = metadata
            (root / "source.json").write_text(json.dumps(source), encoding="utf-8")
            (root / "target.json").write_text(json.dumps(target), encoding="utf-8")
            (root / "runtime.json").write_text((FIXTURES / "ready/runtime.json").read_text(), encoding="utf-8")
            out = root / "out"
            proc = subprocess.run([sys.executable, "scripts/assemble_live_discovery.py", "--source-control", str(root / "source.json"), "--target-control", str(root / "target.json"), "--runtime", str(root / "runtime.json"), "--schema-policy", str(ROOT / "inventory/live-discovery-schema-policy.json"), "--out-dir", str(out)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(0, proc.returncode, proc.stderr)
            mapping = json.loads((out / "schema-mapping.json").read_text())
            self.assertEqual("openstack-rehome-directional-schema-mapping/v1alpha1", mapping["schema_version"])
            self.assertEqual("COMMON_COMPATIBLE", mapping["tables"]["nova.instances"][0]["classification"])
            rendered_capabilities = json.loads((out / "schema-capabilities.json").read_text())
            self.assertEqual(
                metadata["indexes"],
                rendered_capabilities["services"]["source-information-schema"]["indexes"],
            )

    def test_live_assembler_rejects_prebuilt_directional_mapping_bypass(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = FIXTURES / "ready/source-control.json"
            target = FIXTURES / "ready/target-control.json"
            runtime = FIXTURES / "ready/runtime.json"
            prebuilt = FIXTURES / "schema-policy.json"
            self.assertEqual(
                "openstack-rehome-directional-schema-mapping/v1alpha1",
                json.loads(prebuilt.read_text())["schema_version"],
            )

            process = subprocess.run(
                [
                    sys.executable,
                    "scripts/assemble_live_discovery.py",
                    "--source-control", str(source),
                    "--target-control", str(target),
                    "--runtime", str(runtime),
                    "--schema-policy", str(prebuilt),
                    "--out-dir", str(root / "out"),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(3, process.returncode)
            self.assertFalse((root / "out" / "schema-mapping.json").exists())

    def test_live_assembler_rejects_malformed_directional_constraint_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = json.loads((FIXTURES / "ready/source-control.json").read_text())
            target = json.loads((FIXTURES / "ready/target-control.json").read_text())
            column = {"name": "id", "ordinal": 1, "column_type": "varchar(36)", "nullable": False, "default": None, "extra": ""}
            metadata = {
                "tables": {"nova.instances": {"id": column}},
                "indexes": {"nova.instances": {"PRIMARY": {"name": "PRIMARY", "unique": True, "columns": ["missing"], "index_type": "BTREE"}}},
                "foreign_keys": {},
                "used_columns": {"nova.instances": ["id"]},
            }
            source["schema_capabilities"]["source-information-schema"] = metadata
            target["schema_capabilities"]["target-information-schema"] = metadata
            (root / "source.json").write_text(json.dumps(source), encoding="utf-8")
            (root / "target.json").write_text(json.dumps(target), encoding="utf-8")
            (root / "runtime.json").write_text((FIXTURES / "ready/runtime.json").read_text(), encoding="utf-8")

            proc = subprocess.run(
                [sys.executable, "scripts/assemble_live_discovery.py", "--source-control", str(root / "source.json"), "--target-control", str(root / "target.json"), "--runtime", str(root / "runtime.json"), "--schema-policy", str(ROOT / "inventory/live-discovery-schema-policy.json"), "--out-dir", str(root / "out")],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(3, proc.returncode)
            self.assertFalse((root / "out").exists())

    def test_live_assembler_rejects_raw_runtime_without_real_typed_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "source.json").write_text((FIXTURES / "ready/source-control.json").read_text(), encoding="utf-8")
            (root / "target.json").write_text((FIXTURES / "ready/target-control.json").read_text(), encoding="utf-8")
            runtime = {"schema_version":"openstack-rehome-live-discovery/v1alpha1","service":"runtime","side":"source","nodes":[{"kind":"runtime_evidence","id":"source-runtime-raw","side":"source","facts":{},"evidence_ids":[],"key":"runtime_evidence:source-runtime-raw"}],"edges":[],"checks":[],"unknowns":[],"blockers":[],"evidence":[]}
            (root / "runtime.json").write_text(json.dumps(runtime), encoding="utf-8")
            out = root / "out"
            proc = subprocess.run([sys.executable, "scripts/assemble_live_discovery.py", "--source-control", str(root / "source.json"), "--target-control", str(root / "target.json"), "--runtime", str(root / "runtime.json"), "--schema-policy", str(FIXTURES / "schema-policy.json"), "--out-dir", str(out)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(3, proc.returncode)
            self.assertFalse((out / "resource-graph.json").exists())

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
