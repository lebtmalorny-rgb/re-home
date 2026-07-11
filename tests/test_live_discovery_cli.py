import json
import hashlib
import inspect
import os
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
from live_discovery.contract import CheckResult, CollectorResult, ResourceNode
from collect_live_control import _CombinedClient, _TABLE_ROOT_FILTERS, _api_phase, _collector_table_catalog, _execute_probe_config, _expected_plan_tables, _integrate_storage_readiness, _phase_binding, _read_protected_json, _root_filter_values
from live_discovery.cinder import CORE_TABLES as CINDER_CORE, OPTIONAL_TABLES as CINDER_OPTIONAL
from live_discovery.neutron import CORE_TABLES as NEUTRON_CORE, OPTIONAL_TABLE_FAMILIES as NEUTRON_OPTIONAL
from live_discovery.nova import DB_SCHEMAS, DB_TABLES
from live_discovery.schema import SchemaSnapshot


class LiveDiscoveryCliTests(unittest.TestCase):
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
            rejected = subprocess.run([sys.executable,"scripts/collect_live_control.py","--phase","combine","--side","source","--api-result",str(api/"api-result.json"),"--db-jsonl-dir",str(db),"--information-schema",str(FIXTURES/"control-information-schema.tsv"),"--schema-policy",str(FIXTURES/"schema-policy.json"),"--out",str(root/"out")],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
            self.assertEqual(3, rejected.returncode)
            with mock.patch.dict("os.environ",{"LIVE_PHASE_KEY":"fixture-only-phase-integrity-anchor-v1"}):
                downgraded = subprocess.run([sys.executable,"scripts/collect_live_control.py","--phase","combine","--side","source","--phase-key-env","LIVE_PHASE_KEY","--api-result",str(api/"api-result.json"),"--db-jsonl-dir",str(db),"--information-schema",str(FIXTURES/"control-information-schema.tsv"),"--schema-policy",str(FIXTURES/"schema-policy.json"),"--out",str(root/"downgraded")],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,env={**os.environ,"LIVE_PHASE_KEY":"fixture-only-phase-integrity-anchor-v1"})
            self.assertEqual(3,downgraded.returncode)

    def test_missing_capability_evidence_is_not_fabricated(self):
        collector = {"side":"target","service":"target-profile","nodes":[{"evidence_ids":["target-profile-real"]}],"checks":[]}
        with self.assertRaises(ValueError):
            control._build_evidence_index("target", [collector], {"openstack":[]}, [])

    def test_storage_pass_cannot_cross_backend_kind_or_resource(self):
        volume_id = "22222222-2222-2222-2222-222222222222"
        result = CollectorResult(service="cinder", side="source", nodes=[ResourceNode("volume",volume_id,"source",{"size":1,"storage_backend_id":"rbd-backend","backend_kind":"rbd","resource_identity":"volumes/volume-2"})])
        api = {"storage_probe_results":[{"volume_id":volume_id,"scope":"source-compute","kind":"nfs","backend_identity":"rbd-backend","resource_identity":"/srv/nfs/volume-2","expected_size":1073741824,"observed_size":1073741824,"evidence_id":"storage-cross-kind","status":"PASS","reason":"ok"}]}
        _integrate_storage_readiness(result,[volume_id],api)
        self.assertEqual("BLOCKED", result.checks[0].status)
        result2=CollectorResult(service="cinder",side="source",nodes=[ResourceNode("volume",volume_id,"source",{"size":1,"storage_backend_id":"rbd-backend","backend_kind":"rbd","resource_identity":"volumes/expected"})])
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
        payload={"schema_version":"openstack-rehome-cinder-sensitive-evidence/v1alpha1","side":"source","entries":[{"evidence_id":"cinder-sensitive-attachment","volume_id":volume_id,"attachment_id":attachment_id,"backend_kind":"rbd","backend_id":"rbd-backend","resource_identity":"volumes/volume-2","connector":{"host":"compute-023","auth_password":"connector-secret"},"connection_info":{"driver_volume_type":"rbd","secret_uuid":"connection-secret"}}]}
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/"cinder-sensitive.json"
            path.write_text(json.dumps(payload),encoding="utf-8")
            path.chmod(0o600)
            summaries,sensitive=control._load_cinder_sensitive_evidence(path,"source")
            self.assertEqual("rbd",summaries[volume_id]["backend_kind"])
            self.assertNotIn("connector-secret",json.dumps(summaries))
            self.assertIn("connector-secret",json.dumps(sensitive))
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                control._load_cinder_sensitive_evidence(path,"source")

    def test_root_manifest_is_merged_before_recursive_api_closure(self):
        ids = {name: f"{index:08d}-1111-4111-8111-{index:012d}" for index, name in enumerate((
            "instance","port","child_port","network","subnet","security_group","qos","trunk","floating","router","address_group","volume","type","attachment","snapshot","secret","image","flavor"
        ), start=1)}
        roots = {
            "instances":[ids["instance"]],"ports":[ids["port"]],"networks":[ids["network"]],"subnets":[ids["subnet"]],
            "security_groups":[ids["security_group"]],"qos_policies":[ids["qos"]],"trunks":[ids["trunk"]],"floating_ips":[ids["floating"]],
            "routers":[ids["router"]],"address_groups":[ids["address_group"]],"volumes":[ids["volume"]],"volume_types":[ids["type"]],
            "attachments":[ids["attachment"]],"snapshots":[ids["snapshot"]],"barbican_secrets":[ids["secret"]],"images":[ids["image"]],"flavors":[ids["flavor"]],
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
                    payload = {"id":ids["volume"],"volume_type_id":ids["type"],"snapshot_id":ids["snapshot"],"attachments":[{"id":ids["attachment"]}]}
                elif command[:3] == ["network","trunk","show"]:
                    payload = {"id":ids["trunk"],"sub_ports":[{"port_id":ids["child_port"]}]}
                else:
                    payload = {"id": command[-4] if len(command) > 4 else ids["instance"]}
                return payload, {"id":evidence_id}
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
        rows, proof = client.db_records("ports", {"id":[one]})
        self.assertEqual([one], [item["row"]["id"] for item in rows])
        self.assertEqual({"id":[one]}, proof["filters"])
        missing, _ = client.db_records("ports", {"id":["33333333-3333-3333-3333-333333333333"]})
        self.assertEqual([], missing)

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
                return payload, {"id": evidence_id}
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

    def test_target_live_like_all_collectors_have_zero_cache_misses_and_real_evidence(self):
        manage=json.loads((ROOT/"tests/fixtures/live_discovery/openstack-command-results.json").read_text())["manage_outputs"]
        api={"openstack":[],"roots":{"ports":[],"volumes":[],"images":[],"projects":[]},"target_manage_outputs":manage,"target_image_inspects":{},"target_runtime_outputs":{"runtime-target-virsh-version":"9.0.0","runtime-target-domcapabilities":"<domainCapabilities><devices><disk><enum name='bus'><value>virtio</value></enum></disk></devices></domainCapabilities>","runtime-target-qemu-machine-help":"Supported machines are:\npc-q35-8.2 fixture\n"},"target_virsh_argv":["virsh"],"target_qemu_argv":["qemu-system-x86_64"],"capability_evidence":[{"evidence_id":"nova-online-data-migrations","kind":"runtime-command","side":"target","service":"target-profile","command":["nova-manage","db","online_data_migrations"]},{"evidence_id":"cinder-online-data-migrations","kind":"runtime-command","side":"target","service":"target-profile","command":["cinder-manage","db","online_data_migrations"]}]}
        collectors,misses=control._compose_collectors("target",api,[],[],SchemaSnapshot(tables={}))
        self.assertEqual([],misses)
        self.assertEqual({"target-profile","runtime-capabilities","neutron","cinder","glance"},{item["service"] for item in collectors})
        index=control._build_evidence_index("target",collectors,api,[])
        identities={item["evidence_id"] for item in index}
        self.assertIn("runtime-target-virsh-version",identities)
        self.assertIn("nova-online-data-migrations",identities)
    def test_task7_and_task8_probe_results_are_typed_and_handed_to_collectors(self):
        volume_id = "22222222-2222-2222-2222-222222222222"
        image_id = "44444444-4444-4444-4444-444444444444"
        api_result = {
            "openstack": [],
            "glance_store_capabilities": [{"store_id": "store-1", "backend_type": "rbd"}],
            "glance_catalog_origin":"https://glance.example",
            "image_store_ids":{image_id:["store-1"]},
            "glance_data_probe_results": [{"image_id": image_id, "endpoint_origin":"https://glance.example","expected_size":1,"observed_size":1,"required":True,"store_ids":["store-1"],"evidence_id":f"glance-range:{image_id}","status": "PASS", "reason": "Glance image data byte is readable"}],
            "storage_probe_results": [
                {"volume_id": volume_id, "scope": "source-compute", "kind": "nfs", "backend_identity":"rbd-backend","resource_identity":"/srv/volume","expected_size":1073741824,"observed_size":1073741824,"evidence_id":"storage:nfs", "status": "PASS", "reason": "backing object is readable with expected size"},
                {"volume_id": volume_id, "scope": "target-storage", "kind": "rbd", "backend_identity":"rbd-backend","resource_identity":"volumes/volume","expected_size":1073741824,"observed_size":1073741824,"evidence_id":"storage:rbd", "status": "PASS", "reason": "backing object is readable with expected size"},
                {"volume_id": volume_id, "scope": "target-storage", "kind": "lvm", "backend_identity":"rbd-backend","resource_identity":"cinder/volume","expected_size":1073741824,"observed_size":1073741824,"evidence_id":"storage:lvm", "status": "PASS", "reason": "backing object is readable with expected size"},
                {"volume_id": volume_id, "scope": "target-storage", "kind": "vendor-san", "backend_identity":"rbd-backend","resource_identity":"vendor","expected_size":1073741824,"observed_size":None,"evidence_id":"storage:vendor", "status": "UNKNOWN", "reason": "storage driver is unsupported"},
            ],
        }
        client = _CombinedClient("source", api_result, [], [])
        capabilities, evidence = client.glance_store_capabilities("glance-source-store-capabilities")
        self.assertEqual("rbd", capabilities[0]["backend_type"])
        self.assertEqual("glance-source-store-capabilities", evidence["evidence_id"])
        self.assertEqual("PASS", client.probe_image_data(image_id, 1, True).status)
        cinder = CollectorResult(service="cinder", side="source", nodes=[ResourceNode("volume", volume_id, "source", {"size":1,"storage_backend_id":"rbd-backend","backend_kind":"nfs","resource_identity":"/srv/volume"})])
        _integrate_storage_readiness(cinder, [volume_id], api_result)
        self.assertTrue(all(any(f".{kind}." in check.check_id for check in cinder.checks) for kind in {"nfs", "rbd", "lvm", "vendor-san"}))
        self.assertIn("backing object probe is not bound to Cinder size and backend", cinder.blockers)

    def test_image_pass_cannot_be_reused_for_different_size_or_requirement(self):
        image_id = "44444444-4444-4444-4444-444444444444"
        result = {"image_id":image_id,"endpoint_origin":"https://glance.example","expected_size":1,"observed_size":1,"required":True,"store_ids":["store-1"],"evidence_id":f"glance-range:{image_id}","status":"PASS","reason":"ok"}
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
                combine = subprocess.run([sys.executable, "scripts/collect_live_control.py", "--phase", "combine", "--fixture-phase", "--side", "source", "--api-result", str(api / "api-result.json"), "--db-jsonl-dir", str(db), "--information-schema", str(ROOT / "tests/fixtures/live_discovery/full-run/control-information-schema.tsv"), "--schema-policy", str(FIXTURES / "schema-policy.json"), "--out", str(root / "combined")], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
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
