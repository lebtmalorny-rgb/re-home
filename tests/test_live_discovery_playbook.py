import re
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - CI with only the standard library
    yaml = None


ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / "playbooks/02b-discover-live-resource-graph.yml"
SCHEMA_TASKS = ROOT / "playbooks/tasks/collect-live-schema-service.yml"
DB_TASKS = ROOT / "playbooks/tasks/collect-live-db-jsonl-service.yml"
ALL_VARS = ROOT / "group_vars/all.yml"
GENERIC_INVENTORY = ROOT / "inventory/hosts.yml"
LAB_INVENTORY = ROOT / "inventory/lab-os1-to-os2.yml"


def _top_level_play_names(text):
    return re.findall(r"(?m)^- name: (.+)$", text)


def _yaml_documents(path):
    text = path.read_text(encoding="utf-8")
    if yaml is None:
        return [{"name": name} for name in _top_level_play_names(text)]
    return yaml.safe_load(text)


def _walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


class LiveDiscoveryPlaybookTests(unittest.TestCase):
    def test_playbook_has_exactly_seven_ordered_plays(self):
        names = [play["name"] for play in _yaml_documents(PLAYBOOK)]
        self.assertEqual(len(names), 7)
        self.assertEqual(
            names,
            [
                "02B | Freeze live discovery run locally",
                "02B | Collect source control-plane evidence",
                "02B | Collect target control-plane evidence",
                "02B | Collect re-home compute runtime evidence",
                "02B | Collect target reference compute capabilities",
                "02B | Probe source and target storage read-only",
                "02B | Assemble live discovery artifacts locally",
            ],
        )

    def test_every_command_task_is_explicitly_read_only_to_ansible(self):
        for path in (PLAYBOOK, SCHEMA_TASKS, DB_TASKS):
            for mapping in _walk(_yaml_documents(path)):
                if "ansible.builtin.command" in mapping:
                    if mapping.get("name") in {
                        "Live discovery | acquire exclusive local run directory",
                        "Live discovery | acquire persistent sibling run owner lock",
                    }:
                        self.assertIs(mapping.get("changed_when"), True)
                    else:
                        self.assertIs(
                            mapping.get("changed_when"),
                            False,
                            f"command without changed_when:false in {path}: {mapping.get('name')}",
                        )
                self.assertNotIn("ansible.builtin.shell", mapping)

    def test_sensitive_inspect_outputs_are_not_logged(self):
        text = PLAYBOOK.read_text(encoding="utf-8")
        for task_name in (
            "Target live discovery | inspect service container image digests",
        ):
            start = text.index(f"- name: {task_name}")
            end = text.find("\n        - name:", start + 1)
            task = text[start : end if end != -1 else None]
            self.assertIn("no_log: true", task)
        self.assertIn("(item.stdout | from_json) | first", text)

    def test_lab_runtime_commands_are_kolla_argv(self):
        lab = LAB_INVENTORY.read_text(encoding="utf-8")
        self.assertIn(
            "live_discovery_source_virsh_argv: [docker, exec, nova_libvirt, virsh]",
            lab,
        )
        self.assertIn(
            "live_discovery_target_virsh_argv: [docker, exec, nova_libvirt, virsh]",
            lab,
        )
        self.assertIn("live_discovery_target_qemu_argv:", lab)

    def test_hosts_are_explicit_and_singletons_are_asserted(self):
        text = PLAYBOOK.read_text(encoding="utf-8")
        for host_pattern in (
            "hosts: localhost",
            "hosts: source_control",
            "hosts: target_control",
            "hosts: rehome_compute",
            "hosts: target_reference_compute",
        ):
            self.assertIn(host_pattern, text)
        self.assertNotIn("source_control[0]", text)
        self.assertNotIn("target_control[0]", text)
        self.assertIn("groups['source_control'] | length == 1", text)
        self.assertIn("groups['target_control'] | length == 1", text)
        self.assertIn("groups['target_reference_compute'] | length == 1", text)
        self.assertIn("live_discovery_frozen_source", text)
        self.assertIn("live_discovery_frozen_target", text)
        self.assertIn("hostvars[groups['source_control'][0]]", text)
        self.assertIn("hostvars[groups['target_control'][0]]", text)

    @unittest.skipUnless(shutil.which("ansible-inventory"), "ansible-inventory unavailable")
    def test_generic_and_lab_localhost_values_cannot_override_controller_freeze(self):
        for inventory in (GENERIC_INVENTORY, LAB_INVENTORY):
            with self.subTest(inventory=inventory.name), tempfile.TemporaryDirectory() as temporary:
                env = {**os.environ, "ANSIBLE_LOCAL_TEMP": temporary}
                localhost = json.loads(subprocess.check_output(
                    ["ansible-inventory", "-i", str(inventory), "--host", "localhost"],
                    text=True, env=env,
                ))
                all_data = json.loads(subprocess.check_output(
                    ["ansible-inventory", "-i", str(inventory), "--list"],
                    text=True, env=env,
                ))
                source_host = all_data["source_control"]["hosts"][0]
                source_vars = all_data["_meta"]["hostvars"][source_host]
                self.assertIn("rehome_host", localhost)
                if inventory == LAB_INVENTORY:
                    self.assertNotEqual(localhost["rehome_host"], source_vars["rehome_host"])
        self.assertIn("rehome_host: \"{{ live_discovery_frozen_source.rehome_host }}\"", PLAYBOOK.read_text(encoding="utf-8"))

    def test_live_task10_phases_and_protected_handoff_are_wired(self):
        text = PLAYBOOK.read_text(encoding="utf-8")
        for required in (
            "collect_live_control.py",
            "collect_live_runtime.py",
            "assemble_live_discovery.py",
            "--phase",
            "api",
            "combine",
            "--phase-key-file",
            "--root-manifest",
            "--capability-config",
            "--probe-config",
            "source-control.json",
            "target-control.json",
            "runtime.json",
            "target-capability-input.json",
            "source-probe-config.json",
            "target-probe-config.json",
            "live-discovery-schema-policy.json",
        ):
            self.assertIn(required, text)
        self.assertIn("verify", DB_TASKS.read_text(encoding="utf-8"))
        self.assertIn("argv_policy.py", text)
        self.assertIn("probe_plan.py", text)
        self.assertIn("--mysql-json", DB_TASKS.read_text(encoding="utf-8"))
        self.assertIn("roots derived from live source API", text)
        self.assertNotIn("source_root_manifest_file_local", text)
        self.assertNotIn("target_root_manifest_file_local", text)
        self.assertNotIn(
            '- {path: "{{ live_discovery_side_remote_dir }}/api", mode: "0750"}',
            text,
        )
        self.assertNotIn('path: "{{ live_discovery_source_probe_dir }}/api"', text)
        self.assertNotIn('path: "{{ live_discovery_target_probe_dir }}/api"', text)
        self.assertIn("verified-plan.json", DB_TASKS.read_text(encoding="utf-8"))
        self.assertIn("openstack-rehome-verified-plan/v1alpha1", DB_TASKS.read_text(encoding="utf-8"))
        self.assertIn("item.query_id is match('^[0-9]{4}-[a-z_][a-z0-9_]*-[a-z_][a-z0-9_]*$')", DB_TASKS.read_text(encoding="utf-8"))

    def test_sensitive_files_are_run_local_protected_and_cleaned_in_always(self):
        text = PLAYBOOK.read_text(encoding="utf-8")
        self.assertGreaterEqual(text.count("always:"), 4)
        self.assertGreaterEqual(text.count("state: absent"), 4)
        self.assertIn('mode: "0700"', text)
        self.assertIn('mode: "0600"', text)
        self.assertIn("no_log: true", text)
        for secret_name in (
            "phase-hmac.key",
            "clouds.yaml",
            "glance-token",
            "cinder-sensitive-evidence.json",
        ):
            self.assertIn(secret_name, text)
        self.assertNotRegex(text, r"(?i)(password|token|secret)\s*:\s*[A-Za-z0-9_-]{12,}")
        self.assertIn("live_discovery_protected_local_inputs.results[0].stat.size >= 16", text)
        self.assertIn("live_discovery_optional_protected_inputs", text)
        self.assertIn("live_discovery_source_glance_token_file_local", text)
        self.assertIn("live_discovery_target_glance_token_file_local", text)
        self.assertNotIn("live_discovery_glance_token_file_local", text)
        self.assertIn("results[3].stat.checksum != live_discovery_protected_local_inputs.results[4].stat.checksum", text)

    def test_collection_commands_are_read_only_and_preserve_failures(self):
        text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (PLAYBOOK, SCHEMA_TASKS, DB_TASKS)
        )
        for forbidden in (
            "online_data_migrations",
            "openstack server set",
            "mysql <",
            "docker stop",
            "systemctl stop",
            "nova-manage db sync",
            "neutron-db-manage upgrade",
            "cinder-manage db sync",
            "glance-manage db_sync",
        ):
            self.assertNotIn(forbidden, text)
        for required in (
            "nova-manage api_db version",
            "nova-manage db version",
            "neutron-db-manage current --verbose",
            "cinder-manage db version",
            "alembic_version",
            "inspect",
            "changed_when: false",
        ):
            self.assertIn(required, text)
        self.assertIn("failed_when: false", DB_TASKS.read_text(encoding="utf-8"))
        self.assertIn("item.rc", DB_TASKS.read_text(encoding="utf-8"))
        self.assertIn("item.stderr", DB_TASKS.read_text(encoding="utf-8"))

    def test_db_tasks_validate_generated_sql_before_mysql(self):
        text = DB_TASKS.read_text(encoding="utf-8")
        self.assertLess(text.index("--validate-sql"), text.index("live_discovery_mysql_json_argv"))
        self.assertIn("db-query-plan.json", text)
        self.assertIn(".sql", text)
        self.assertIn(".rc", text)
        self.assertIn(".stderr", text)
        self.assertIn("ansible.builtin.command", text)
        self.assertNotIn("ansible.builtin.shell", text)
        self.assertIn("live_discovery_db_service_credentials[item.schema]", text)
        self.assertIn("password_key", text)

    def test_unknown_or_blocked_assembler_exit_fails_play(self):
        text = PLAYBOOK.read_text(encoding="utf-8")
        self.assertIn("live_discovery_assemble.rc in [0]", text)
        self.assertIn("cleanup-live-run-owner.yml", text)
        self.assertIn("live_discovery_fail_on_not_ready", text)

    def test_generic_defaults_fail_closed_and_lab_is_backend_extensible(self):
        variables = ALL_VARS.read_text(encoding="utf-8")
        generic = GENERIC_INVENTORY.read_text(encoding="utf-8")
        lab = LAB_INVENTORY.read_text(encoding="utf-8")
        self.assertIn("live_discovery_storage_backends: {}", variables)
        self.assertNotIn("live_discovery_storage_backends:", generic)
        self.assertIn("live_discovery_storage_backends:", lab)
        self.assertIn("nfs:", lab)
        self.assertIn("network_backend: ovs", lab)
        self.assertIn("kind: nfs", lab)
        self.assertIn("probe_template: nfs", lab)
        self.assertIn("storage_backends | length > 0 or item.storage | length == 0", PLAYBOOK.read_text(encoding="utf-8"))
        self.assertIn("allowed_scopes", lab)
        self.assertIn("source_delegate", lab)
        self.assertIn("target_delegate", lab)
        self.assertIn("live_discovery_glance_range_probe_enabled", PLAYBOOK.read_text(encoding="utf-8"))

    def test_run_id_is_validated_before_use_in_paths(self):
        text = PLAYBOOK.read_text(encoding="utf-8")
        self.assertIn("live_discovery_frozen_run_id is match", text)
        self.assertIn("^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$", text)
        self.assertNotIn("ansible.builtin.shell", text)
        self.assertIn("%f", text)
        self.assertIn("lookup('password'", text)
        self.assertIn("Live discovery | acquire exclusive local run directory", text)

    def test_exclusive_run_guard_rejects_same_second_same_id_collision(self):
        with tempfile.TemporaryDirectory() as temporary:
            run = Path(temporary) / "20260711T120000000000Z-fixed"
            first = subprocess.run(["mkdir", "--", str(run)], check=False)
            second = subprocess.run(["mkdir", "--", str(run)], check=False, stderr=subprocess.DEVNULL)
            self.assertEqual(0, first.returncode)
            self.assertNotEqual(0, second.returncode)

    def test_sibling_owner_survives_atomic_artifact_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            owner = root / ".control" / "owners" / "fixed-run"
            owner.mkdir(parents=True)
            (owner / "run-owner.json").write_text('{"status":"running"}', encoding="utf-8")
            output = root / "fixed-run"
            output.mkdir()
            staging = root / ".fixed-run.staging"
            staging.mkdir()
            backup = root / ".fixed-run.backup"
            os.replace(output, backup)
            os.replace(staging, output)
            self.assertTrue((owner / "run-owner.json").is_file())
            second = subprocess.run(
                ["mkdir", "--", str(owner)], check=False,
                stderr=subprocess.DEVNULL,
            )
            self.assertNotEqual(0, second.returncode)

    def test_source_profile_probes_are_not_silently_discarded(self):
        text = PLAYBOOK.read_text(encoding="utf-8")
        self.assertNotIn("live_discovery_source_profile_probes", text)
        self.assertNotIn("live_discovery_source_image_inspects", text)

    def test_target_profile_is_derived_from_live_rc_bearing_records(self):
        text = PLAYBOOK.read_text(encoding="utf-8")
        self.assertNotIn('release: "2025.1"', text)
        self.assertNotIn("distribution: vanilla", text)
        self.assertIn("capability_input.py", text)
        self.assertIn("item.rc", text)
        self.assertIn("item.stderr", text)
        self.assertIn("live_discovery_target_online_migration_evidence_file_local", text)
        self.assertNotIn("online_data_migrations", text)

    def test_run_identity_enablement_and_sibling_owner_lock_are_explicit(self):
        text = PLAYBOOK.read_text(encoding="utf-8")
        self.assertIn("live_discovery_frozen_source.enabled", text)
        self.assertIn("live_discovery_frozen_target.enabled", text)
        self.assertIn("live_discovery_frozen_target.run_id", text)
        self.assertIn("live_discovery_run_owner_dir", text)
        self.assertIn("live_discovery_run_owner_token", text)
        self.assertIn("completed.json", text)
        self.assertIn("delegate_facts: true", text)
        owner_tasks = (ROOT / "playbooks/tasks/verify-live-run-owner.yml").read_text(encoding="utf-8")
        self.assertIn("live_discovery_frozen_run_id == hostvars['localhost'].live_discovery_frozen_run_id", owner_tasks)

    def test_protected_inputs_are_frozen_before_any_later_use(self):
        text = PLAYBOOK.read_text(encoding="utf-8")
        self.assertIn("live_discovery_frozen_protected_dir", text)
        self.assertIn("ansible.builtin.slurp", text)
        self.assertIn("live_discovery_frozen_protected_paths", text)
        self.assertNotIn("lookup('file', live_discovery_source_probe_config_file_local)", text)
        self.assertNotIn("lookup('file', live_discovery_target_probe_config_file_local)", text)


if __name__ == "__main__":
    unittest.main()
