import re
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
                    self.assertIs(
                        mapping.get("changed_when"),
                        False,
                        f"command without changed_when:false in {path}: {mapping.get('name')}",
                    )
                self.assertNotIn("ansible.builtin.shell", mapping)

    def test_sensitive_inspect_outputs_are_not_logged(self):
        text = PLAYBOOK.read_text(encoding="utf-8")
        for task_name in (
            "Source live discovery | inspect service container image digests",
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
        self.assertIn("roots derived from live source API", text)
        self.assertNotIn("source_root_manifest_file_local", text)
        self.assertNotIn("target_root_manifest_file_local", text)
        self.assertNotIn(
            '- {path: "{{ live_discovery_side_remote_dir }}/api", mode: "0750"}',
            text,
        )
        self.assertNotIn('path: "{{ live_discovery_source_probe_dir }}/api"', text)
        self.assertNotIn('path: "{{ live_discovery_target_probe_dir }}/api"', text)

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
        self.assertIn("failed_when: live_discovery_assemble.rc not in [0]", text)
        self.assertIn("live_discovery_fail_on_not_ready", text)

    def test_generic_defaults_fail_closed_and_lab_is_backend_extensible(self):
        variables = ALL_VARS.read_text(encoding="utf-8")
        generic = GENERIC_INVENTORY.read_text(encoding="utf-8")
        lab = LAB_INVENTORY.read_text(encoding="utf-8")
        self.assertIn('live_discovery_storage_backend_kind: ""', variables)
        self.assertIn("live_discovery_storage_backend_kinds: []", variables)
        self.assertIn('live_discovery_source_storage_probe_host: ""', variables)
        self.assertIn('live_discovery_target_storage_probe_host: ""', variables)
        self.assertIn("live_discovery_storage_backends: {}", variables)
        self.assertNotIn("live_discovery_storage_backend_kind:", generic)
        self.assertIn("live_discovery_storage_backend_kind: nfs", lab)
        self.assertIn("live_discovery_storage_backend_kinds: [nfs]", lab)
        self.assertIn("live_discovery_storage_backends:", lab)
        self.assertIn("nfs:", lab)
        self.assertIn("rbd:", variables)
        self.assertIn("lvm:", variables)
        self.assertIn("vendor:", variables)
        self.assertIn("network_backend: ovs", lab)
        self.assertIn("live_discovery_source_storage_probe_host:", lab)
        self.assertIn("live_discovery_target_storage_probe_host:", lab)
        self.assertIn("live_discovery_storage_backend_kinds | length == 0", PLAYBOOK.read_text(encoding="utf-8"))

    def test_run_id_is_validated_before_use_in_paths(self):
        text = PLAYBOOK.read_text(encoding="utf-8")
        self.assertIn("live_discovery_frozen_run_id is match", text)
        self.assertIn("^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$", text)
        self.assertNotIn("ansible.builtin.shell", text)


if __name__ == "__main__":
    unittest.main()
