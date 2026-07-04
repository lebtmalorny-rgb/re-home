import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / "playbooks" / "12-reconcile-target-host-containers.yml"
TASKS = ROOT / "playbooks" / "tasks" / "reconcile-target-host-container.yml"
HELPER = ROOT / "scripts" / "recreate_docker_container_with_image.py"
RUNTIME_GUARD = ROOT / "playbooks" / "tasks" / "runtime-guard.yml"
INVENTORY = ROOT / "inventory" / "lab-os1-to-os2.yml"
LOGIC_DOC = ROOT / "playbook-logic-ru.md"
RUNBOOK_DOC = ROOT / "lab-rehome-runbook-ru.md"
INVESTIGATION_DOC = ROOT / "nova-ovs-rehome-investigation-ru.md"


class ReconcileTargetHostContainersPlaybookTests(unittest.TestCase):
    def test_playbook_is_report_only_by_default_and_apply_gated(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("target_host_container_reconcile_apply: false", text)
        self.assertIn("target_host_container_reconcile_apply | bool", text)
        self.assertIn("deployment_driver == 'kolla'", text)
        self.assertIn("container_runtime_cli == 'docker'", text)
        self.assertIn("target_host_container_reconcile_report", text)

    def test_default_scope_excludes_libvirt_and_ovs_unless_explicitly_enabled(self):
        text = PLAYBOOK.read_text(encoding="utf-8")
        inventory = INVENTORY.read_text(encoding="utf-8")

        self.assertIn("target_host_container_reconcile_include_libvirt: false", text)
        self.assertIn("target_host_container_reconcile_include_ovs: false", text)
        self.assertIn("target_host_container_reconcile_default_containers", inventory)
        self.assertIn("- fluentd", inventory)
        self.assertIn("- cron", inventory)
        self.assertIn("- kolla_toolbox", inventory)
        self.assertIn("- nova_ssh", inventory)
        self.assertIn("target_host_container_reconcile_libvirt_containers", inventory)
        self.assertIn("- nova_libvirt", inventory)
        self.assertIn("target_host_container_reconcile_ovs_containers", inventory)
        self.assertIn("- openvswitch_db", inventory)
        self.assertIn("- openvswitch_vswitchd", inventory)

    def test_inventory_defines_target_images_for_remaining_target_host_containers(self):
        inventory = INVENTORY.read_text(encoding="utf-8")

        self.assertIn("target_host_container_reconcile_images:", inventory)
        self.assertIn("fluentd: quay.io/openstack.kolla/fluentd:2025.1-ubuntu-noble", inventory)
        self.assertIn("cron: quay.io/openstack.kolla/cron:2025.1-ubuntu-noble", inventory)
        self.assertIn("kolla_toolbox: quay.io/openstack.kolla/kolla-toolbox:2025.1-ubuntu-noble", inventory)
        self.assertIn("nova_ssh: quay.io/openstack.kolla/nova-ssh:2025.1-ubuntu-noble", inventory)
        self.assertIn("nova_libvirt: quay.io/openstack.kolla/nova-libvirt:2025.1-ubuntu-noble", inventory)
        self.assertIn(
            "openvswitch_db: quay.io/openstack.kolla/openvswitch-db-server:2025.1-ubuntu-noble",
            inventory,
        )
        self.assertIn(
            "openvswitch_vswitchd: quay.io/openstack.kolla/openvswitch-vswitchd:2025.1-ubuntu-noble",
            inventory,
        )

    def test_container_task_uses_inspect_based_recreate_runtime_guard_and_rollback(self):
        playbook = PLAYBOOK.read_text(encoding="utf-8")
        text = TASKS.read_text(encoding="utf-8")
        helper = HELPER.read_text(encoding="utf-8")
        combined = playbook + text + helper

        self.assertIn("recreate_docker_container_with_image.py", combined)
        self.assertIn("target_host_container_reconcile_script_remote", text)
        self.assertIn("docker inspect", text)
        self.assertIn("runtime-guard.yml", text)
        self.assertIn("runtime_guard_mode: check", text)
        self.assertIn("rescue:", text)
        self.assertIn("ansible_failed_result.msg", text)
        self.assertIn('"rename"', combined)
        self.assertIn('"start"', combined)

    def test_container_task_can_stage_target_kolla_config_with_rollback(self):
        playbook = PLAYBOOK.read_text(encoding="utf-8")
        tasks = TASKS.read_text(encoding="utf-8")
        inventory = INVENTORY.read_text(encoding="utf-8")

        self.assertIn("target_host_container_reconcile_config_stage_dir", playbook)
        self.assertIn("target_host_container_reconcile_config_dirs", playbook)
        self.assertIn("cron: cron", playbook)
        self.assertIn("kolla_toolbox: kolla-toolbox", playbook)
        self.assertIn("nova_ssh: nova-ssh", playbook)
        self.assertIn("Target host container reconcile | check staged target Kolla config", tasks)
        self.assertIn("Target host container reconcile | backup current Kolla config", tasks)
        self.assertIn("Target host container reconcile | install staged target Kolla config", tasks)
        self.assertIn("Target host container reconcile | compare current and staged Kolla config", tasks)
        self.assertIn("Target host container reconcile | restart container after config-only change", tasks)
        self.assertIn("diff -qr", tasks)
        self.assertIn("- restart", tasks)
        self.assertIn("Target host container reconcile | restore Kolla config after failure", tasks)
        self.assertIn("target_host_container_reconcile_config_backup_path", tasks)
        self.assertIn("--env-overrides-json", tasks)
        self.assertIn("target_host_container_reconcile_env_overrides_for_container", tasks)
        self.assertIn("/etc/kolla/", tasks)
        self.assertIn("target_host_container_reconcile_config_dir", tasks)
        self.assertIn("target_host_container_reconcile_config_dirs", inventory + playbook)
        self.assertIn("target_host_container_reconcile_env_overrides", inventory + tasks)
        self.assertIn("KOLLA_BASE_DISTRO: ubuntu", inventory)

    def test_container_task_can_drop_unsafe_source_mounts_per_container(self):
        playbook = PLAYBOOK.read_text(encoding="utf-8")
        tasks = TASKS.read_text(encoding="utf-8")
        inventory = INVENTORY.read_text(encoding="utf-8")
        helper = HELPER.read_text(encoding="utf-8")

        self.assertNotIn("target_host_container_reconcile_drop_mount_destinations: {}", playbook)
        self.assertIn("target_host_container_reconcile_drop_mount_destinations_for_container", tasks)
        self.assertIn("--drop-mount-destinations-json", tasks)
        self.assertIn("drop_mount_destinations", helper)
        self.assertIn("target_host_container_reconcile_drop_mount_destinations:", inventory)
        self.assertIn("nova_ssh:", inventory)
        self.assertIn("- /var/lib/nova/mnt", inventory)

    def test_doc_has_reconcile_section(self):
        text = LOGIC_DOC.read_text(encoding="utf-8")

        self.assertIn("### `12-reconcile-target-host-containers.yml`", text)

    def test_runtime_guard_retries_domain_capture_after_libvirt_restart(self):
        guard = RUNTIME_GUARD.read_text(encoding="utf-8")
        inventory = INVENTORY.read_text(encoding="utf-8")

        self.assertIn("runtime_guard_domains_capture", guard)
        self.assertIn("runtime_guard_domain_capture_retries", guard)
        self.assertIn("until: runtime_guard_domains_capture.rc == 0", guard)
        self.assertIn("runtime_guard_domain_capture_retries: 6", inventory)
        self.assertIn("runtime_guard_domain_capture_delay: 5", inventory)

    def test_runtime_guard_uses_configurable_ovs_vsctl_command(self):
        guard = RUNTIME_GUARD.read_text(encoding="utf-8")
        inventory = INVENTORY.read_text(encoding="utf-8")

        self.assertIn("runtime_guard_ovs_ports_capture", guard)
        self.assertIn("runtime_guard_ovs_capture_retries", guard)
        self.assertIn("until: runtime_guard_ovs_ports_capture.rc == 0", guard)
        self.assertIn("runtime_guard_ovs_vsctl_command", guard)
        self.assertIn("{{ runtime_guard_ovs_vsctl_command }} br-exists", guard)
        self.assertIn("{{ runtime_guard_ovs_vsctl_command }} list-ports", guard)
        self.assertNotIn("command -v ovs-vsctl", guard)
        self.assertIn("runtime_guard_ovs_vsctl_command: docker exec openvswitch_db ovs-vsctl", inventory)
        self.assertIn("runtime_guard_ovs_capture_retries: 6", inventory)
        self.assertIn("runtime_guard_ovs_capture_delay: 5", inventory)

    def test_nova_libvirt_preflight_checks_versions_and_machine_types_before_apply(self):
        playbook = PLAYBOOK.read_text(encoding="utf-8")
        tasks = TASKS.read_text(encoding="utf-8")
        inventory = INVENTORY.read_text(encoding="utf-8")
        combined = playbook + tasks + inventory

        self.assertIn("target_host_container_reconcile_nova_libvirt_image", tasks)
        self.assertIn("Nova libvirt compatibility | capture running domain machine types", tasks)
        self.assertIn("Nova libvirt compatibility | capture current libvirt and QEMU versions", tasks)
        self.assertIn("Nova libvirt compatibility | inspect target image versions and machine types", tasks)
        self.assertIn("docker run --rm --entrypoint /bin/bash", tasks)
        self.assertIn("virsh --version", tasks)
        self.assertIn("target_host_container_reconcile_nova_libvirt_qemu_paths", tasks)
        self.assertIn("-machine help", tasks)
        self.assertIn("Nova libvirt compatibility | fail if target image misses running domain machine types", tasks)
        self.assertIn("target_host_container_reconcile_allow_unsupported_libvirt_machine_types: false", playbook)
        self.assertIn("target_host_container_reconcile_allow_libvirt_version_downgrade: false", playbook)
        self.assertIn("target_host_container_reconcile_nova_libvirt_qemu_paths", inventory)
        self.assertIn("/usr/libexec/qemu-kvm", combined)
        self.assertIn("/usr/bin/qemu-system-x86_64", combined)

    def test_docs_describe_successful_nova_libvirt_machine_type_path(self):
        logic = LOGIC_DOC.read_text(encoding="utf-8")
        runbook = RUNBOOK_DOC.read_text(encoding="utf-8")
        investigation = INVESTIGATION_DOC.read_text(encoding="utf-8")
        combined = logic + runbook + investigation

        self.assertIn("Если preflight чистый", combined)
        self.assertIn("target_host_container_reconcile_apply=true", combined)
        self.assertIn("runtime guard", combined)
        self.assertIn("rollback", combined)
        self.assertIn("не часть первичного cutover", combined)


if __name__ == "__main__":
    unittest.main()
