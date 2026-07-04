import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / "playbooks" / "06-cutover-compute.yml"
INVENTORY = ROOT / "inventory" / "lab-os1-to-os2.yml"


class CutoverComputePlaybookTests(unittest.TestCase):
    def test_cutover_is_kolla_apply_gated_and_does_not_use_generic_systemd(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("cutover_apply: false", text)
        self.assertIn("cutover_apply | bool", text)
        self.assertIn("deployment_driver == 'kolla'", text)
        self.assertIn("source_runtime_switch_containers", text)
        self.assertIn("target_runtime_switch_containers", text)
        self.assertIn("dataplane_keep_containers", text)
        self.assertNotIn("ansible.builtin.systemd", text)
        self.assertNotIn("source_compute_units", text)
        self.assertNotIn("target_compute_units", text)
        self.assertNotIn("virsh list --name", text)
        self.assertIn("{{ runtime_guard_virsh_command }} list --name", text)

    def test_cutover_requires_staged_target_kolla_configs_and_target_images(self):
        text = PLAYBOOK.read_text(encoding="utf-8")
        inventory = INVENTORY.read_text(encoding="utf-8")

        self.assertIn("target_kolla_config_stage_dir", text)
        self.assertIn("config.json", text)
        self.assertIn("target_runtime_switch_container_images", text)
        self.assertIn("quay.io/openstack.kolla/neutron-openvswitch-agent:2025.1-ubuntu-noble", inventory)
        self.assertIn("quay.io/openstack.kolla/nova-compute:2025.1-ubuntu-noble", inventory)

    def test_cutover_has_mount_leak_preflight_guard(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("cutover_mount_leak_guard_path: /var/lib/nova/mnt", text)
        self.assertIn("cutover_mount_leak_guard_max_entries", text)
        self.assertIn("Cutover preflight | guard against leaked nova mnt mount entries", text)
        self.assertIn("/proc/1/mountinfo", text)
        self.assertIn("startswith(path)", text)
        self.assertIn("cutover_mount_leak_guard_max_entries | int", text)

    def test_cutover_stops_only_runtime_containers_and_keeps_dataplane(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("Cutover stop | stop source Kolla container systemd units", text)
        self.assertIn("systemctl stop \"$unit\"", text)
        self.assertIn("unit=\"kolla-{{ item }}-container.service\"", text)
        self.assertIn("docker stop {{ item }}", text)
        self.assertIn("docker rm -f {{ item.name }}", text)
        self.assertIn("docker run -d", text)
        self.assertIn("item.name != 'nova_compute'", text)
        self.assertIn("item.name == 'nova_compute'", text)
        self.assertNotIn("docker stop nova_libvirt", text)
        self.assertNotIn("docker stop openvswitch_db", text)
        self.assertNotIn("docker stop openvswitch_vswitchd", text)
        self.assertNotIn("docker stop iscsid", text)
        self.assertNotIn("docker stop multipathd", text)

        systemd_stop = text.index("Cutover stop | stop source Kolla container systemd units")
        docker_stop = text.index("Cutover stop | stop source runtime containers only")
        self.assertLess(systemd_stop, docker_stop)

    def test_cutover_builds_docker_run_options_without_jinja_backslash_gluing(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("cutover_docker_run_options", text)
        self.assertIn("docker run -d {{ cutover_docker_run_options | join(' ') }}", text)
        self.assertNotIn("\\{% endif %}", text)
        self.assertNotIn("\\{% endfor %}", text)

    def test_cutover_rebinds_target_ports_before_network_reachability_guard(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("cutover_rebind_ports_during_cutover", text)
        self.assertIn("target_clouds_file_local", text)
        self.assertIn("OS_CLIENT_CONFIG_FILE", text)
        self.assertIn("openstack --os-cloud {{ target_cloud_name | quote }}", text)
        self.assertIn("port set --host {{ rehome_host | quote }}", text)

        network_start = text.index("Cutover start | start target network containers before nova_compute")
        rebind = text.index("Cutover network | rebind target Neutron ports to re-home host")
        guard = text.index("Cutover guard | verify VM after target network containers started")
        self.assertLess(network_start, rebind)
        self.assertLess(rebind, guard)

    def test_cutover_accepts_current_manifest_source_instance_ports(self):
        text = PLAYBOOK.read_text(encoding="utf-8")

        self.assertIn("cutover_manifest.rehome_instances", text)
        self.assertIn("cutover_manifest.source.instances", text)
        self.assertIn("cutover_manifest_ports", text)

    def test_lab_runtime_guard_uses_lab_host_not_local_macos(self):
        inventory = INVENTORY.read_text(encoding="utf-8")

        self.assertIn("runtime_guard_probe_delegate: os2-ctrl-01", inventory)


if __name__ == "__main__":
    unittest.main()
