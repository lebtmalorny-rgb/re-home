from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
FIXTURES = ROOT / "tests" / "fixtures" / "live_discovery"

from live_discovery.contract import CollectorResult, DependencyEdge, ResourceNode
from live_discovery.runtime import (
    FixtureRuntimeRunner,
    collect_runtime,
    collect_target_capabilities,
    compare_disk_buses,
    compare_machine_types,
    compare_runtime_to_nova,
)


def collect_from_fixture(fixture):
    return collect_runtime(
        FixtureRuntimeRunner(fixture),
        fixture.get("virsh_argv", ["virsh"]),
        fixture.get("network_backend", "ovs"),
    )


class RuntimeCollectorTests(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads(
            (FIXTURES / "runtime-source.json").read_text(encoding="utf-8")
        )

    def test_runtime_maps_domain_disk_and_interface_to_openstack_ids(self):
        result = collect_from_fixture(self.fixture)

        edge_pairs = {(edge.source, edge.target) for edge in result.edges}
        self.assertIn(
            ("libvirt_domain:instance-0000002a", "volume:volume-1"),
            edge_pairs,
        )
        self.assertIn(
            ("runtime_interface:tap-port-1", "port:port-1"),
            edge_pairs,
        )

    def test_unmapped_running_disk_is_blocker(self):
        fixture = deepcopy(self.fixture)
        fixture["domains"][0]["disks"].append(
            {"target": "vdb", "source": "/unknown/disk"}
        )

        result = collect_from_fixture(fixture)

        self.assertIn(
            "unmapped runtime disk: instance-0000002a/vdb",
            result.blockers,
        )

    def test_cinder_volume_backend_name_normalizes_to_canonical_uuid(self):
        fixture = deepcopy(self.fixture)
        volume_uuid = "22222222-2222-2222-2222-222222222222"
        fixture["domains"][0]["disks"][0]["source"] = (
            f"cinder-volumes/volume-{volume_uuid}"
        )
        fixture["domains"][0]["disks"][0]["serial"] = volume_uuid

        result = collect_from_fixture(fixture)

        targets = {edge.target for edge in result.edges}
        self.assertIn(f"volume:{volume_uuid}", targets)
        self.assertNotIn(f"volume:volume-{volume_uuid}", targets)

    def test_non_uuid_volume_text_cannot_suppress_unmapped_disk_blocker(self):
        fixture = deepcopy(self.fixture)
        fixture["domains"][0]["disks"][0]["source"] = (
            "cinder-volumes/volume-not-a-canonical-uuid"
        )
        fixture["domains"][0]["disks"][0].pop("serial", None)
        runner = FixtureRuntimeRunner(fixture)
        runner.allow_fixture_aliases = False

        result = collect_runtime(runner, ["virsh"], "ovs")

        self.assertIn(
            "unmapped runtime disk: instance-0000002a/vda",
            result.blockers,
        )
        self.assertNotIn(
            "volume:volume-not-a-canonical-uuid",
            {edge.target for edge in result.edges},
        )

    def test_noncanonical_uppercase_volume_uuid_is_not_accepted(self):
        fixture = deepcopy(self.fixture)
        volume_uuid = "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"
        fixture["domains"][0]["disks"][0]["source"] = f"volume-{volume_uuid}"
        fixture["domains"][0]["disks"][0].pop("serial", None)
        runner = FixtureRuntimeRunner(fixture)
        runner.allow_fixture_aliases = False

        result = collect_runtime(runner, ["virsh"], "ovs")

        self.assertIn(
            "unmapped runtime disk: instance-0000002a/vda",
            result.blockers,
        )

    def test_truncated_tap_name_does_not_invent_port_id(self):
        fixture = deepcopy(self.fixture)
        fixture["domains"][0]["interfaces"][0]["target"] = "tap33333333-33"
        fixture["ovs_interfaces"][0]["name"] = "tap33333333-33"
        fixture["ovs_interfaces"][0]["external_ids"] = {}
        fixture["ovs_ports"][0]["name"] = "tap33333333-33"

        result = collect_from_fixture(fixture)

        self.assertIn(
            "unmapped runtime interface: instance-0000002a/tap33333333-33",
            result.blockers,
        )
        self.assertNotIn("port:33333333-33", {edge.target for edge in result.edges})

    def test_source_machine_type_missing_on_target_is_blocker(self):
        checks = compare_machine_types(
            ["pc-i440fx-rhel7.6.0"],
            ["pc-q35-9.0", "pc-i440fx-9.0"],
        )

        self.assertTrue(any(item.status == "BLOCKED" for item in checks))

    def test_dumpxml_secret_is_redacted_before_evidence_persistence(self):
        result = collect_from_fixture(self.fixture)

        serialized = json.dumps(result.to_dict())
        self.assertNotIn("libvirt-secret-value", serialized)
        self.assertNotIn("secret-uuid", serialized)
        self.assertTrue(all(set(item) == {"evidence_id","kind","side","service","command"} for item in result.evidence))

    def test_dumpxml_graphics_password_and_auth_values_are_redacted(self):
        class CredentialXmlRunner(FixtureRuntimeRunner):
            def _domain_xml(self, domain):
                xml = super()._domain_xml(domain)
                return xml.replace(
                    "</devices>",
                    '<graphics type="vnc" passwd="graphics-password" token="vnc-token"/>'
                    '<auth username="chap-user"><secret type="ceph" uuid="auth-secret"/>'
                    "chap-password</auth></devices>",
                )

        result = collect_runtime(CredentialXmlRunner(self.fixture), ["virsh"], "ovs")

        serialized = json.dumps(result.to_dict())
        for sensitive in (
            "graphics-password",
            "vnc-token",
            "chap-user",
            "auth-secret",
            "chap-password",
        ):
            self.assertNotIn(sensitive, serialized)
        self.assertTrue(all("stdout" not in item for item in result.evidence))

    def test_runtime_issues_only_prescribed_read_only_commands(self):
        runner = FixtureRuntimeRunner(self.fixture)

        collect_runtime(runner, ["virsh"], "ovs")

        self.assertEqual(
            [
                ["virsh", "list", "--uuid", "--name"],
                ["ovs-vsctl", "--format=json", "list", "Interface"],
                ["ovs-vsctl", "--format=json", "list", "Port"],
                ["virsh", "dominfo", "instance-0000002a"],
                ["virsh", "dumpxml", "instance-0000002a", "--security-info"],
                ["virsh", "domblklist", "instance-0000002a", "--details"],
                ["virsh", "domiflist", "instance-0000002a"],
            ],
            runner.commands,
        )

    def test_runtime_domain_correlates_to_nova_instance_uuid(self):
        runtime = collect_from_fixture(self.fixture)
        nova = CollectorResult(service="nova", side="source")
        nova.nodes.append(
            ResourceNode(
                "instance",
                "11111111-1111-1111-1111-111111111111",
                "source",
            )
        )
        nova.edges.extend(
            [
                DependencyEdge(
                    "instance:11111111-1111-1111-1111-111111111111",
                    "volume:volume-1",
                    "uses_volume",
                    True,
                ),
                DependencyEdge(
                    "instance:11111111-1111-1111-1111-111111111111",
                    "port:port-1",
                    "uses_port",
                    True,
                ),
            ]
        )

        checks = compare_runtime_to_nova(runtime, nova)

        self.assertEqual(3, len(checks))
        self.assertTrue(all(item.status == "PASS" for item in checks))

    def test_runtime_nova_roots_block_missing_and_extra_ports_and_volumes(self):
        instance_uuid = "11111111-1111-1111-1111-111111111111"
        domain = ResourceNode(
            "libvirt_domain",
            "instance-0000002a",
            "source",
            {"instance_uuid": instance_uuid},
        )
        runtime = CollectorResult(service="runtime", side="source", nodes=[domain])
        runtime.edges.extend(
            [
                DependencyEdge(domain.key, "runtime_disk:disk-1", "has_runtime_disk", True),
                DependencyEdge("runtime_disk:disk-1", "volume:volume-extra", "maps_to_volume", True),
                DependencyEdge(domain.key, "runtime_interface:tap-1", "has_runtime_interface", True),
                DependencyEdge("runtime_interface:tap-1", "port:port-extra", "maps_to_port", True),
            ]
        )
        nova = CollectorResult(
            service="nova",
            side="source",
            nodes=[ResourceNode("instance", instance_uuid, "source")],
            edges=[
                DependencyEdge(f"instance:{instance_uuid}", "volume:volume-missing", "uses_volume", True),
                DependencyEdge(f"instance:{instance_uuid}", "port:port-missing", "uses_port", True),
            ],
        )

        checks = compare_runtime_to_nova(runtime, nova)
        root_checks = {item.check_id: item for item in checks if "roots" in item.check_id}

        self.assertEqual("BLOCKED", root_checks[f"runtime.nova-roots.{instance_uuid}.volume"].status)
        self.assertIn("missing runtime=['volume:volume-missing']", root_checks[f"runtime.nova-roots.{instance_uuid}.volume"].reason)
        self.assertIn("extra runtime=['volume:volume-extra']", root_checks[f"runtime.nova-roots.{instance_uuid}.volume"].reason)
        self.assertEqual("BLOCKED", root_checks[f"runtime.nova-roots.{instance_uuid}.port"].status)
        self.assertIn("missing runtime=['port:port-missing']", root_checks[f"runtime.nova-roots.{instance_uuid}.port"].reason)
        self.assertIn("extra runtime=['port:port-extra']", root_checks[f"runtime.nova-roots.{instance_uuid}.port"].reason)

    def test_domain_uses_volume_does_not_replace_runtime_disk_mapping(self):
        instance_uuid = "11111111-1111-1111-1111-111111111111"
        domain = ResourceNode(
            "libvirt_domain",
            "instance-0000002a",
            "source",
            {"instance_uuid": instance_uuid},
        )
        runtime = CollectorResult(
            service="runtime",
            side="source",
            nodes=[domain],
            edges=[
                DependencyEdge(domain.key, "volume:volume-1", "uses_volume", True),
            ],
        )
        nova = CollectorResult(
            service="nova",
            side="source",
            nodes=[ResourceNode("instance", instance_uuid, "source")],
            edges=[
                DependencyEdge(
                    f"instance:{instance_uuid}",
                    "volume:volume-1",
                    "uses_volume",
                    True,
                ),
            ],
        )

        checks = compare_runtime_to_nova(runtime, nova)
        volume_check = next(item for item in checks if item.check_id.endswith(".volume"))

        self.assertEqual("BLOCKED", volume_check.status)
        self.assertIn("missing runtime=['volume:volume-1']", volume_check.reason)

    def test_runtime_domain_missing_from_nova_is_blocked(self):
        runtime = collect_from_fixture(self.fixture)
        nova = CollectorResult(service="nova", side="source")

        checks = compare_runtime_to_nova(runtime, nova)

        self.assertEqual(["BLOCKED"], [item.status for item in checks])

    def test_nova_instance_missing_runtime_domain_is_blocked(self):
        runtime = CollectorResult(service="runtime", side="source")
        nova = CollectorResult(service="nova", side="source")
        nova.nodes.append(
            ResourceNode(
                "instance",
                "11111111-1111-1111-1111-111111111111",
                "source",
            )
        )

        checks = compare_runtime_to_nova(runtime, nova)

        self.assertEqual(["BLOCKED"], [item.status for item in checks])

    def test_shutoff_nova_instance_does_not_require_running_domain(self):
        runtime = CollectorResult(service="runtime", side="source")
        nova = CollectorResult(service="nova", side="source")
        nova.nodes.append(
            ResourceNode(
                "instance",
                "11111111-1111-1111-1111-111111111111",
                "source",
                {"status": "SHUTOFF"},
            )
        )

        checks = compare_runtime_to_nova(runtime, nova)

        self.assertEqual([], checks)

    def test_malformed_successful_dataplane_output_is_blocker(self):
        class MalformedOvsRunner(FixtureRuntimeRunner):
            def _stdout(self, argv):
                if argv == ["ovs-vsctl", "--format=json", "list", "Interface"]:
                    return "not-json"
                return super()._stdout(argv)

        result = collect_runtime(MalformedOvsRunner(self.fixture), ["virsh"], "ovs")

        self.assertIn("invalid OVS Interface output", result.blockers)

    def test_malformed_successful_dataplane_row_is_blocker(self):
        class MalformedOvsRowRunner(FixtureRuntimeRunner):
            def _stdout(self, argv):
                if argv == ["ovs-vsctl", "--format=json", "list", "Interface"]:
                    return '{"headings":["name","external_ids"],"data":[["tap-only"]]}'
                return super()._stdout(argv)

        result = collect_runtime(MalformedOvsRowRunner(self.fixture), ["virsh"], "ovs")

        self.assertIn("invalid OVS Interface output", result.blockers)

    def test_blank_successful_domain_disk_output_is_blocker(self):
        class BlankDiskRunner(FixtureRuntimeRunner):
            def _stdout(self, argv):
                if len(argv) >= 3 and argv[-3] == "domblklist":
                    return ""
                return super()._stdout(argv)

        result = collect_runtime(BlankDiskRunner(self.fixture), ["virsh"], "ovs")

        self.assertIn(
            "invalid domain disk list: instance-0000002a",
            result.blockers,
        )

    def test_ovn_non_port_binding_is_not_mapped_to_neutron_port(self):
        fixture = deepcopy(self.fixture)
        fixture["network_backend"] = "ovn"
        fixture["ovn_bindings"] = [{"logical_port": "cr-lrp-router-1"}]

        result = collect_from_fixture(fixture)

        self.assertNotIn(
            "port:cr-lrp-router-1",
            {edge.target for edge in result.edges},
        )

    def test_target_device_name_maps_port_without_ovs_external_ids(self):
        fixture = deepcopy(self.fixture)
        fixture["ovs_interfaces"][0]["external_ids"] = {}

        result = collect_from_fixture(fixture)

        edge_pairs = {(edge.source, edge.target) for edge in result.edges}
        self.assertIn(
            ("runtime_interface:tap-port-1", "port:port-1"),
            edge_pairs,
        )

    def test_target_capabilities_use_probe_only_commands(self):
        fixture = deepcopy(self.fixture)
        fixture["side"] = "target"
        fixture["virsh_version"] = "Compiled against library: libvirt 11.0.0\n"
        fixture["target_machine_types"] = ["pc-i440fx-rhel7.6.0", "pc-q35-9.0"]
        fixture["target_disk_buses"] = ["virtio", "scsi"]
        runner = FixtureRuntimeRunner(fixture)

        result = collect_target_capabilities(
            runner,
            ["virsh"],
            ["qemu-system-x86_64"],
        )

        self.assertEqual([], result.blockers)
        self.assertEqual(
            [
                ["virsh", "version"],
                ["virsh", "domcapabilities"],
                ["qemu-system-x86_64", "-machine", "help"],
            ],
            runner.commands,
        )
        self.assertIn("pc-i440fx-rhel7.6.0", result.checks[0].resource_ids)
        self.assertIn("virtio", result.checks[1].resource_ids)

    def test_target_capabilities_include_non_pc_qemu_machine_types(self):
        fixture = deepcopy(self.fixture)
        fixture["side"] = "target"
        fixture["virsh_version"] = "Compiled against library: libvirt 11.0.0\n"
        fixture["target_machine_types"] = ["microvm", "virt"]
        fixture["target_disk_buses"] = ["virtio"]

        result = collect_target_capabilities(
            FixtureRuntimeRunner(fixture),
            ["virsh"],
            ["qemu-system-x86_64"],
        )

        self.assertIn("microvm", result.checks[0].resource_ids)
        self.assertIn("virt", result.checks[0].resource_ids)

    def test_source_disk_bus_missing_on_target_is_blocker(self):
        checks = compare_disk_buses(["virtio", "scsi"], ["virtio"])

        self.assertEqual(["PASS", "BLOCKED"], [item.status for item in checks])

    def test_fixture_cli_writes_contract_result(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "runtime.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "collect_live_runtime.py"),
                    "--fixture",
                    str(FIXTURES / "runtime-source.json"),
                    "--side",
                    "source",
                    "--out",
                    str(output),
                ],
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(0, completed.returncode, completed.stderr)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                "openstack-rehome-live-discovery/v1alpha1",
                payload["schema_version"],
            )
            self.assertTrue(
                any(node["kind"] == "libvirt_domain" for node in payload["nodes"])
            )


if __name__ == "__main__":
    unittest.main()
