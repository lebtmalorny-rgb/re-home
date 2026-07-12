import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from live_discovery.argv_policy import validate_inventory_commands, validate_mysql_argv


class LiveDiscoveryArgvPolicyTests(unittest.TestCase):
    def valid(self):
        return {
            "nova_api": ["docker", "exec", "nova_api", "nova-manage", "api_db", "version"],
            "nova_cell": ["docker", "exec", "nova_conductor", "nova-manage", "db", "version"],
            "neutron": ["docker", "exec", "neutron_server", "neutron-db-manage", "current", "--verbose"],
            "cinder": ["docker", "exec", "cinder_api", "cinder-manage", "db", "version"],
            "inspect": ["docker", "inspect"],
            "source_virsh": ["docker", "exec", "nova_libvirt", "virsh"],
            "target_virsh": ["virsh"],
            "target_qemu": ["qemu-system-x86_64"],
            "openstack_container": "kolla_toolbox",
        }

    def test_accepts_exact_host_and_kolla_read_only_argv(self):
        self.assertEqual(self.valid(), validate_inventory_commands(self.valid()))

    def test_rejects_mutation_extra_arg_shell_syntax_and_wrong_container(self):
        mutations = []
        appended = self.valid(); appended["nova_cell"] += ["sync"]; mutations.append(appended)
        shell = self.valid(); shell["target_qemu"] = ["qemu-system-x86_64;touch", "/tmp/x"]; mutations.append(shell)
        wrong = self.valid(); wrong["neutron"][2] = "nova_api"; mutations.append(wrong)
        openstack = self.valid(); openstack["openstack_container"] = "toolbox;evil"; mutations.append(openstack)
        for payload in mutations:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                validate_inventory_commands(payload)

    def test_rejects_unknown_keys_and_non_string_argv(self):
        extra = self.valid(); extra["unexpected"] = ["version"]
        with self.assertRaises(ValueError):
            validate_inventory_commands(extra)
        invalid = self.valid(); invalid["inspect"] = ["docker", 1]
        with self.assertRaises(ValueError):
            validate_inventory_commands(invalid)

    def test_mysql_transport_is_exact_and_rejects_extra_execute_or_shell(self):
        self.assertEqual(
            ["mysql", "--batch", "--raw", "--skip-column-names"],
            validate_mysql_argv(["mysql", "--batch", "--raw", "--skip-column-names"]),
        )
        kolla = ["docker", "exec", "-e", "MYSQL_PWD=opaque", "-i", "mariadb", "mysql", "-unova", "-h", "192.0.2.10", "--batch", "--raw", "--skip-column-names"]
        self.assertEqual(kolla, validate_mysql_argv(kolla))
        for suffix in (["--execute", "DELETE FROM nova.instances"], [";touch", "/tmp/x"]):
            with self.assertRaises(ValueError):
                validate_mysql_argv(kolla + suffix)
