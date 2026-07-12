"""Exact allowlist for inventory-overridable live-discovery command argv."""

import argparse
from copy import deepcopy
import json
import re


_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SHELL_SYNTAX = re.compile(r"[\r\n;&|`<>]|\$\(")
_EXPECTED = {
    "nova_api": (["nova-manage", "api_db", "version"], "nova_api"),
    "nova_cell": (["nova-manage", "db", "version"], "nova_conductor"),
    "neutron": (["neutron-db-manage", "current", "--verbose"], "neutron_server"),
    "cinder": (["cinder-manage", "db", "version"], "cinder_api"),
}


def _argv(value, name):
    if not isinstance(value, list) or not value or not all(
        isinstance(item, str) and item and _SHELL_SYNTAX.search(item) is None
        for item in value
    ):
        raise ValueError(f"{name} argv is invalid")
    return list(value)


def _exact_or_kolla(value, name, suffix, container):
    argv = _argv(value, name)
    if argv == suffix:
        return argv
    if argv != ["docker", "exec", container, *suffix]:
        raise ValueError(f"{name} argv is outside the read-only policy")
    return argv


def _virsh(value, name):
    argv = _argv(value, name)
    if argv not in (["virsh"], ["docker", "exec", "nova_libvirt", "virsh"]):
        raise ValueError(f"{name} argv is outside the read-only policy")
    return argv


def _qemu(value):
    argv = _argv(value, "target_qemu")
    host = [["qemu-system-x86_64"], ["/usr/bin/qemu-system-x86_64"], ["/usr/libexec/qemu-kvm"]]
    kolla = [["docker", "exec", "nova_libvirt", *item] for item in host]
    if argv not in [*host, *kolla]:
        raise ValueError("target_qemu argv is outside the read-only policy")
    return argv


def validate_inventory_commands(payload):
    expected_keys = {
        "nova_api", "nova_cell", "neutron", "cinder", "inspect",
        "source_virsh", "target_virsh", "target_qemu", "openstack_container",
    }
    if not isinstance(payload, dict) or set(payload) != expected_keys:
        raise ValueError("inventory command policy document is invalid")
    normalized = {}
    for name, (suffix, container) in _EXPECTED.items():
        normalized[name] = _exact_or_kolla(payload[name], name, suffix, container)
    normalized["inspect"] = _argv(payload["inspect"], "inspect")
    if normalized["inspect"] != ["docker", "inspect"]:
        raise ValueError("container inspect argv is outside the read-only policy")
    normalized["source_virsh"] = _virsh(payload["source_virsh"], "source_virsh")
    normalized["target_virsh"] = _virsh(payload["target_virsh"], "target_virsh")
    normalized["target_qemu"] = _qemu(payload["target_qemu"])
    container = payload["openstack_container"]
    if not isinstance(container, str) or _SAFE_NAME.fullmatch(container) is None or container != "kolla_toolbox":
        raise ValueError("OpenStack CLI container is outside the policy")
    normalized["openstack_container"] = container
    return deepcopy(normalized)


def validate_mysql_argv(value):
    argv = _argv(value, "mysql")
    direct = ["mysql", "--batch", "--raw", "--skip-column-names"]
    if argv == direct:
        return argv
    if len(argv) != 13 or argv[:3] != ["docker", "exec", "-e"]:
        raise ValueError("MySQL argv is outside the transport policy")
    if not argv[3].startswith("MYSQL_PWD=") or not argv[3][len("MYSQL_PWD="):]:
        raise ValueError("MySQL password transport is invalid")
    if argv[4:7] != ["-i", "mariadb", "mysql"]:
        raise ValueError("MySQL container transport is invalid")
    if not argv[7].startswith("-u") or _SAFE_NAME.fullmatch(argv[7][2:]) is None:
        raise ValueError("MySQL user is invalid")
    if argv[8] != "-h" or _SAFE_NAME.fullmatch(argv[9]) is None:
        raise ValueError("MySQL host is invalid")
    if argv[10:] != ["--batch", "--raw", "--skip-column-names"]:
        raise ValueError("MySQL flags are outside the read-only transport policy")
    return argv


def main(argv=None):
    parser = argparse.ArgumentParser(description="Validate live-discovery argv policy")
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--config-json")
    inputs.add_argument("--mysql-json")
    args = parser.parse_args(argv)
    try:
        payload = json.loads(args.config_json or args.mysql_json)
        if args.config_json is not None:
            validate_inventory_commands(payload)
        else:
            validate_mysql_argv(payload)
    except (ValueError, json.JSONDecodeError):
        return 2
    print("READ_ONLY_ARGV_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
