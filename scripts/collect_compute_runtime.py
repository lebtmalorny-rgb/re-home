#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import pathlib
import shlex
import subprocess


def run_shell(command, allow_fail=True):
    proc = subprocess.run(
        command,
        shell=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0 and not allow_fail:
        raise RuntimeError(f"command failed: {command}\n{proc.stderr}")
    return {
        "command": command,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--virsh-command", default="virsh")
    args = parser.parse_args()

    out = pathlib.Path(args.out_dir)
    domains_dir = out / "domains"
    domains_dir.mkdir(parents=True, exist_ok=True)

    virsh = args.virsh_command
    domain_list = run_shell(f"{virsh} list --all --name", allow_fail=False)
    domain_names = [line.strip() for line in domain_list["stdout"].splitlines() if line.strip()]

    domains = []
    for name in domain_names:
        qname = shlex.quote(name)
        uuid = run_shell(f"{virsh} domuuid {qname}")
        state = run_shell(f"{virsh} domstate {qname}")
        domiflist = run_shell(f"{virsh} domiflist {qname}")
        dumpxml = run_shell(f"{virsh} dumpxml {qname}")
        xml_path = domains_dir / f"{name}.xml"
        xml_path.write_text(dumpxml["stdout"], encoding="utf-8")
        domains.append(
            {
                "name": name,
                "uuid": uuid["stdout"].strip(),
                "state": state["stdout"].strip(),
                "domiflist_stdout": domiflist["stdout"],
                "dumpxml_path": str(xml_path),
            }
        )

    commands = {
        "ip_link": "ip -br link",
        "ip_addr": "ip -br addr",
        "ip_route": "ip route",
        "docker_ps": "docker ps --format 'table {{.Names}}\\t{{.Image}}\\t{{.Status}}'",
        "ovs_show": (
            "if command -v ovs-vsctl >/dev/null 2>&1; then "
            "ovs-vsctl show; "
            "elif docker ps --format '{{.Names}}' | grep -qx openvswitch_db; then "
            "docker exec openvswitch_db ovs-vsctl show; "
            "else echo 'ovs-vsctl unavailable'; fi"
        ),
        "ovs_interfaces_json": (
            "if command -v ovs-vsctl >/dev/null 2>&1; then "
            "ovs-vsctl --format=json list Interface; "
            "elif docker ps --format '{{.Names}}' | grep -qx openvswitch_db; then "
            "docker exec openvswitch_db ovs-vsctl --format=json list Interface; "
            "else echo '{}'; fi"
        ),
        "ovs_ports_json": (
            "if command -v ovs-vsctl >/dev/null 2>&1; then "
            "ovs-vsctl --format=json list Port; "
            "elif docker ps --format '{{.Names}}' | grep -qx openvswitch_db; then "
            "docker exec openvswitch_db ovs-vsctl --format=json list Port; "
            "else echo '{}'; fi"
        ),
        "instances_path_ls": "ls -la /var/lib/nova/instances 2>&1 || true",
        "iscsi_sessions": "iscsiadm -m session 2>&1 || true",
        "rbd_showmapped": "rbd showmapped 2>&1 || true",
        "multipath_ll": "multipath -ll 2>&1 || true",
    }

    command_results = {}
    raw_dir = out / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for label, command in commands.items():
        result = run_shell(command)
        command_results[label] = {
            "command": command,
            "returncode": result["returncode"],
            "stdout_path": str(raw_dir / f"{label}.stdout"),
            "stderr_path": str(raw_dir / f"{label}.stderr"),
        }
        (raw_dir / f"{label}.stdout").write_text(result["stdout"], encoding="utf-8")
        (raw_dir / f"{label}.stderr").write_text(result["stderr"], encoding="utf-8")

    manifest = {
        "schema_version": "openstack-rehome-compute-runtime/v1alpha1",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "virsh_command": virsh,
        "domains": domains,
        "command_results": command_results,
    }
    write_json(out / "compute-runtime.json", manifest)


if __name__ == "__main__":
    main()
