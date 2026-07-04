#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import pathlib
import re
import subprocess
import sys


UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def load_json_or_empty(text, default):
    if not text.strip():
        return default
    return json.loads(text)


def get_any(mapping, keys, default=None):
    if not isinstance(mapping, dict):
        return default
    for key in keys:
        if key in mapping:
            return mapping[key]
    return default


def extract_ids(value):
    if value is None:
        return []
    if isinstance(value, str):
        return sorted(set(UUID_RE.findall(value)))
    if isinstance(value, dict):
        found = []
        for key in ("id", "ID", "uuid", "UUID"):
            if key in value and isinstance(value[key], str):
                found.extend(UUID_RE.findall(value[key]))
        for item in value.values():
            found.extend(extract_ids(item))
        return sorted(set(found))
    if isinstance(value, list):
        found = []
        for item in value:
            found.extend(extract_ids(item))
        return sorted(set(found))
    return []


class Collector:
    def __init__(self, args):
        self.args = args
        self.out = pathlib.Path(args.out_dir)
        self.raw = self.out / "raw"
        self.clouds_in_container = f"/tmp/rehome-clouds-{args.side}.yaml"
        self.raw.mkdir(parents=True, exist_ok=True)

    def run(self, cmd, allow_fail=False):
        proc = subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if proc.returncode != 0 and not allow_fail:
            sys.stderr.write(proc.stderr)
            raise SystemExit(proc.returncode)
        return proc

    def copy_clouds(self):
        self.run(
            [
                "docker",
                "cp",
                self.args.clouds_file,
                f"{self.args.container}:{self.clouds_in_container}",
            ]
        )
        self.run(["docker", "exec", "-u", "0", self.args.container, "chmod", "0644", self.clouds_in_container])

    def os_json(self, name, os_args, default, allow_fail=True):
        cmd = [
            "docker",
            "exec",
            "-e",
            f"OS_CLIENT_CONFIG_FILE={self.clouds_in_container}",
            self.args.container,
            "openstack",
            "--os-cloud",
            self.args.cloud,
            *os_args,
        ]
        proc = self.run(cmd, allow_fail=allow_fail)
        raw_path = self.raw / f"{name}.json"
        raw_path.write_text(proc.stdout, encoding="utf-8")
        err_path = self.raw / f"{name}.stderr"
        err_path.write_text(proc.stderr, encoding="utf-8")
        if proc.returncode != 0:
            return default
        try:
            return load_json_or_empty(proc.stdout, default)
        except json.JSONDecodeError:
            return default

    def collect(self):
        self.copy_clouds()

        host = self.args.rehome_host
        servers = self.os_json(
            "servers-by-host",
            ["server", "list", "--all-projects", "--host", host, "--long", "-f", "json"],
            [],
        )
        compute_service = self.os_json(
            "compute-service-by-host",
            ["compute", "service", "list", "--host", host, "-f", "json"],
            [],
        )
        hypervisors = self.os_json(
            "hypervisors",
            ["hypervisor", "list", "--long", "-f", "json"],
            [],
        )
        hypervisor_show = self.os_json(
            "hypervisor-show",
            ["hypervisor", "show", host, "-f", "json"],
            {},
        )
        ports_by_host = self.os_json(
            "ports-by-host",
            ["port", "list", "--host", host, "--long", "-f", "json"],
            [],
        )

        instances = []
        for server_row in servers:
            server_id = get_any(server_row, ["ID", "id"])
            if not server_id:
                continue
            server_show = self.os_json(
                f"server-{server_id}",
                ["server", "show", server_id, "-f", "json"],
                {},
            )
            server_ports = self.os_json(
                f"server-{server_id}-ports",
                ["port", "list", "--server", server_id, "--long", "-f", "json"],
                [],
            )

            ports = []
            for port_row in server_ports:
                port_id = get_any(port_row, ["ID", "id"])
                if not port_id:
                    continue
                port_show = self.os_json(
                    f"port-{port_id}",
                    ["port", "show", port_id, "-f", "json"],
                    {},
                )
                network_id = get_any(port_show, ["network_id", "Network", "network"])
                network_show = {}
                if isinstance(network_id, str) and UUID_RE.search(network_id):
                    network_show = self.os_json(
                        f"network-{network_id}",
                        ["network", "show", network_id, "-f", "json"],
                        {},
                    )

                subnet_ids = []
                fixed_ips = get_any(port_show, ["fixed_ips", "Fixed IP Addresses"], [])
                if isinstance(fixed_ips, list):
                    for fixed_ip in fixed_ips:
                        subnet_id = get_any(fixed_ip, ["subnet_id", "subnet"])
                        if subnet_id:
                            subnet_ids.append(subnet_id)
                else:
                    subnet_ids.extend(extract_ids(fixed_ips))

                subnets = []
                for subnet_id in sorted(set(subnet_ids)):
                    subnets.append(
                        self.os_json(
                            f"subnet-{subnet_id}",
                            ["subnet", "show", subnet_id, "-f", "json"],
                            {},
                        )
                    )

                security_groups = []
                security_group_ids = get_any(
                    port_show,
                    ["security_group_ids", "Security Groups", "security_groups"],
                    [],
                )
                for sg_id in extract_ids(security_group_ids):
                    sg_show = self.os_json(
                        f"security-group-{sg_id}",
                        ["security", "group", "show", sg_id, "-f", "json"],
                        {},
                    )
                    sg_rules = self.os_json(
                        f"security-group-{sg_id}-rules",
                        ["security", "group", "rule", "list", sg_id, "-f", "json"],
                        [],
                    )
                    security_groups.append({"show": sg_show, "rules": sg_rules})

                ports.append(
                    {
                        "id": port_id,
                        "row": port_row,
                        "show": port_show,
                        "network": network_show,
                        "subnets": subnets,
                        "security_groups": security_groups,
                    }
                )

            volume_ids = extract_ids(
                get_any(
                    server_show,
                    ["volumes_attached", "os-extended-volumes:volumes_attached"],
                    [],
                )
            )
            volumes = []
            for volume_id in volume_ids:
                volumes.append(
                    self.os_json(
                        f"volume-{volume_id}",
                        ["volume", "show", volume_id, "-f", "json"],
                        {},
                    )
                )

            flavor_ids = extract_ids(get_any(server_show, ["flavor"], {}))
            flavors = [
                self.os_json(f"flavor-{flavor_id}", ["flavor", "show", flavor_id, "-f", "json"], {})
                for flavor_id in flavor_ids
            ]
            image_ids = extract_ids(get_any(server_show, ["image"], {}))
            images = [
                self.os_json(f"image-{image_id}", ["image", "show", image_id, "-f", "json"], {})
                for image_id in image_ids
            ]

            project_id = get_any(server_show, ["project_id", "tenant_id"])
            user_id = get_any(server_show, ["user_id"])
            project = (
                self.os_json(f"project-{project_id}", ["project", "show", project_id, "-f", "json"], {})
                if project_id
                else {}
            )
            user = (
                self.os_json(f"user-{user_id}", ["user", "show", user_id, "-f", "json"], {})
                if user_id
                else {}
            )

            instances.append(
                {
                    "uuid": server_id,
                    "name": get_any(server_show, ["name", "Name"], get_any(server_row, ["Name", "name"])),
                    "status": get_any(server_show, ["status", "Status"], get_any(server_row, ["Status", "status"])),
                    "host": get_any(server_show, ["OS-EXT-SRV-ATTR:host"]),
                    "instance_name": get_any(server_show, ["OS-EXT-SRV-ATTR:instance_name"]),
                    "hypervisor_hostname": get_any(server_show, ["OS-EXT-SRV-ATTR:hypervisor_hostname"]),
                    "project_id": project_id,
                    "user_id": user_id,
                    "row": server_row,
                    "show": server_show,
                    "ports": ports,
                    "volumes": volumes,
                    "flavors": flavors,
                    "images": images,
                    "project": project,
                    "user": user,
                }
            )

        manifest = {
            "schema_version": "openstack-rehome-openstack-manifest/v1alpha1",
            "generated_at_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "side": self.args.side,
            "rehome_host": host,
            "cloud": self.args.cloud,
            "instances": instances,
            "compute_service": compute_service,
            "hypervisors": hypervisors,
            "hypervisor_show": hypervisor_show,
            "ports_by_host": ports_by_host,
        }
        write_json(self.out / "openstack-manifest.json", manifest)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--clouds-file", required=True)
    parser.add_argument("--cloud", required=True)
    parser.add_argument("--rehome-host", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--side", required=True, choices=["source", "target"])
    parser.add_argument("--container", default="kolla_toolbox")
    args = parser.parse_args()
    Collector(args).collect()


if __name__ == "__main__":
    main()
