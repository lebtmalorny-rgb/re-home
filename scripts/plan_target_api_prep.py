#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import os
import pathlib
import subprocess
import sys


RESOURCE_COLLECTIONS = {
    "flavor": "flavors",
    "network": "networks",
    "subnet": "subnets",
    "security_group": "security_groups",
    "port": "ports",
    "volume": "volumes",
}

RESOURCE_ORDER = {
    "flavor": 10,
    "network": 20,
    "subnet": 30,
    "security_group": 40,
    "port": 50,
    "volume": 60,
}


def read_json(path):
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def write_json(path, data):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def yaml_scalar(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value), ensure_ascii=False)


def write_yaml_value(handle, value, indent=0):
    sp = "  " * indent
    if isinstance(value, dict):
        for key in sorted(value.keys()):
            item = value[key]
            if isinstance(item, (dict, list)):
                handle.write(f"{sp}{key}:\n")
                write_yaml_value(handle, item, indent + 1)
            else:
                handle.write(f"{sp}{key}: {yaml_scalar(item)}\n")
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, (dict, list)):
                handle.write(f"{sp}-\n")
                write_yaml_value(handle, item, indent + 1)
            else:
                handle.write(f"{sp}- {yaml_scalar(item)}\n")
    else:
        handle.write(f"{sp}{yaml_scalar(value)}\n")


def write_yaml(path, data):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        write_yaml_value(handle, data)


def resource_name(resource_type, payload):
    if resource_type == "flavor":
        return payload.get("name") or payload.get("id")
    return payload.get("name")


def add_resource(resources, resource_type, resource_id, payload, instance_uuid):
    if not resource_id:
        return
    current = resources.setdefault(
        (resource_type, resource_id),
        {
            "resource_type": resource_type,
            "id": resource_id,
            "name": resource_name(resource_type, payload),
            "source": payload,
            "referenced_by_instances": [],
        },
    )
    if instance_uuid and instance_uuid not in current["referenced_by_instances"]:
        current["referenced_by_instances"].append(instance_uuid)


def extract_required_resources(manifest):
    resources = {}
    for instance in manifest.get("source", {}).get("instances", []):
        instance_uuid = instance.get("uuid")

        flavor = instance.get("flavor")
        if isinstance(flavor, dict):
            add_resource(resources, "flavor", flavor.get("id") or flavor.get("name"), flavor, instance_uuid)

        for port in instance.get("ports", []):
            add_resource(resources, "port", port.get("id"), port, instance_uuid)

            network = port.get("network", {})
            add_resource(resources, "network", network.get("id"), network, instance_uuid)

            for subnet in port.get("subnets", []):
                add_resource(resources, "subnet", subnet.get("id"), subnet, instance_uuid)

            for security_group in port.get("security_groups", []):
                add_resource(
                    resources,
                    "security_group",
                    security_group.get("id"),
                    security_group,
                    instance_uuid,
                )

        for volume in instance.get("volumes", []):
            add_resource(resources, "volume", volume.get("id"), volume, instance_uuid)

    return sorted(
        resources.values(),
        key=lambda item: (RESOURCE_ORDER.get(item["resource_type"], 999), item["id"]),
    )


def target_object(target_state, resource_type, resource_id):
    collection = RESOURCE_COLLECTIONS[resource_type]
    return target_state.get(collection, {}).get(resource_id)


def flavor_create_command(source):
    name = source.get("name") or source.get("id")
    command = [
        "flavor",
        "create",
        "--id",
        source.get("id"),
        "--ram",
        str(source.get("ram", 0)),
        "--disk",
        str(source.get("disk", 0)),
        "--vcpus",
        str(source.get("vcpus", 1)),
    ]
    if source.get("ephemeral") is not None:
        command.extend(["--ephemeral", str(source.get("ephemeral"))])
    if source.get("swap") is not None:
        command.extend(["--swap", str(source.get("swap"))])
    command.append("--public" if source.get("is_public", True) else "--private")
    command.append(name)
    return command


def classify_resource(resource, target_state):
    resource_type = resource["resource_type"]
    target = target_object(target_state, resource_type, resource["id"])
    if target:
        return {
            **resource,
            "present_on_target": True,
            "target": target,
            "action": "exists",
            "api_safe": False,
            "reason": "Target object with the same canonical ID already exists.",
            "apply_commands": [],
        }

    if resource_type == "flavor":
        return {
            **resource,
            "present_on_target": False,
            "target": {},
            "action": "create_api_safe",
            "api_safe": True,
            "reason": "Flavor can be created through OpenStack API with an explicit flavor ID.",
            "apply_commands": [flavor_create_command(resource["source"])],
        }

    if resource_type == "volume":
        return {
            **resource,
            "present_on_target": False,
            "target": {},
            "action": "db_import_only",
            "api_safe": False,
            "reason": "Cinder/Nova volume attachment metadata must be prepared by reviewed metadata import.",
            "apply_commands": [],
        }

    return {
        **resource,
        "present_on_target": False,
        "target": {},
        "action": "requires_existing_or_db_import",
        "api_safe": False,
        "reason": (
            "This resource is UUID-backed for re-home. Creating it with a new ID "
            "through a generic API path would break metadata consistency."
        ),
        "apply_commands": [],
    }


def build_plan(manifest, target_state):
    items = [classify_resource(resource, target_state) for resource in extract_required_resources(manifest)]
    summary = {
        "total": len(items),
        "exists": 0,
        "create_api_safe": 0,
        "requires_existing_or_db_import": 0,
        "db_import_only": 0,
    }
    for item in items:
        summary[item["action"]] = summary.get(item["action"], 0) + 1

    return {
        "schema_version": "openstack-rehome-target-api-prep/v1alpha1",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": summary,
        "items": items,
        "safe_to_apply_count": summary["create_api_safe"],
        "requires_metadata_import_count": (
            summary["requires_existing_or_db_import"] + summary["db_import_only"]
        ),
    }


class OpenStackRunner:
    def __init__(self, cloud, clouds_file=None, container=None):
        self.cloud = cloud
        self.clouds_file = clouds_file
        self.container = container
        self.clouds_in_container = "/tmp/rehome-target-prep-clouds.yaml"

    def run(self, cmd, allow_fail=False):
        proc = subprocess.run(
            cmd,
            env=self._env(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if proc.returncode != 0 and not allow_fail:
            sys.stderr.write(proc.stderr)
            raise SystemExit(proc.returncode)
        return proc

    def _env(self):
        env = os.environ.copy()
        if self.clouds_file and not self.container:
            env["OS_CLIENT_CONFIG_FILE"] = self.clouds_file
        return env

    def prepare(self):
        if not self.container or not self.clouds_file:
            return
        self.run(["docker", "cp", self.clouds_file, f"{self.container}:{self.clouds_in_container}"])
        self.run(["docker", "exec", "-u", "0", self.container, "chmod", "0644", self.clouds_in_container])

    def os_json(self, os_args, default, allow_fail=True):
        if self.container:
            cmd = [
                "docker",
                "exec",
                "-e",
                f"OS_CLIENT_CONFIG_FILE={self.clouds_in_container}",
                self.container,
                "openstack",
                "--os-cloud",
                self.cloud,
                *os_args,
            ]
        else:
            cmd = ["openstack", "--os-cloud", self.cloud, *os_args]
        proc = self.run(cmd, allow_fail=allow_fail)
        if proc.returncode != 0 or not proc.stdout.strip():
            return default
        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError:
            return default


def show_command(resource_type, resource_id):
    if resource_type == "flavor":
        return ["flavor", "show", resource_id, "-f", "json"]
    if resource_type == "network":
        return ["network", "show", resource_id, "-f", "json"]
    if resource_type == "subnet":
        return ["subnet", "show", resource_id, "-f", "json"]
    if resource_type == "security_group":
        return ["security", "group", "show", resource_id, "-f", "json"]
    if resource_type == "port":
        return ["port", "show", resource_id, "-f", "json"]
    if resource_type == "volume":
        return ["volume", "show", resource_id, "-f", "json"]
    raise ValueError(f"unsupported resource type: {resource_type}")


def collect_target_state(manifest, runner):
    state = {collection: {} for collection in RESOURCE_COLLECTIONS.values()}
    for resource in extract_required_resources(manifest):
        resource_type = resource["resource_type"]
        resource_id = resource["id"]
        obj = runner.os_json(show_command(resource_type, resource_id), {}, allow_fail=True)
        if obj:
            state[RESOURCE_COLLECTIONS[resource_type]][resource_id] = obj
    return state


def apply_api_safe_items(plan, runner):
    applied = []
    for item in plan["items"]:
        if item["action"] != "create_api_safe":
            continue
        for command in item["apply_commands"]:
            runner.os_json([*command, "-f", "json"], {}, allow_fail=False)
        extra_specs = item["source"].get("extra_specs") or {}
        for key, value in sorted(extra_specs.items()):
            runner.os_json(
                ["flavor", "set", "--property", f"{key}={value}", item["id"], "-f", "json"],
                {},
                allow_fail=False,
            )
        applied.append({"resource_type": item["resource_type"], "id": item["id"]})
    return applied


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest-json", required=True)
    parser.add_argument("--target-state-json")
    parser.add_argument("--out-json", required=True)
    parser.add_argument("--out-yaml")
    parser.add_argument("--cloud")
    parser.add_argument("--clouds-file")
    parser.add_argument("--container", default="")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--fail-on-db-required", action="store_true")
    args = parser.parse_args()

    manifest = read_json(args.manifest_json)
    if args.target_state_json:
        target_state = read_json(args.target_state_json)
        runner = None
    else:
        if not args.cloud:
            raise SystemExit("--cloud is required when --target-state-json is not provided")
        runner = OpenStackRunner(args.cloud, args.clouds_file, args.container or None)
        runner.prepare()
        target_state = collect_target_state(manifest, runner)

    plan = build_plan(manifest, target_state)
    plan["mode"] = "apply" if args.apply else "report"
    plan["applied"] = []

    if args.fail_on_db_required and plan["requires_metadata_import_count"] > 0:
        write_json(args.out_json, plan)
        if args.out_yaml:
            write_yaml(args.out_yaml, plan)
        raise SystemExit("target prep report contains resources that require existing UUIDs or DB import")

    if args.apply:
        if runner is None:
            raise SystemExit("--apply requires live OpenStack access, not --target-state-json")
        plan["applied"] = apply_api_safe_items(plan, runner)

    write_json(args.out_json, plan)
    if args.out_yaml:
        write_yaml(args.out_yaml, plan)


if __name__ == "__main__":
    main()
