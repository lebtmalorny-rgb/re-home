#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import pathlib


SQL_BLOCKS = {
    "keystone_identity_optional": {
        "sql_file": "sql-skeleton/10-keystone-projects-users-optional.sql",
        "required": False,
        "tables": ["project", "user", "assignment"],
        "reason": "Target may need matching project/user identity before metadata import.",
    },
    "neutron_metadata": {
        "sql_file": "sql-skeleton/20-neutron-networks-ports-sg.sql",
        "required": True,
        "tables": [
            "networks",
            "networksegments",
            "subnets",
            "subnetpools",
            "ports",
            "ipallocations",
            "ml2_port_bindings",
            "securitygroups",
            "securitygrouprules",
            "securitygroupportbindings",
        ],
        "reason": "Neutron UUID-backed network resources must preserve source IDs.",
    },
    "cinder_metadata": {
        "sql_file": "sql-skeleton/30-cinder-volumes-attachments.sql",
        "required": True,
        "tables": [
            "volumes",
            "volume_attachment",
            "volume_glance_metadata",
            "volume_admin_metadata",
            "volume_metadata",
        ],
        "reason": "Boot volume and attachment metadata must match Nova block device mapping.",
    },
    "nova_api_metadata": {
        "sql_file": "sql-skeleton/40-nova-api-instance-mappings-request-specs.sql",
        "required": True,
        "tables": [
            "host_mappings",
            "instance_mappings",
            "request_specs",
            "build_requests",
        ],
        "reason": "Nova API DB must know instance-to-cell mapping and scheduling request specs.",
    },
    "nova_cell_metadata": {
        "sql_file": "sql-skeleton/50-nova-cell-instances-bdm-info-cache.sql",
        "required": True,
        "tables": [
            "instances",
            "instance_extra",
            "instance_info_caches",
            "instance_metadata",
            "instance_system_metadata",
            "block_device_mapping",
            "virtual_interfaces",
            "migrations",
        ],
        "reason": "Nova cell DB must contain the running instance and its device metadata.",
    },
    "nova_compute_service_mapping": {
        "sql_file": "sql-skeleton/60-nova-cell-compute-nodes-services-if-needed.sql",
        "required": False,
        "tables": [
            "services",
            "compute_nodes",
            "host_mappings",
        ],
        "reason": "Only needed if target nova-compute registration does not create the expected host records.",
    },
}

BLOCK_ORDER = [
    "keystone_identity_optional",
    "neutron_metadata",
    "cinder_metadata",
    "nova_api_metadata",
    "nova_cell_metadata",
    "nova_compute_service_mapping",
]


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


def sorted_unique(values):
    return sorted({value for value in values if value})


def instance_resources(manifest):
    instances = manifest.get("source", {}).get("instances", [])
    instance_ids = []
    instance_names = []
    project_ids = []
    user_ids = []
    network_ids = []
    subnet_ids = []
    security_group_ids = []
    port_ids = []
    volume_ids = []

    for instance in instances:
        instance_ids.append(instance.get("uuid"))
        instance_names.append(instance.get("instance_name"))
        project_ids.append(instance.get("project_id"))
        user_ids.append(instance.get("user_id"))

        for port in instance.get("ports", []):
            port_ids.append(port.get("id"))
            network_ids.append(port.get("network", {}).get("id"))
            for subnet in port.get("subnets", []):
                subnet_ids.append(subnet.get("id"))
            for security_group in port.get("security_groups", []):
                security_group_ids.append(security_group.get("id"))

        for volume in instance.get("volumes", []):
            volume_ids.append(volume.get("id"))

    return {
        "instances": sorted_unique(instance_ids),
        "instance_names": sorted_unique(instance_names),
        "rehome_hosts": sorted_unique([manifest.get("rehome_host")]),
        "projects": sorted_unique(project_ids),
        "users": sorted_unique(user_ids),
        "networks": sorted_unique(network_ids),
        "subnets": sorted_unique(subnet_ids),
        "security_groups": sorted_unique(security_group_ids),
        "ports": sorted_unique(port_ids),
        "volumes": sorted_unique(volume_ids),
    }


def api_report_actions(api_report):
    actions = {}
    for item in api_report.get("items", []):
        resource_type = item.get("resource_type")
        resource_id = item.get("id")
        if resource_type and resource_id:
            actions.setdefault(resource_type, {})[resource_id] = item.get("action")
    return actions


def block_resource_ids(name, resources):
    if name == "keystone_identity_optional":
        return {"projects": resources["projects"], "users": resources["users"]}
    if name == "neutron_metadata":
        return {
            "networks": resources["networks"],
            "subnets": resources["subnets"],
            "security_groups": resources["security_groups"],
            "ports": resources["ports"],
        }
    if name == "cinder_metadata":
        return {"volumes": resources["volumes"]}
    if name in ("nova_api_metadata", "nova_cell_metadata"):
        return {
            "instances": resources["instances"],
            "instance_names": resources["instance_names"],
            "rehome_hosts": resources["rehome_hosts"],
            "ports": resources["ports"],
            "volumes": resources["volumes"],
        }
    if name == "nova_compute_service_mapping":
        return {"instances": resources["instances"]}
    return {}


def block_needed(name, resources, actions):
    if name == "keystone_identity_optional":
        return bool(resources["projects"] or resources["users"])
    if name == "neutron_metadata":
        neutron_missing = []
        for resource_type, ids in (
            ("network", resources["networks"]),
            ("subnet", resources["subnets"]),
            ("security_group", resources["security_groups"]),
            ("port", resources["ports"]),
        ):
            neutron_missing.extend(
                resource_id
                for resource_id in ids
                if actions.get(resource_type, {}).get(resource_id) != "exists"
            )
        return bool(neutron_missing)
    if name == "cinder_metadata":
        return bool(resources["volumes"])
    if name in ("nova_api_metadata", "nova_cell_metadata"):
        return bool(resources["instances"])
    return False


def build_plan(manifest, api_report):
    resources = instance_resources(manifest)
    actions = api_report_actions(api_report)
    blocks = []

    for name in BLOCK_ORDER:
        if not block_needed(name, resources, actions):
            continue
        spec = SQL_BLOCKS[name]
        blocks.append(
            {
                "name": name,
                "sql_file": spec["sql_file"],
                "required": spec["required"],
                "tables": spec["tables"],
                "reason": spec["reason"],
                "resource_ids": block_resource_ids(name, resources),
                "guards": [
                    "schema compatibility reports must be reviewed before importing",
                    "source rows must be selected by explicit UUID or instance_name filters",
                    "target rows with the same UUID must be absent or byte-for-byte reviewed",
                    "target database backup must exist before import",
                    "SQL must be reviewed; generated skeletons are not executable imports",
                ],
            }
        )

    required_sql_files = [block["sql_file"] for block in blocks if block["required"]]
    ordered_sql_files = [block["sql_file"] for block in blocks]

    return {
        "schema_version": "openstack-rehome-db-import-plan/v1alpha1",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "rehome_host": manifest.get("rehome_host"),
        "summary": {
            "instances": len(resources["instances"]),
            "ports": len(resources["ports"]),
            "volumes": len(resources["volumes"]),
            "blocks": len(blocks),
            "requires_reviewed_sql_files": len(ordered_sql_files),
            "required_import_sql_files": len(required_sql_files),
            "optional_sql_files": len(ordered_sql_files) - len(required_sql_files),
        },
        "api_prep_summary": api_report.get("summary", {}),
        "resource_ids": resources,
        "blocks": blocks,
        "required_sql_files": required_sql_files,
        "ordered_sql_files": ordered_sql_files,
        "hard_stop": (
            "Do not run mysql import from this plan directly. Replace skeletons "
            "with reviewed host-scoped SQL generated from source DB rows."
        ),
    }


def sql_list_comment(label, values):
    if not values:
        return [f"-- {label}: none"]
    lines = [f"-- {label}:"]
    lines.extend(f"--   - {value}" for value in values)
    return lines


def render_sql_skeleton(block):
    resource_ids = block["resource_ids"]
    lines = [
        "-- DO NOT EXECUTE: review skeleton only.",
        "-- Replace this file with schema-aware, host-scoped SQL before import.",
        f"-- Block: {block['name']}",
        f"-- Reason: {block['reason']}",
        "-- Tables to review:",
    ]
    lines.extend(f"--   - {table}" for table in block["tables"])
    lines.append("-- Resource filters:")
    for key in sorted(resource_ids.keys()):
        lines.extend(sql_list_comment(key, resource_ids[key]))
    lines.extend(
        [
            "-- Guard conditions:",
            "--   - confirm schema compatibility artifacts are clean or explicitly accepted",
            "--   - take target DB backup immediately before import",
            "--   - select source rows only by the UUIDs listed above",
            "--   - verify target row counts before and after import",
            "--   - do not import whole service databases",
            "",
        ]
    )
    return "\n".join(lines)


def render_sql_review_pack(plan, out_dir):
    out_dir = pathlib.Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for block in plan["blocks"]:
        path = out_dir / pathlib.Path(block["sql_file"]).name
        path.write_text(render_sql_skeleton(block), encoding="utf-8")
        written.append(str(path))
    return written


def render_markdown(plan):
    lines = [
        "# Target DB Metadata Import Plan",
        "",
        "This is a review artifact, not an executable import.",
        "",
        f"- Re-home host: `{plan.get('rehome_host')}`",
        f"- Instances: `{plan['summary']['instances']}`",
        f"- Required reviewed SQL files: `{plan['summary']['requires_reviewed_sql_files']}`",
        "",
        "## Ordered SQL Blocks",
        "",
    ]
    for block in plan["blocks"]:
        lines.extend(
            [
                f"### {block['name']}",
                "",
                f"- SQL file: `{block['sql_file']}`",
                f"- Required: `{str(block['required']).lower()}`",
                f"- Reason: {block['reason']}",
                "- Tables:",
            ]
        )
        lines.extend(f"  - `{table}`" for table in block["tables"])
        lines.append("- Resource IDs:")
        for key in sorted(block["resource_ids"].keys()):
            values = block["resource_ids"][key]
            joined = ", ".join(f"`{value}`" for value in values) if values else "`none`"
            lines.append(f"  - `{key}`: {joined}")
        lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest-json", required=True)
    parser.add_argument("--target-api-prep-report", required=True)
    parser.add_argument("--out-json", required=True)
    parser.add_argument("--out-yaml")
    parser.add_argument("--out-md")
    parser.add_argument("--sql-review-dir")
    args = parser.parse_args()

    manifest = read_json(args.manifest_json)
    api_report = read_json(args.target_api_prep_report)
    plan = build_plan(manifest, api_report)

    write_json(args.out_json, plan)
    if args.out_yaml:
        write_yaml(args.out_yaml, plan)
    if args.out_md:
        pathlib.Path(args.out_md).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(args.out_md).write_text(render_markdown(plan), encoding="utf-8")
    if args.sql_review_dir:
        render_sql_review_pack(plan, args.sql_review_dir)


if __name__ == "__main__":
    main()
