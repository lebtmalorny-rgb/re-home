#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import pathlib


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def find_one(root, pattern):
    matches = sorted(pathlib.Path(root).glob(pattern))
    if not matches:
        raise SystemExit(f"missing artifact matching {pattern} under {root}")
    return matches[0]


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
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        write_yaml_value(handle, data)


def compact_instance(instance):
    server_show = instance.get("show", {})
    ports = []
    for port in instance.get("ports", []):
        show = port.get("show", {})
        security_groups = []
        for security_group in port.get("security_groups", []):
            sg_show = security_group.get("show", {})
            security_groups.append(
                {
                    "id": sg_show.get("id"),
                    "name": sg_show.get("name"),
                    "description": sg_show.get("description"),
                    "project_id": sg_show.get("project_id"),
                    "stateful": sg_show.get("stateful"),
                    "rules": sg_show.get("rules", security_group.get("rules", [])),
                }
            )
        ports.append(
            {
                "id": port.get("id"),
                "mac_address": show.get("mac_address"),
                "fixed_ips": show.get("fixed_ips"),
                "network_id": show.get("network_id"),
                "binding_host_id": show.get("binding_host_id") or show.get("binding:host_id"),
                "binding_vif_type": show.get("binding_vif_type") or show.get("binding:vif_type"),
                "binding_vif_details": show.get("binding_vif_details") or show.get("binding:vif_details"),
                "security_group_ids": show.get("security_group_ids"),
                "security_groups": security_groups,
                "network": {
                    "id": port.get("network", {}).get("id"),
                    "name": port.get("network", {}).get("name"),
                    "provider_network_type": port.get("network", {}).get("provider:network_type"),
                    "provider_physical_network": port.get("network", {}).get("provider:physical_network"),
                    "provider_segmentation_id": port.get("network", {}).get("provider:segmentation_id"),
                },
                "subnets": [
                    {
                        "id": subnet.get("id"),
                        "name": subnet.get("name"),
                        "cidr": subnet.get("cidr"),
                        "gateway_ip": subnet.get("gateway_ip"),
                        "enable_dhcp": subnet.get("enable_dhcp"),
                    }
                    for subnet in port.get("subnets", [])
                ],
            }
        )
    volumes = []
    for volume in instance.get("volumes", []):
        volumes.append(
            {
                "id": volume.get("id"),
                "name": volume.get("name"),
                "status": volume.get("status"),
                "bootable": volume.get("bootable"),
                "size": volume.get("size"),
                "type": volume.get("type"),
                "availability_zone": volume.get("availability_zone"),
                "host": volume.get("os-vol-host-attr:host"),
                "tenant_id": volume.get("os-vol-tenant-attr:tenant_id"),
                "user_id": volume.get("user_id"),
                "attachments": volume.get("attachments", []),
                "volume_image_metadata": volume.get("volume_image_metadata", {}),
            }
        )
    return {
        "uuid": instance.get("uuid"),
        "name": instance.get("name"),
        "status": instance.get("status"),
        "vm_state": server_show.get("OS-EXT-STS:vm_state"),
        "power_state": server_show.get("OS-EXT-STS:power_state"),
        "host": instance.get("host"),
        "instance_name": instance.get("instance_name"),
        "hypervisor_hostname": instance.get("hypervisor_hostname"),
        "availability_zone": server_show.get("OS-EXT-AZ:availability_zone"),
        "root_device_name": server_show.get("OS-EXT-SRV-ATTR:root_device_name"),
        "config_drive": server_show.get("config_drive"),
        "project_id": instance.get("project_id"),
        "user_id": instance.get("user_id"),
        "server_groups": server_show.get("server_groups", []),
        "server_security_groups": server_show.get("security_groups", []),
        "ports": ports,
        "volumes": volumes,
        "volume_ids": [volume.get("id") for volume in volumes if volume.get("id")],
        "flavor": server_show.get("flavor"),
        "flavors": instance.get("flavors", []),
        "image": server_show.get("image"),
        "images": instance.get("images", []),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-dir", required=True)
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--output-yaml", required=True)
    args = parser.parse_args()

    artifact_dir = pathlib.Path(args.artifact_dir)
    source_manifest = read_json(find_one(artifact_dir, "source/**/openstack-manifest.json"))
    target_manifest = read_json(find_one(artifact_dir, "target/**/openstack-manifest.json"))
    compute_runtime = read_json(find_one(artifact_dir, "compute/**/compute-runtime.json"))

    source_instances = source_manifest.get("instances", [])
    domain_names = {domain.get("name") for domain in compute_runtime.get("domains", [])}
    instance_names = {instance.get("instance_name") for instance in source_instances}

    manifest = {
        "schema_version": "openstack-rehome-manifest/v1alpha1",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "rehome_host": source_manifest.get("rehome_host"),
        "source": {
            "cloud": source_manifest.get("cloud"),
            "instances": [compact_instance(instance) for instance in source_instances],
            "compute_service": source_manifest.get("compute_service", []),
            "hypervisor_show": source_manifest.get("hypervisor_show", {}),
            "ports_by_host": source_manifest.get("ports_by_host", []),
        },
        "target_pre": {
            "cloud": target_manifest.get("cloud"),
            "compute_service": target_manifest.get("compute_service", []),
            "hypervisor_show": target_manifest.get("hypervisor_show", {}),
            "ports_by_host": target_manifest.get("ports_by_host", []),
            "instances_on_same_host": [
                compact_instance(instance) for instance in target_manifest.get("instances", [])
            ],
        },
        "compute_runtime": {
            "virsh_command": compute_runtime.get("virsh_command"),
            "domains": compute_runtime.get("domains", []),
        },
        "checks": {
            "source_instance_count": len(source_instances),
            "compute_domain_count": len(compute_runtime.get("domains", [])),
            "source_instance_names": sorted(name for name in instance_names if name),
            "compute_domain_names": sorted(name for name in domain_names if name),
            "source_instances_present_as_domains": sorted(
                name for name in instance_names if name and name in domain_names
            ),
            "source_instances_missing_domains": sorted(
                name for name in instance_names if name and name not in domain_names
            ),
        },
        "raw_artifacts": {
            "source_openstack_manifest": str(find_one(artifact_dir, "source/**/openstack-manifest.json")),
            "target_openstack_manifest": str(find_one(artifact_dir, "target/**/openstack-manifest.json")),
            "compute_runtime_manifest": str(find_one(artifact_dir, "compute/**/compute-runtime.json")),
        },
    }

    output_json = pathlib.Path(args.output_json)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    write_yaml(pathlib.Path(args.output_yaml), manifest)


if __name__ == "__main__":
    main()
