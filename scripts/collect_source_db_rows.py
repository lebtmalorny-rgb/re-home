#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import pathlib


SERVICE_ORDER = ["keystone", "neutron", "cinder", "nova_api", "nova_cell"]


def read_json(path):
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def write_json(path, data):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def sql_string(value):
    return "'" + str(value).replace("\\", "\\\\").replace("'", "''") + "'"


def in_list(values):
    clean = [value for value in values if value]
    if not clean:
        return "('__openstack_rehome_empty_filter__')"
    return "(" + ", ".join(sql_string(value) for value in sorted(set(clean))) + ")"


def qname(db_name, table_name):
    return f"`{db_name}`.`{table_name}`"


def select_table(db_name, table_name, where_clause):
    full_name = f"{db_name}.{table_name}"
    return [
        f"SELECT 'BEGIN {full_name}';",
        f"SELECT * FROM {qname(db_name, table_name)} WHERE {where_clause};",
        f"SELECT 'END {full_name}';",
        "",
    ]


def service_sql(service_name, statements):
    lines = [
        "-- Read-only source DB row collection for OpenStack re-home.",
        "-- This file must contain SELECT statements only.",
        f"-- Service: {service_name}",
        "",
    ]
    lines.extend(statements)
    lines.append("")
    return "\n".join(lines)


def resources(plan):
    return plan.get("resource_ids", {})


def build_keystone_sql(ids):
    project_ids = ids.get("projects", [])
    user_ids = ids.get("users", [])
    statements = []
    statements.extend(select_table("keystone", "project", f"id IN {in_list(project_ids)}"))
    statements.extend(select_table("keystone", "user", f"id IN {in_list(user_ids)}"))
    statements.extend(
        select_table(
            "keystone",
            "assignment",
            f"target_id IN {in_list(project_ids)} OR actor_id IN {in_list(user_ids)}",
        )
    )
    return service_sql("keystone", statements)


def build_neutron_sql(ids):
    network_ids = ids.get("networks", [])
    subnet_ids = ids.get("subnets", [])
    security_group_ids = ids.get("security_groups", [])
    port_ids = ids.get("ports", [])
    subnetpool_filter = (
        "id IN (SELECT subnetpool_id FROM `neutron`.`subnets` "
        f"WHERE id IN {in_list(subnet_ids)} AND subnetpool_id IS NOT NULL)"
    )
    standard_attr_sources = [
        f"SELECT standard_attr_id FROM `neutron`.`networks` WHERE id IN {in_list(network_ids)}",
        f"SELECT standard_attr_id FROM `neutron`.`networksegments` WHERE network_id IN {in_list(network_ids)}",
        f"SELECT standard_attr_id FROM `neutron`.`subnets` WHERE id IN {in_list(subnet_ids)} "
        f"OR network_id IN {in_list(network_ids)}",
        f"SELECT standard_attr_id FROM `neutron`.`subnetpools` WHERE {subnetpool_filter}",
        f"SELECT standard_attr_id FROM `neutron`.`ports` WHERE id IN {in_list(port_ids)} "
        f"OR network_id IN {in_list(network_ids)}",
        f"SELECT standard_attr_id FROM `neutron`.`securitygroups` WHERE id IN {in_list(security_group_ids)}",
        f"SELECT standard_attr_id FROM `neutron`.`securitygrouprules` "
        f"WHERE security_group_id IN {in_list(security_group_ids)} "
        f"OR remote_group_id IN {in_list(security_group_ids)}",
    ]
    statements = []
    statements.extend(
        select_table(
            "neutron",
            "standardattributes",
            "id IN (" + " UNION ".join(standard_attr_sources) + ")",
        )
    )
    statements.extend(select_table("neutron", "networks", f"id IN {in_list(network_ids)}"))
    statements.extend(select_table("neutron", "networksegments", f"network_id IN {in_list(network_ids)}"))
    statements.extend(
        select_table(
            "neutron",
            "subnets",
            f"id IN {in_list(subnet_ids)} OR network_id IN {in_list(network_ids)}",
        )
    )
    statements.extend(
        select_table(
            "neutron",
            "subnetpools",
            subnetpool_filter,
        )
    )
    statements.extend(
        select_table(
            "neutron",
            "ports",
            f"id IN {in_list(port_ids)} OR network_id IN {in_list(network_ids)}",
        )
    )
    statements.extend(select_table("neutron", "ipallocations", f"port_id IN {in_list(port_ids)}"))
    statements.extend(select_table("neutron", "ml2_port_bindings", f"port_id IN {in_list(port_ids)}"))
    statements.extend(select_table("neutron", "securitygroups", f"id IN {in_list(security_group_ids)}"))
    statements.extend(
        select_table(
            "neutron",
            "securitygrouprules",
            f"security_group_id IN {in_list(security_group_ids)} "
            f"OR remote_group_id IN {in_list(security_group_ids)}",
        )
    )
    statements.extend(
        select_table("neutron", "securitygroupportbindings", f"port_id IN {in_list(port_ids)}")
    )
    return service_sql("neutron", statements)


def build_cinder_sql(ids):
    volume_ids = ids.get("volumes", [])
    instance_ids = ids.get("instances", [])
    statements = []
    statements.extend(select_table("cinder", "volumes", f"id IN {in_list(volume_ids)}"))
    statements.extend(
        select_table(
            "cinder",
            "volume_attachment",
            f"volume_id IN {in_list(volume_ids)} OR instance_uuid IN {in_list(instance_ids)}",
        )
    )
    statements.extend(select_table("cinder", "volume_glance_metadata", f"volume_id IN {in_list(volume_ids)}"))
    statements.extend(select_table("cinder", "volume_admin_metadata", f"volume_id IN {in_list(volume_ids)}"))
    statements.extend(select_table("cinder", "volume_metadata", f"volume_id IN {in_list(volume_ids)}"))
    return service_sql("cinder", statements)


def build_nova_api_sql(ids):
    instance_ids = ids.get("instances", [])
    rehome_hosts = ids.get("rehome_hosts", [])
    statements = []
    statements.extend(select_table("nova_api", "host_mappings", f"host IN {in_list(rehome_hosts)}"))
    statements.extend(select_table("nova_api", "instance_mappings", f"instance_uuid IN {in_list(instance_ids)}"))
    statements.extend(select_table("nova_api", "request_specs", f"instance_uuid IN {in_list(instance_ids)}"))
    statements.extend(select_table("nova_api", "build_requests", f"instance_uuid IN {in_list(instance_ids)}"))
    return service_sql("nova_api", statements)


def build_nova_cell_sql(ids, db_name="nova"):
    instance_ids = ids.get("instances", [])
    volume_ids = ids.get("volumes", [])
    statements = []
    statements.extend(select_table(db_name, "instances", f"uuid IN {in_list(instance_ids)}"))
    statements.extend(select_table(db_name, "instance_extra", f"instance_uuid IN {in_list(instance_ids)}"))
    statements.extend(
        select_table(db_name, "instance_info_caches", f"instance_uuid IN {in_list(instance_ids)}")
    )
    statements.extend(select_table(db_name, "instance_metadata", f"instance_uuid IN {in_list(instance_ids)}"))
    statements.extend(
        select_table(db_name, "instance_system_metadata", f"instance_uuid IN {in_list(instance_ids)}")
    )
    statements.extend(
        select_table(
            db_name,
            "block_device_mapping",
            f"instance_uuid IN {in_list(instance_ids)} OR volume_id IN {in_list(volume_ids)}",
        )
    )
    statements.extend(select_table(db_name, "virtual_interfaces", f"instance_uuid IN {in_list(instance_ids)}"))
    statements.extend(select_table(db_name, "migrations", f"instance_uuid IN {in_list(instance_ids)}"))
    return service_sql("nova_cell", statements)


BUILDERS = {
    "keystone": build_keystone_sql,
    "neutron": build_neutron_sql,
    "cinder": build_cinder_sql,
    "nova_api": build_nova_api_sql,
    "nova_cell": build_nova_cell_sql,
}


def build_query_pack(db_import_plan, nova_cell_db_name="nova"):
    ids = resources(db_import_plan)
    services = []
    for service_name in SERVICE_ORDER:
        if service_name == "nova_cell":
            sql = build_nova_cell_sql(ids, nova_cell_db_name)
        else:
            sql = BUILDERS[service_name](ids)
        service = {
            "name": service_name,
            "sql_file": f"queries/{service_name}.sql",
            "rows_file": f"rows/{service_name}.tsv",
            "sql": sql,
        }
        services.append(service)
    services_by_name = {service["name"]: service for service in services}
    return {
        "schema_version": "openstack-rehome-source-db-row-query-pack/v1alpha1",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "resource_ids": ids,
        "services": services,
        "services_by_name": services_by_name,
    }


def write_query_pack(query_pack, out_dir):
    out_dir = pathlib.Path(out_dir)
    queries_dir = out_dir / "queries"
    rows_dir = out_dir / "rows"
    queries_dir.mkdir(parents=True, exist_ok=True)
    rows_dir.mkdir(parents=True, exist_ok=True)

    manifest_services = []
    for service in query_pack["services"]:
        sql_path = out_dir / service["sql_file"]
        sql_path.write_text(service["sql"], encoding="utf-8")
        manifest_services.append(
            {
                "name": service["name"],
                "sql_file": service["sql_file"],
                "rows_file": service["rows_file"],
            }
        )

    manifest = {
        "schema_version": query_pack["schema_version"],
        "generated_at_utc": query_pack["generated_at_utc"],
        "resource_ids": query_pack["resource_ids"],
        "services": manifest_services,
    }
    write_json(out_dir / "source-db-row-query-manifest.json", manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db-import-plan-json", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--nova-cell-db-name", default="nova")
    args = parser.parse_args()

    plan = read_json(args.db_import_plan_json)
    query_pack = build_query_pack(plan, args.nova_cell_db_name)
    write_query_pack(query_pack, args.out_dir)


if __name__ == "__main__":
    main()
