#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import pathlib


SERVICE_SQL_FILES = {
    "keystone": "10-keystone-projects-users-optional.sql",
    "neutron": "20-neutron-networks-ports-sg.sql",
    "cinder": "30-cinder-volumes-attachments.sql",
    "nova_api": "40-nova-api-instance-mappings-request-specs.sql",
    "nova_cell": "50-nova-cell-instances-bdm-info-cache.sql",
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


def parse_information_schema(path):
    columns = {}
    in_columns = False
    for raw_line in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
        if not raw_line:
            continue
        if raw_line.startswith("SERVICE:"):
            in_columns = False
            continue
        if raw_line == "SECTION:COLUMNS":
            in_columns = True
            continue
        if raw_line.startswith("SECTION:"):
            in_columns = False
            continue
        if not in_columns:
            continue
        parts = raw_line.split("\t")
        if len(parts) < 8:
            continue
        schema, table, ordinal, name, column_type, nullable, default, extra = parts[:8]
        key = (schema, table)
        columns.setdefault(key, []).append(
            {
                "name": name,
                "ordinal": int(ordinal),
                "type": column_type,
                "nullable": nullable,
                "default": default,
                "extra": extra,
            }
        )
    for key in list(columns.keys()):
        columns[key] = sorted(columns[key], key=lambda column: column["ordinal"])
    return columns


def parse_row_sections(path):
    sections = []
    current = None
    for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
        if line.startswith("BEGIN "):
            full_name = line.removeprefix("BEGIN ")
            schema, table = full_name.split(".", 1)
            current = {"schema": schema, "table": table, "rows": []}
            continue
        if line.startswith("END "):
            if current:
                sections.append(current)
                current = None
            continue
        if current is not None:
            current["rows"].append(line.split("\t"))
    return sections


def load_all_row_sections(manifest, root_dir):
    root_dir = pathlib.Path(root_dir)
    by_service = []
    for service in manifest.get("services", []):
        rows_path = root_dir / service["rows_file"]
        by_service.append(
            {
                "service": service["name"],
                "rows_file": service["rows_file"],
                "sections": parse_row_sections(rows_path),
            }
        )
    return by_service


def sql_identifier(name):
    return "`" + name.replace("`", "``") + "`"


def sql_value(value):
    if value == "NULL":
        return "NULL"
    return "'" + value.replace("\\", "\\\\").replace("'", "''") + "'"


def insert_statement(schema, table, columns, row):
    column_names = [column["name"] for column in columns]
    left = ", ".join(sql_identifier(name) for name in column_names)
    right = ", ".join(sql_value(value) for value in row)
    return f"INSERT INTO {sql_identifier(schema)}.{sql_identifier(table)} ({left}) VALUES ({right});"


def auto_increment_columns(columns):
    return [column["name"] for column in columns if "auto_increment" in (column.get("extra") or "")]


def render_service_sql(service_name, sections, schema):
    lines = [
        "-- DO NOT EXECUTE: target DB import draft for review only.",
        "-- This file is generated from source DB rows and information_schema.",
        "-- Review auto-increment IDs, foreign keys, target row existence and service-specific invariants.",
        "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DO NOT EXECUTE: review and remove this hard-stop manually';",
        f"-- Service: {service_name}",
        "",
    ]
    issues = []
    row_count = 0
    table_count = 0

    for section in sections:
        key = (section["schema"], section["table"])
        columns = schema.get(key)
        table_count += 1
        lines.append(f"-- BEGIN {section['schema']}.{section['table']}")
        if not columns:
            issue = f"missing schema columns for {section['schema']}.{section['table']}"
            issues.append(issue)
            lines.append(f"-- REVIEW_REQUIRED: {issue}")
            lines.append(f"-- END {section['schema']}.{section['table']}")
            lines.append("")
            continue

        auto_columns = auto_increment_columns(columns)
        if auto_columns:
            lines.append(f"-- REVIEW_REQUIRED: auto_increment columns: {', '.join(auto_columns)}")

        for row in section["rows"]:
            if len(row) != len(columns):
                issue = (
                    f"row width mismatch for {section['schema']}.{section['table']}: "
                    f"{len(row)} values for {len(columns)} columns"
                )
                issues.append(issue)
                lines.append(f"-- REVIEW_REQUIRED: {issue}")
                lines.append("-- " + json.dumps(row, ensure_ascii=False))
                continue
            lines.append(insert_statement(section["schema"], section["table"], columns, row))
            row_count += 1
        lines.append(f"-- END {section['schema']}.{section['table']}")
        lines.append("")

    return "\n".join(lines), {
        "service": service_name,
        "table_count": table_count,
        "row_count": row_count,
        "issues": issues,
    }


def write_draft_files(row_sections, schema, out_dir):
    out_dir = pathlib.Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    files = []
    for service in row_sections:
        file_name = SERVICE_SQL_FILES.get(service["service"], f"{service['service']}.sql")
        content, service_summary = render_service_sql(service["service"], service["sections"], schema)
        path = out_dir / file_name
        path.write_text(content, encoding="utf-8")
        files.append(
            {
                **service_summary,
                "path": str(path),
                "file": file_name,
            }
        )
    return {
        "schema_version": "openstack-rehome-target-sql-draft/v1alpha1",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": files,
        "total_rows": sum(item["row_count"] for item in files),
        "total_issues": sum(len(item["issues"]) for item in files),
        "hard_stop": "Every generated SQL file starts with SIGNAL SQLSTATE and must be manually reviewed.",
    }


def render_markdown(summary):
    lines = [
        "# Target SQL Import Draft Summary",
        "",
        "Generated files are review drafts. Each SQL file starts with a hard-stop.",
        "",
        f"- Total rows represented: `{summary['total_rows']}`",
        f"- Total issues: `{summary['total_issues']}`",
        "",
        "## Files",
        "",
    ]
    for item in summary["files"]:
        lines.extend(
            [
                f"### {item['file']}",
                "",
                f"- Service: `{item['service']}`",
                f"- Tables: `{item['table_count']}`",
                f"- Rows: `{item['row_count']}`",
                f"- Issues: `{len(item['issues'])}`",
                "",
            ]
        )
        for issue in item["issues"]:
            lines.append(f"- `{issue}`")
        if item["issues"]:
            lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-db-rows-dir", required=True)
    parser.add_argument("--source-information-schema", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--out-json", required=True)
    parser.add_argument("--out-yaml")
    parser.add_argument("--out-md")
    args = parser.parse_args()

    rows_root = pathlib.Path(args.source_db_rows_dir)
    manifest = read_json(rows_root / "source-db-row-query-manifest.json")
    schema = parse_information_schema(args.source_information_schema)
    row_sections = load_all_row_sections(manifest, rows_root)
    summary = write_draft_files(row_sections, schema, args.out_dir)
    write_json(args.out_json, summary)
    if args.out_yaml:
        write_yaml(args.out_yaml, summary)
    if args.out_md:
        pathlib.Path(args.out_md).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(args.out_md).write_text(render_markdown(summary), encoding="utf-8")


if __name__ == "__main__":
    main()
