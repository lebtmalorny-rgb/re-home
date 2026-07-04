#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import pathlib


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


def scan_rows(rows_file, service):
    conflicts = []
    current_table = None
    for index, line in enumerate(rows_file.read_text(encoding="utf-8").splitlines(), start=1):
        if line.startswith("BEGIN "):
            current_table = line.removeprefix("BEGIN ")
            continue
        if line.startswith("END "):
            current_table = None
            continue
        if current_table and line:
            conflicts.append(
                {
                    "service": service,
                    "table": current_table,
                    "rows_file": str(rows_file),
                    "line": index,
                    "sample": line[:240],
                }
            )
    return conflicts


def build_report(root_dir):
    root_dir = pathlib.Path(root_dir)
    rows_dir = root_dir / "rows"
    rc_files = sorted(rows_dir.glob("*.rc"))
    rows_files = sorted(rows_dir.glob("*.tsv"))

    query_failures = []
    for rc_file in rc_files:
        rc = rc_file.read_text(encoding="utf-8").strip()
        if rc != "0":
            query_failures.append({"service": rc_file.stem, "rc": rc, "rc_file": str(rc_file)})

    conflicts = []
    for rows_file in rows_files:
        conflicts.extend(scan_rows(rows_file, rows_file.stem))

    return {
        "schema_version": "openstack-rehome-target-preimport-guard/v1alpha1",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "passed": not conflicts and not query_failures,
        "summary": {
            "services_checked": len(rows_files),
            "query_failures": len(query_failures),
            "conflicting_rows": len(conflicts),
        },
        "query_failures": query_failures,
        "conflicts": conflicts,
        "hard_stop": "Do not import SQL while this guard report has passed=false.",
    }


def render_markdown(report):
    lines = [
        "# Target Pre-Import Guard Report",
        "",
        f"- Passed: `{str(report['passed']).lower()}`",
        f"- Services checked: `{report['summary']['services_checked']}`",
        f"- Query failures: `{report['summary']['query_failures']}`",
        f"- Conflicting rows: `{report['summary']['conflicting_rows']}`",
        "",
    ]
    if report["conflicts"]:
        lines.extend(["## Conflicts", ""])
        for conflict in report["conflicts"]:
            lines.append(
                f"- `{conflict['service']}` `{conflict['table']}` line `{conflict['line']}`"
            )
    if report["query_failures"]:
        lines.extend(["", "## Query Failures", ""])
        for failure in report["query_failures"]:
            lines.append(f"- `{failure['service']}` rc `{failure['rc']}`")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-db-rows-dir", required=True)
    parser.add_argument("--out-json", required=True)
    parser.add_argument("--out-yaml")
    parser.add_argument("--out-md")
    parser.add_argument("--fail-on-conflict", action="store_true")
    args = parser.parse_args()

    report = build_report(args.target_db_rows_dir)
    write_json(args.out_json, report)
    if args.out_yaml:
        write_yaml(args.out_yaml, report)
    if args.out_md:
        pathlib.Path(args.out_md).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(args.out_md).write_text(render_markdown(report), encoding="utf-8")
    if args.fail_on_conflict and not report["passed"]:
        raise SystemExit("target pre-import guard failed: existing target rows or query failures found")


if __name__ == "__main__":
    main()
