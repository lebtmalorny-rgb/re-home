#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import pathlib
import re
import shutil


FORBIDDEN_STATEMENT_RE = re.compile(
    r"^(ALTER|CREATE|DELETE|DROP|GRANT|REPLACE|REVOKE|SET|TRUNCATE|UPDATE)\b",
    re.IGNORECASE,
)
INSERT_RE = re.compile(r"^INSERT INTO `([^`]+)`\.`([^`]+)` \((.*)\) VALUES \((.*)\);$")


def write_json(path, data):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def generated_at_utc():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def strip_hard_stop_text(text):
    stripped_lines = []
    removed = 0
    for line in text.splitlines():
        if "DO NOT EXECUTE:" in line or line.strip().startswith("SIGNAL SQLSTATE '45000'"):
            removed += 1
            continue
        stripped_lines.append(line)
    return "\n".join(stripped_lines).rstrip() + "\n", removed


def validate_sql_text(path, text):
    issues = []
    insert_count = 0
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("--"):
            continue
        if "DO NOT EXECUTE" in line or line.startswith("SIGNAL SQLSTATE"):
            issues.append(f"{path}:{line_no}: hard-stop remains")
            continue
        if FORBIDDEN_STATEMENT_RE.match(line):
            issues.append(f"{path}:{line_no}: forbidden statement: {line.split(None, 1)[0].upper()}")
            continue
        if line.upper().startswith("INSERT INTO "):
            insert_count += 1
            continue
        issues.append(f"{path}:{line_no}: unsupported statement")
    return issues, insert_count


def replace_sql_literals(text, literal_replacements):
    replacements_applied = 0
    for old, new in sorted((literal_replacements or {}).items()):
        old_literal = sql_literal(old)
        new_literal = sql_literal(new)
        count = text.count(old_literal)
        if count:
            text = text.replace(old_literal, new_literal)
            replacements_applied += count
    return text, replacements_applied


def split_sql_csv(text):
    items = []
    current = []
    in_quote = False
    i = 0
    while i < len(text):
        char = text[i]
        if char == "'" and not in_quote:
            in_quote = True
            current.append(char)
            i += 1
            continue
        if char == "'" and in_quote:
            current.append(char)
            if i + 1 < len(text) and text[i + 1] == "'":
                current.append(text[i + 1])
                i += 2
                continue
            in_quote = False
            i += 1
            continue
        if char == "\\" and in_quote and i + 1 < len(text):
            current.append(char)
            current.append(text[i + 1])
            i += 2
            continue
        if char == "," and not in_quote:
            items.append("".join(current).strip())
            current = []
            i += 1
            continue
        current.append(char)
        i += 1
    items.append("".join(current).strip())
    return items


def unquote_identifier(identifier):
    identifier = identifier.strip()
    if identifier.startswith("`") and identifier.endswith("`"):
        return identifier[1:-1].replace("``", "`")
    return identifier


def replace_table_column_literals(text, column_replacements):
    if not column_replacements:
        return text, 0

    changed_lines = []
    replacements_applied = 0
    for line in text.splitlines():
        match = INSERT_RE.match(line.strip())
        if not match:
            changed_lines.append(line)
            continue
        schema, table, column_text, value_text = match.groups()
        columns = [unquote_identifier(item) for item in split_sql_csv(column_text)]
        values = split_sql_csv(value_text)
        if len(columns) != len(values):
            changed_lines.append(line)
            continue
        changed = False
        for index, column in enumerate(columns):
            replacement = column_replacements.get((schema, table, column))
            if replacement is None:
                continue
            new_value = sql_literal(replacement)
            if values[index] != new_value:
                values[index] = new_value
                replacements_applied += 1
                changed = True
        if not changed:
            changed_lines.append(line)
            continue
        rendered_columns = ", ".join(sql_identifier(column) for column in columns)
        rendered_values = ", ".join(values)
        changed_lines.append(
            f"INSERT INTO {sql_identifier(schema)}.{sql_identifier(table)} ({rendered_columns}) "
            f"VALUES ({rendered_values});"
        )
    return "\n".join(changed_lines).rstrip() + "\n", replacements_applied


def sql_identifier(name):
    return "`" + str(name).replace("`", "``") + "`"


def sql_literal(value):
    return "'" + str(value).replace("\\", "\\\\").replace("'", "''") + "'"


def prepare_import(
    source_dir,
    out_dir,
    strip_hard_stop=False,
    skip_files=None,
    literal_replacements=None,
    column_replacements=None,
):
    source_dir = pathlib.Path(source_dir)
    out_dir = pathlib.Path(out_dir)
    skip_files = set(skip_files or [])

    if not source_dir.is_dir():
        raise SystemExit(f"source SQL directory does not exist: {source_dir}")

    sql_files = sorted(source_dir.glob("*.sql"))
    if not sql_files:
        raise SystemExit(f"no SQL files found in {source_dir}")

    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "schema_version": "openstack-rehome-target-sql-import/v1alpha1",
        "generated_at_utc": generated_at_utc(),
        "source_dir": str(source_dir),
        "out_dir": str(out_dir),
        "strip_hard_stop": bool(strip_hard_stop),
        "files": [],
        "summary": {
            "files_seen": len(sql_files),
            "files_prepared": 0,
            "files_skipped": 0,
            "hard_stop_lines_removed": 0,
            "insert_statements": 0,
            "literal_replacements": 0,
            "column_replacements": 0,
            "issues": 0,
        },
        "issues": [],
    }

    for sql_file in sql_files:
        if sql_file.name in skip_files:
            manifest["files"].append({"file": sql_file.name, "action": "skipped"})
            manifest["summary"]["files_skipped"] += 1
            continue

        text = sql_file.read_text(encoding="utf-8")
        if ("DO NOT EXECUTE" in text or "SIGNAL SQLSTATE" in text) and not strip_hard_stop:
            raise SystemExit(f"{sql_file.name}: hard-stop present; use --strip-hard-stop only after review")

        removed = 0
        if strip_hard_stop:
            text, removed = strip_hard_stop_text(text)

        replacements_applied = 0
        if literal_replacements:
            text, replacements_applied = replace_sql_literals(text, literal_replacements)

        column_replacements_applied = 0
        if column_replacements:
            text, column_replacements_applied = replace_table_column_literals(text, column_replacements)

        issues, insert_count = validate_sql_text(sql_file.name, text)
        if issues:
            manifest["issues"].extend(issues)
            manifest["summary"]["issues"] += len(issues)
            raise SystemExit("forbidden or unsupported SQL found:\n" + "\n".join(issues))

        dest = out_dir / sql_file.name
        dest.write_text(text, encoding="utf-8")
        manifest["files"].append(
            {
                "file": sql_file.name,
                "action": "prepared",
                "hard_stop_lines_removed": removed,
                "insert_statements": insert_count,
                "literal_replacements": replacements_applied,
                "column_replacements": column_replacements_applied,
            }
        )
        manifest["summary"]["files_prepared"] += 1
        manifest["summary"]["hard_stop_lines_removed"] += removed
        manifest["summary"]["insert_statements"] += insert_count
        manifest["summary"]["literal_replacements"] += replacements_applied
        manifest["summary"]["column_replacements"] += column_replacements_applied

    write_json(out_dir / "manifest.json", manifest)
    return manifest


def parse_args():
    parser = argparse.ArgumentParser(description="Prepare reviewed target SQL import files.")
    parser.add_argument("--source-dir", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--strip-hard-stop", action="store_true")
    parser.add_argument("--skip-file", action="append", default=[])
    parser.add_argument(
        "--replace-literal",
        action="append",
        default=[],
        help="Replace one SQL string literal value, formatted as OLD=NEW.",
    )
    parser.add_argument(
        "--replace-column",
        action="append",
        default=[],
        help="Replace a generated INSERT column value, formatted as SCHEMA.TABLE.COLUMN=NEW.",
    )
    parser.add_argument("--manifest-json")
    return parser.parse_args()


def main():
    args = parse_args()
    literal_replacements = {}
    for item in args.replace_literal:
        if "=" not in item:
            raise SystemExit(f"invalid --replace-literal value: {item}")
        old, new = item.split("=", 1)
        literal_replacements[old] = new
    column_replacements = {}
    for item in args.replace_column:
        if "=" not in item:
            raise SystemExit(f"invalid --replace-column value: {item}")
        left, new = item.split("=", 1)
        parts = left.split(".")
        if len(parts) != 3:
            raise SystemExit(f"invalid --replace-column target: {left}")
        column_replacements[tuple(parts)] = new
    manifest = prepare_import(
        pathlib.Path(args.source_dir),
        pathlib.Path(args.out_dir),
        strip_hard_stop=args.strip_hard_stop,
        skip_files=set(args.skip_file),
        literal_replacements=literal_replacements,
        column_replacements=column_replacements,
    )
    if args.manifest_json:
        write_json(args.manifest_json, manifest)


if __name__ == "__main__":
    main()
