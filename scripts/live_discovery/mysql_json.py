import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import uuid
from typing import Optional, Sequence

from .runner import MutationRejected, validate_select_only_sql


_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def validate_identifier(value: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"invalid identifier: {value!r}")
    return value


def _quote_identifier(value: str) -> str:
    return f"`{validate_identifier(value)}`"


def uuid_in(column: str, values: Sequence[str]) -> str:
    quoted_values = []
    for value in values:
        try:
            parsed = uuid.UUID(value)
        except (AttributeError, TypeError, ValueError) as error:
            raise ValueError(f"invalid UUID: {value!r}") from error
        quoted_values.append(f"'{parsed}'")
    if not quoted_values:
        raise ValueError("UUID filter requires at least one value")
    return f"{_quote_identifier(column)} IN ({', '.join(quoted_values)})"


def build_json_row_query(
    schema: str,
    table: str,
    columns: Sequence[str],
    where_sql: str,
) -> str:
    if not columns:
        raise ValueError("JSON row query requires at least one column")
    row_members = ", ".join(
        f"'{validate_identifier(column)}', {_quote_identifier(column)}"
        for column in columns
    )
    statement = (
        "SELECT JSON_OBJECT(\n"
        f"  '_schema', '{validate_identifier(schema)}',\n"
        f"  '_table', '{validate_identifier(table)}',\n"
        f"  'row', JSON_OBJECT({row_members})\n"
        ")\n"
        f"FROM {_quote_identifier(schema)}.{_quote_identifier(table)}\n"
        f"WHERE {where_sql};"
    )
    return validate_select_only_sql(statement)


def verify_plan_marker(plan_path: Path, marker_path: Path) -> None:
    plan = json.loads(Path(plan_path).read_text(encoding="utf-8"))
    marker = json.loads(Path(marker_path).read_text(encoding="utf-8"))
    if (
        not isinstance(plan, dict)
        or set(plan) != {"schema_version", "side", "queries", "binding_sha256"}
        or plan.get("schema_version") != "openstack-rehome-db-query-plan/v1alpha1"
        or not isinstance(plan.get("queries"), list)
        or not isinstance(marker, dict)
        or set(marker) != {"schema_version", "side", "plan_sha256", "binding_sha256", "query_ids"}
        or marker.get("schema_version") != "openstack-rehome-verified-plan/v1alpha1"
    ):
        raise ValueError("verified plan marker schema is invalid")
    canonical = json.dumps(plan, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    query_ids = [query.get("query_id") for query in plan["queries"] if isinstance(query, dict)]
    if (
        marker["side"] != plan["side"]
        or marker["binding_sha256"] != plan["binding_sha256"]
        or marker["plan_sha256"] != digest
        or marker["query_ids"] != query_ids
    ):
        raise ValueError("verified plan marker does not match query plan")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate live discovery JSONL SQL")
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--validate-sql", type=Path, metavar="FILE")
    inputs.add_argument("--verify-plan-marker", type=Path, nargs=2, metavar=("PLAN", "MARKER"))
    args = parser.parse_args(argv)
    try:
        if args.validate_sql is not None:
            validate_select_only_sql(args.validate_sql.read_text(encoding="utf-8"))
        else:
            verify_plan_marker(*args.verify_plan_marker)
    except (MutationRejected, OSError, ValueError, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print("SELECT_ONLY_OK" if args.validate_sql is not None else "VERIFIED_PLAN_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
