#!/usr/bin/env python3
"""Resolve a Nova host to a sanitized cell schema from live DB evidence."""

import argparse
import json
from pathlib import Path
import re
import sys
import uuid

from .nova import cell_database_schema


SCHEMA_VERSION = "openstack-rehome-source-cell-mapping/v1alpha1"
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.:@+-]{1,255}$")


def _sql_literal(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 255
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError("cell mapping host is invalid")
    return "'" + value.replace("\\", "\\\\").replace("'", "''") + "'"


def build_cell_mapping_query(host: str) -> str:
    literal = _sql_literal(host)
    return (
        "SELECT cm.id, cm.uuid, cm.name, cm.database_connection "
        "FROM nova_api.cell_mappings AS cm "
        "JOIN nova_api.host_mappings AS hm ON hm.cell_id = cm.id "
        f"WHERE hm.host = {literal} ORDER BY cm.id;"
    )


def parse_cell_mapping_tsv(value: str, host: str) -> dict:
    if not isinstance(value, str) or len(value.encode("utf-8")) > 1024 * 1024:
        raise ValueError("cell mapping evidence is invalid")
    rows = [line.split("\t") for line in value.splitlines() if line]
    if len(rows) != 1 or len(rows[0]) != 4:
        raise ValueError("cell mapping evidence must contain exactly one row")
    raw_id, raw_uuid, name, connection = rows[0]
    try:
        cell_id = int(raw_id)
        canonical_uuid = str(uuid.UUID(raw_uuid))
    except (ValueError, AttributeError):
        raise ValueError("cell mapping identity is invalid") from None
    if cell_id < 0 or canonical_uuid != raw_uuid or _SAFE_NAME.fullmatch(name) is None:
        raise ValueError("cell mapping identity is invalid")
    schema = cell_database_schema(connection)
    if schema is None:
        raise ValueError("cell mapping database schema is invalid")
    if not isinstance(host, str) or not host:
        raise ValueError("cell mapping host is invalid")
    return {
        "schema_version": SCHEMA_VERSION,
        "evidence_id": f"nova-source-cell-mapping-{host}",
        "host": host,
        "id": cell_id,
        "uuid": canonical_uuid,
        "name": name,
        "database_schema": schema,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Resolve a live Nova cell")
    subparsers = parser.add_subparsers(dest="action", required=True)
    query = subparsers.add_parser("query")
    query.add_argument("--host", required=True)
    normalize = subparsers.add_parser("normalize")
    normalize.add_argument("--host", required=True)
    normalize.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.action == "query":
        print(build_cell_mapping_query(args.host))
        return 0
    result = parse_cell_mapping_tsv(sys.stdin.read(), args.host)
    args.out.write_text(
        json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    args.out.chmod(0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
