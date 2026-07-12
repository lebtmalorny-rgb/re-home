#!/usr/bin/env python3
"""Build a sanitized acquisition sidecar for one scoped DB query."""

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import sys


SCHEMA_VERSION = "openstack-rehome-db-query-evidence/v1alpha1"
_QUERY_ID = re.compile(r"^[0-9]{4}-[a-z_][a-z0-9_]*-[a-z_][a-z0-9_]*$")


def build_db_evidence(record):
    expected = {"side", "query_id", "returncode", "observed_at", "stderr"}
    if not isinstance(record, dict) or set(record) != expected:
        raise ValueError("DB evidence record is invalid")
    side = record["side"]
    query_id = record["query_id"]
    returncode = record["returncode"]
    observed_at = record["observed_at"]
    stderr = record["stderr"]
    try:
        parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        raise ValueError("DB evidence timestamp is invalid") from None
    if (
        side not in {"source", "target"}
        or not isinstance(query_id, str)
        or _QUERY_ID.fullmatch(query_id) is None
        or not isinstance(returncode, int)
        or isinstance(returncode, bool)
        or parsed.tzinfo is None
        or not isinstance(stderr, str)
        or len(stderr.encode("utf-8")) > 8 * 1024 * 1024
    ):
        raise ValueError("DB evidence record is invalid")
    return {
        "schema_version": SCHEMA_VERSION,
        "query_id": query_id,
        "evidence_id": f"{side}-db:{query_id}",
        "observed_at": observed_at,
        "returncode": returncode,
        "failure_class": None if returncode == 0 else "command-failed",
        "stderr_sha256": hashlib.sha256(stderr.encode("utf-8")).hexdigest(),
        "raw_artifact_ref": f"protected://{side}/db-stderr/{query_id}.stderr",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build sanitized DB evidence")
    parser.add_argument("--record-stdin", action="store_true", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        value = sys.stdin.read(8 * 1024 * 1024 + 1)
        if len(value.encode("utf-8")) > 8 * 1024 * 1024:
            raise ValueError("DB evidence input is too large")
        result = build_db_evidence(json.loads(value))
        args.out.write_text(
            json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        args.out.chmod(0o640)
        return 0
    except (OSError, ValueError, json.JSONDecodeError):
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
