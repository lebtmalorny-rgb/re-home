"""Build the fixed, read-only information_schema query pack."""

import argparse
import json
import re
import sys
from typing import Any, Dict, Sequence


QUERY_PACK_VERSION = "openstack-rehome-schema-query-pack/v1alpha1"
_SCHEMA_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_MAX_SCHEMAS = 64


def validate_schema_identifier(value: object) -> str:
    """Return one reviewed MySQL schema identifier or fail closed."""
    if not isinstance(value, str) or _SCHEMA_IDENTIFIER.fullmatch(value) is None:
        raise ValueError("invalid schema identifier")
    return value


def sql_string_literal(value: object) -> str:
    """Quote a validated identifier as a SQL string literal.

    Validation deliberately precedes quoting.  This helper is not a general SQL
    escaping API and must not be used for arbitrary input.
    """
    return "'" + validate_schema_identifier(value) + "'"


def build_schema_query_pack(database_names: Sequence[object]) -> Dict[str, Any]:
    if (
        not isinstance(database_names, (list, tuple))
        or not database_names
        or len(database_names) > _MAX_SCHEMAS
    ):
        raise ValueError("schema list is invalid")
    schemas = sorted(validate_schema_identifier(value) for value in database_names)
    if len(schemas) != len(set(schemas)):
        raise ValueError("schema identifier is duplicated")
    literals = ", ".join(sql_string_literal(value) for value in schemas)

    columns = (
        "SELECT TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION, COLUMN_NAME, "
        "COLUMN_TYPE, IS_NULLABLE, IFNULL(COLUMN_DEFAULT, '\\\\N'), "
        "IFNULL(EXTRA, '\\\\N') FROM information_schema.COLUMNS "
        f"WHERE TABLE_SCHEMA IN ({literals}) "
        "ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION;"
    )
    statistics = (
        "SELECT TABLE_SCHEMA, TABLE_NAME, INDEX_NAME, NON_UNIQUE, "
        "SEQ_IN_INDEX, COLUMN_NAME, INDEX_TYPE "
        "FROM information_schema.STATISTICS "
        f"WHERE TABLE_SCHEMA IN ({literals}) "
        "ORDER BY TABLE_SCHEMA, TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX;"
    )
    foreign_keys = (
        "SELECT k.CONSTRAINT_SCHEMA, k.TABLE_NAME, k.CONSTRAINT_NAME, "
        "k.ORDINAL_POSITION, k.COLUMN_NAME, k.REFERENCED_TABLE_SCHEMA, "
        "k.REFERENCED_TABLE_NAME, k.REFERENCED_COLUMN_NAME, "
        "r.UPDATE_RULE, r.DELETE_RULE "
        "FROM information_schema.KEY_COLUMN_USAGE AS k "
        "INNER JOIN information_schema.REFERENTIAL_CONSTRAINTS AS r "
        "ON r.CONSTRAINT_SCHEMA = k.CONSTRAINT_SCHEMA "
        "AND r.CONSTRAINT_NAME = k.CONSTRAINT_NAME "
        "AND r.TABLE_NAME = k.TABLE_NAME "
        f"WHERE k.CONSTRAINT_SCHEMA IN ({literals}) "
        "AND k.REFERENCED_TABLE_SCHEMA IS NOT NULL "
        "ORDER BY k.CONSTRAINT_SCHEMA, k.TABLE_NAME, k.CONSTRAINT_NAME, "
        "k.ORDINAL_POSITION;"
    )
    return {
        "schema_version": QUERY_PACK_VERSION,
        "queries": [
            {"section": "COLUMNS", "sql": columns},
            {"section": "STATISTICS", "sql": statistics},
            {"section": "FOREIGN_KEYS", "sql": foreign_keys},
        ],
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Render strict information_schema SQL")
    parser.add_argument("--databases-json", required=True)
    args = parser.parse_args(argv)
    try:
        database_names = json.loads(args.databases_json)
        pack = build_schema_query_pack(database_names)
    except (TypeError, ValueError, json.JSONDecodeError):
        print("schema query input rejected", file=sys.stderr)
        return 2
    print(json.dumps(pack, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
