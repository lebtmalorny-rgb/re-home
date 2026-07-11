import argparse
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


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate live discovery JSONL SQL")
    parser.add_argument("--validate-sql", type=Path, required=True, metavar="FILE")
    args = parser.parse_args(argv)
    try:
        validate_select_only_sql(args.validate_sql.read_text(encoding="utf-8"))
    except (MutationRejected, OSError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print("SELECT_ONLY_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
