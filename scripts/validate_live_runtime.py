#!/usr/bin/env python3
"""Validate a fetched runtime artifact with the assembler's exact contract."""

import argparse
from pathlib import Path

from assemble_live_discovery import _bundle, _validate_evidence_closure, _validate_role


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", required=True, type=Path)
    args = parser.parse_args()
    collectors, checks, bundle = _bundle(args.runtime)
    _validate_role(collectors, "runtime")
    _validate_evidence_closure(collectors, checks, bundle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
