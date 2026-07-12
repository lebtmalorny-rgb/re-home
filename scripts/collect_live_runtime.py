#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

from live_discovery.runner import ReadOnlyRunner
from live_discovery.runtime import FixtureRuntimeRunner, collect_runtime


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect read-only compute runtime facts")
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--side", choices=("source", "target"), default="source")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--network-backend", choices=("ovs", "ovn"), default="ovs")
    parser.add_argument("--virsh-argv", nargs="+", default=["virsh"])
    args = parser.parse_args()

    if args.fixture:
        fixture = json.loads(args.fixture.read_text(encoding="utf-8"))
        fixture["side"] = args.side
        runner = FixtureRuntimeRunner(fixture)
        virsh_argv = fixture.get("virsh_argv", args.virsh_argv)
        network_backend = fixture.get("network_backend", args.network_backend)
    else:
        runner = ReadOnlyRunner()
        runner.side = args.side
        virsh_argv = args.virsh_argv
        network_backend = args.network_backend

    result = collect_runtime(runner, virsh_argv, network_backend)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0 if not result.blockers else 2


if __name__ == "__main__":
    raise SystemExit(main())
