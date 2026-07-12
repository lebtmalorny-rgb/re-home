#!/usr/bin/env python3
"""Persistent sibling run-owner lifecycle with token-checked cleanup."""

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
from typing import Dict


SCHEMA = "openstack-rehome-run-owner/v1alpha1"


def _payload(run_id: str, token: str, status: str) -> Dict[str, str]:
    if not run_id or not token or status not in {"running", "completed"}:
        raise ValueError("run ownership identity is invalid")
    return {
        "schema_version": SCHEMA,
        "run_id": run_id,
        "owner_token": token,
        "status": status,
    }


def _write_exclusive(path: Path, payload: Dict[str, str]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")


def acquire_owner(owner: Path, run_id: str, token: str) -> None:
    owner = Path(owner)
    created = False
    try:
        payload = _payload(run_id, token, "running")
        owner.mkdir(mode=0o700)
        created = True
        _write_exclusive(owner / "run-owner.json", payload)
    except FileExistsError:
        raise ValueError("run owner already exists") from None
    except BaseException:
        if created:
            shutil.rmtree(owner)
        raise


def _read(owner: Path) -> Dict[str, str]:
    marker = Path(owner) / "run-owner.json"
    if marker.is_symlink():
        raise ValueError("run owner marker is unsafe")
    descriptor = os.open(marker, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size <= 0
            or metadata.st_size > 4096
        ):
            raise ValueError("run owner marker is unsafe")
        raw = os.read(descriptor, metadata.st_size + 1)
    finally:
        os.close(descriptor)
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("run owner marker is invalid") from None
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version", "run_id", "owner_token", "status"
    } or payload.get("schema_version") != SCHEMA:
        raise ValueError("run owner marker is invalid")
    return payload


def verify_owner(owner: Path, run_id: str, token: str) -> str:
    payload = _read(owner)
    if payload.get("run_id") != run_id or payload.get("owner_token") != token:
        raise ValueError("run ownership does not match")
    status = payload.get("status")
    if status not in {"running", "completed"}:
        raise ValueError("run owner marker is invalid")
    return str(status)


def cleanup_owner(owner: Path, run_id: str, token: str) -> None:
    if verify_owner(owner, run_id, token) != "running":
        raise ValueError("completed run owner cannot be removed")
    shutil.rmtree(owner)


def complete_owner(owner: Path, run_id: str, token: str) -> None:
    owner = Path(owner)
    if verify_owner(owner, run_id, token) != "running":
        raise ValueError("run owner is not running")
    protected = owner / "protected"
    if protected.exists():
        if protected.is_symlink() or not protected.is_dir():
            raise ValueError("frozen protected boundary is unsafe")
        shutil.rmtree(protected)
    completed = owner / "completed.json"
    _write_exclusive(completed, {
        "schema_version": "openstack-rehome-run-completion/v1alpha1",
        "run_id": run_id,
        "status": "completed",
    })
    temporary = owner / ".run-owner.completed"
    _write_exclusive(temporary, _payload(run_id, token, "completed"))
    os.replace(temporary, owner / "run-owner.json")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("acquire", "verify", "cleanup", "complete"))
    parser.add_argument("--owner", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--token", required=True)
    args = parser.parse_args()
    if args.action == "acquire":
        acquire_owner(args.owner, args.run_id, args.token)
    elif args.action == "verify":
        if verify_owner(args.owner, args.run_id, args.token) != "running":
            raise ValueError("run owner is not running")
    elif args.action == "cleanup":
        cleanup_owner(args.owner, args.run_id, args.token)
    else:
        complete_owner(args.owner, args.run_id, args.token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
