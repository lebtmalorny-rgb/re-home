#!/usr/bin/env python3
"""Atomically validate and freeze controller-owned protected inputs."""

import argparse
import errno
import json
import os
from pathlib import Path
import re
import shutil
import stat
from typing import Dict, Mapping, Optional, Sequence


_KEY = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_BOUNDS = {
    "hmac": (16, 4096),
    "token": (1, 64 * 1024),
    "json": (2, 8 * 1024 * 1024),
    "probe": (2, 1024 * 1024),
    "cinder": (2, 8 * 1024 * 1024),
    "migration": (2, 1024 * 1024),
    "clouds": (2, 1024 * 1024),
    "passwords": (2, 1024 * 1024),
}


def _entry(value: object) -> Mapping[str, object]:
    required = {"key", "path", "type", "required"}
    if (
        not isinstance(value, Mapping)
        or set(value) != required
        or not isinstance(value.get("key"), str)
        or _KEY.fullmatch(value["key"]) is None
        or not isinstance(value.get("path"), str)
        or value.get("type") not in _BOUNDS
        or not isinstance(value.get("required"), bool)
    ):
        raise ValueError("protected input manifest is invalid")
    if value["required"] and not value["path"]:
        raise ValueError("required protected input path is empty")
    return value


def _read_owned(path: Path, kind: str, expected_uid: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if error.errno == errno.ELOOP or path.is_symlink():
            raise ValueError("protected input symlink is forbidden") from None
        raise ValueError("protected input cannot be opened") from None
    try:
        before = os.fstat(descriptor)
        minimum, maximum = _BOUNDS[kind]
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("protected input is not a regular file")
        if before.st_uid != expected_uid:
            raise ValueError("protected input owner is invalid")
        if stat.S_IMODE(before.st_mode) != 0o600:
            raise ValueError("protected input mode is invalid")
        if before.st_size < minimum or before.st_size > maximum:
            raise ValueError("protected input size is invalid")
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise ValueError("protected input changed while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError("protected input changed while reading")
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise ValueError("protected input changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def freeze_protected_inputs(
    entries: Sequence[object],
    destination: Path,
    *,
    expected_uid: Optional[int] = None,
) -> Dict[str, str]:
    """Freeze each path from a single validated fd into a new 0700 boundary."""
    if not isinstance(entries, (list, tuple)) or not entries:
        raise ValueError("protected input manifest is invalid")
    normalized = [_entry(value) for value in entries]
    keys = [str(value["key"]) for value in normalized]
    if len(keys) != len(set(keys)):
        raise ValueError("protected input key is duplicated")
    uid = os.geteuid() if expected_uid is None else expected_uid
    destination = Path(destination)
    try:
        destination.mkdir(mode=0o700)
    except FileExistsError:
        raise ValueError("frozen protected boundary already exists") from None
    outputs: Dict[str, str] = {}
    try:
        for value in normalized:
            source = str(value["path"])
            if not source:
                continue
            payload = _read_owned(Path(source), str(value["type"]), uid)
            target = destination / str(value["key"])
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
            outputs[str(value["key"])] = str(target)
        return outputs
    except BaseException:
        shutil.rmtree(destination)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest-json", required=True)
    parser.add_argument("--destination", required=True, type=Path)
    args = parser.parse_args()
    entries = json.loads(args.manifest_json)
    outputs = freeze_protected_inputs(entries, args.destination)
    print(json.dumps(outputs, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
