#!/usr/bin/env python3
"""Derive the source distribution profile from live service image evidence."""

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import sys


SCHEMA_VERSION = "openstack-rehome-source-capability-input/v1alpha1"
CANONICAL_PROFILE = "keystack-2025.1"
SERVICES = ("nova_api", "neutron_server", "cinder_api", "glance_api")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _record(value, service):
    expected = {"evidence_id", "command", "returncode", "stdout", "stderr"}
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or not isinstance(value.get("evidence_id"), str)
        or not value["evidence_id"]
        or not isinstance(value.get("command"), list)
        or not value["command"]
        or not all(isinstance(item, str) and item for item in value["command"])
        or not isinstance(value.get("returncode"), int)
        or isinstance(value.get("returncode"), bool)
        or not isinstance(value.get("stdout"), str)
        or not isinstance(value.get("stderr"), str)
    ):
        raise ValueError(f"source image record is invalid: {service}")
    if value["returncode"] != 0:
        raise ValueError(f"source image probe failed: {service}")
    try:
        payload = json.loads(value["stdout"])
    except json.JSONDecodeError:
        raise ValueError(f"source image JSON is invalid: {service}") from None
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        raise ValueError(f"source image JSON is invalid: {service}")
    return value, payload[0]


def build_source_profile(image_records):
    if not isinstance(image_records, dict) or set(image_records) != set(SERVICES):
        raise ValueError("source image evidence set is invalid")
    evidence = []
    signals = {}
    proven = True
    for service in SERVICES:
        record, inspect = _record(image_records[service], service)
        config = inspect.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        image = config.get("Image") if isinstance(config, dict) else None
        digest = inspect.get("Image")
        vendor = labels.get("org.opencontainers.image.vendor") if isinstance(labels, dict) else None
        release = labels.get("openstack_release") if isinstance(labels, dict) else None
        valid = (
            isinstance(image, str)
            and image
            and isinstance(vendor, str)
            and vendor.casefold() == "keystack"
            and release == "2025.1"
            and isinstance(digest, str)
            and _DIGEST.fullmatch(digest) is not None
        )
        proven = proven and valid
        signals[service] = {
            "vendor": "Keystack" if valid else None,
            "release": release if release == "2025.1" else None,
            "image_digest": digest if isinstance(digest, str) and _DIGEST.fullmatch(digest) else None,
            "image_reference_sha256": (
                hashlib.sha256(image.encode("utf-8")).hexdigest()
                if isinstance(image, str) and image else None
            ),
        }
        evidence.append({
            "evidence_id": record["evidence_id"],
            "kind": "runtime-command",
            "side": "source",
            "service": "source-profile",
            "command": deepcopy(record["command"]),
        })
    return {
        "schema_version": SCHEMA_VERSION,
        "schema_capabilities": {
            "source-profile": {
                "status": "PASS" if proven else "UNKNOWN",
                "profile": CANONICAL_PROFILE if proven else None,
                "reason": (
                    "live service images prove Keystack 2025.1"
                    if proven
                    else "exact Keystack 2025.1 distribution is not proven by live images"
                ),
                "release": "2025.1" if proven else None,
                "distribution": "keystack" if proven else None,
                "evidence_ids": [item["evidence_id"] for item in evidence],
                "signals": signals,
            },
        },
        "capability_evidence": evidence,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build source profile evidence")
    parser.add_argument("--records-stdin", action="store_true", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        records = json.load(sys.stdin)
        result = build_source_profile(records)
        args.out.write_text(
            json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        args.out.chmod(0o600)
        return 0
    except (OSError, ValueError, json.JSONDecodeError):
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
