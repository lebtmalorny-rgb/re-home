#!/usr/bin/env python3
"""Build the protected target-capability input from live command records."""

from copy import deepcopy
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, Mapping, Optional, Sequence


SCHEMA_VERSION = "openstack-rehome-target-capability-input/v1alpha1"
CANONICAL_RELEASE = "2025.1"
SERVICE_REPOSITORIES = {
    "nova_api": "quay.io/openstack.kolla/nova-api",
    "neutron_server": "quay.io/openstack.kolla/neutron-server",
    "cinder_api": "quay.io/openstack.kolla/cinder-api",
    "glance_api": "quay.io/openstack.kolla/glance-api",
}
MANAGEMENT_FIELDS = (
    "nova_api_db_version",
    "nova_cell_db_version",
    "neutron_heads",
    "cinder_db_version",
    "glance_db_version",
)
IMAGE_SERVICES = ("nova_api", "neutron_server", "cinder_api", "glance_api")
RUNTIME_IDS = (
    "runtime-target-virsh-version",
    "runtime-target-domcapabilities",
    "runtime-target-qemu-machine-help",
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_EPOXY_TAGS = {"2025.1-ubuntu-noble", "2025.1-rocky-9"}
_SENSITIVE_NAME = re.compile(
    r"(?:password|passwd|pwd|token|secret|private[_-]?key|authorization|auth)",
    re.IGNORECASE,
)
_SENSITIVE_CONTENT = re.compile(
    r"(?:password\s*[=:]|passwd\s*[=:]|token\s*[=:]|secret\s*[=:]|"
    r"authorization\s*:|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"<\s*(?:secret|auth|authentication|password|token|private[_-]?key)(?:\s|>|/))",
    re.IGNORECASE,
)
_MAX_SAFE_STDOUT = 1024 * 1024
_MIGRATION_MAX_AGE = timedelta(hours=24)


def _command_record(value: object, expected_id: Optional[str] = None) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"capability record {expected_id} is missing")
    required = {"evidence_id", "command", "returncode", "stdout", "stderr"}
    if (
        set(value) != required
        or not isinstance(value.get("evidence_id"), str)
        or not value["evidence_id"]
        or (expected_id is not None and value.get("evidence_id") != expected_id)
    ):
        raise ValueError(f"capability record {expected_id} is invalid")
    command = value.get("command")
    returncode = value.get("returncode")
    if (
        not isinstance(command, list)
        or not command
        or not all(isinstance(item, str) and item for item in command)
        or not isinstance(returncode, int)
        or isinstance(returncode, bool)
        or not isinstance(value.get("stdout"), str)
        or not isinstance(value.get("stderr"), str)
    ):
        raise ValueError(f"capability record {expected_id} is invalid")
    return deepcopy(dict(value))


def _status(record: Mapping[str, Any]) -> Dict[str, Any]:
    stderr = record["stderr"]
    payload = {
        "returncode": record["returncode"],
        "status": "PASS" if record["returncode"] == 0 else "BLOCKED",
        "failure_class": None if record["returncode"] == 0 else "command-failed",
    }
    if record["returncode"] != 0:
        payload["stdout_sha256"] = _sha256(record["stdout"])
    if stderr:
        payload["stderr_sha256"] = hashlib.sha256(stderr.encode("utf-8")).hexdigest()
    return payload


def _sanitize_argv(argv: Sequence[str]) -> list[str]:
    sanitized = []
    redact_next = False
    for raw in argv:
        value = str(raw)
        if redact_next:
            sanitized.append("[REDACTED]")
            redact_next = False
            continue
        if value.startswith("-") and _SENSITIVE_NAME.search(value):
            if "=" in value:
                key = value.split("=", 1)[0]
                sanitized.append(f"{key}=[REDACTED]")
            else:
                sanitized.append(value)
                redact_next = True
            continue
        if "=" in value:
            key = value.split("=", 1)[0]
            if _SENSITIVE_NAME.search(key):
                sanitized.append(f"{key}=[REDACTED]")
                continue
        if _SENSITIVE_CONTENT.search(value):
            prefix = value.split(":", 1)[0] if ":" in value else "value"
            sanitized.append(f"{prefix}:[REDACTED]")
            continue
        sanitized.append(value)
    return sanitized


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_stdout(value: str, evidence_id: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > _MAX_SAFE_STDOUT
        or "\x00" in value
        or _SENSITIVE_CONTENT.search(value)
    ):
        raise ValueError(f"safe stdout is invalid for {evidence_id}")
    return value


def _normalized_record(record: Mapping[str, Any], *, safe_stdout: bool) -> Dict[str, Any]:
    common = {
        "evidence_id": record["evidence_id"],
        "command": _sanitize_argv(record["command"]),
        "returncode": record["returncode"],
    }
    if record["returncode"] == 0 and safe_stdout:
        return {
            **common,
            "stdout": _safe_stdout(record["stdout"], record["evidence_id"]),
            "stderr_sha256": _sha256(record["stderr"]),
        }
    return {
        **common,
        "failure_class": "command-failed",
        "stdout_sha256": _sha256(record["stdout"]),
        "stderr_sha256": _sha256(record["stderr"]),
    }


def _release_from_image(service: str, inspect: Mapping[str, Any]) -> Optional[str]:
    config = inspect.get("Config")
    if not isinstance(config, Mapping):
        return None
    image = config.get("Image")
    labels = config.get("Labels")
    if not isinstance(image, str) or not isinstance(labels, Mapping):
        return None
    repository = SERVICE_REPOSITORIES[service]
    if not image.startswith(repository + ":"):
        return None
    tag = image[len(repository) + 1:]
    if tag not in _EPOXY_TAGS:
        return None
    label_release = labels.get("openstack_release")
    if not isinstance(label_release, str) or not label_release:
        label_release = labels.get("org.opencontainers.image.version")
    if not isinstance(label_release, str) or not label_release:
        return None
    if label_release != CANONICAL_RELEASE:
        return None
    return CANONICAL_RELEASE


def _online_evidence(
    value: object,
    manage_outputs: Mapping[str, Any],
    *,
    now: Optional[datetime] = None,
) -> tuple[Dict[str, Dict[str, Any]], bool]:
    if value is None:
        return {}, False
    expected_envelope = {"schema_version", "timestamp", "database_revisions", "services"}
    if not isinstance(value, Mapping) or set(value) != expected_envelope:
        raise ValueError("online migration evidence is invalid")
    if value.get("schema_version") != "openstack-rehome-online-migration-evidence/v1alpha1":
        raise ValueError("online migration evidence is invalid")
    timestamp = value.get("timestamp")
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        raise ValueError("online migration evidence is invalid") from None
    if parsed.tzinfo is None:
        raise ValueError("online migration evidence is invalid")
    current = now or datetime.now(timezone.utc)
    recent = timedelta(0) <= current - parsed.astimezone(timezone.utc) <= _MIGRATION_MAX_AGE
    revisions = value.get("database_revisions")
    if not isinstance(revisions, Mapping) or set(revisions) != set(MANAGEMENT_FIELDS):
        raise ValueError("online migration evidence is invalid")
    normalized_live = {
        field: (
            [line for line in manage_outputs[field].splitlines() if line]
            if field == "neutron_heads" and isinstance(manage_outputs.get(field), str)
            else manage_outputs.get(field).strip()
            if isinstance(manage_outputs.get(field), str)
            else None
        )
        for field in MANAGEMENT_FIELDS
    }
    revisions_match = dict(revisions) == normalized_live
    services = value.get("services")
    if not isinstance(services, Mapping) or set(services) != {"nova", "cinder"}:
        raise ValueError("online migration evidence is invalid")
    result = {}
    completed = True
    for service, artifact in services.items():
        expected = {"evidence_id", "returncode", "command", "completed"}
        command = [f"{service}-manage", "db", "online_data_migrations"]
        if (
            not isinstance(artifact, Mapping)
            or set(artifact) != expected
            or artifact.get("command") != command
            or not isinstance(artifact.get("evidence_id"), str)
            or not artifact["evidence_id"]
            or not isinstance(artifact.get("returncode"), int)
            or isinstance(artifact.get("returncode"), bool)
            or not isinstance(artifact.get("completed"), bool)
        ):
            raise ValueError("online migration evidence is invalid")
        completed = completed and artifact["completed"] and artifact["returncode"] == 0
        result[str(service)] = {
            "evidence_id": artifact["evidence_id"],
            "timestamp": timestamp,
            "returncode": artifact["returncode"],
            "command": deepcopy(command),
        }
    return result, recent and revisions_match and completed


def build_target_capability(
    management_records: Mapping[str, object],
    image_records: Mapping[str, object],
    runtime_records: Mapping[str, object],
    online_migration_evidence: object = None,
    *,
    virsh_argv: Sequence[str] = ("virsh",),
    qemu_argv: Sequence[str] = ("qemu-system-x86_64",),
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Normalize live records without ever parsing stdout from failed probes."""
    management = {
        field: _command_record(management_records.get(field))
        for field in MANAGEMENT_FIELDS
    }

    images = {}
    image_releases = set()
    image_digests = set()
    vanilla_images = True
    statuses = {}
    capability_evidence = []

    manage_outputs: Dict[str, Any] = {}
    for field, record in management.items():
        manage_outputs[field] = (
            _safe_stdout(record["stdout"], record["evidence_id"])
            if record["returncode"] == 0 else None
        )
    all_management_passed = all(record["returncode"] == 0 for record in management.values())
    for record in management.values():
        statuses[record["evidence_id"]] = _status(record)
        if record["returncode"] == 0:
            capability_evidence.append({
                "evidence_id": record["evidence_id"], "kind": "runtime-command",
                "side": "target", "service": "target-profile",
                "command": _sanitize_argv(record["command"]),
            })

    for service in IMAGE_SERVICES:
        raw = image_records.get(service)
        record = _command_record(raw)
        statuses[record["evidence_id"]] = _status(record)
        if record["returncode"] != 0:
            vanilla_images = False
            continue
        try:
            values = json.loads(record["stdout"])
        except json.JSONDecodeError:
            values = None
        if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], Mapping):
            statuses[record["evidence_id"]]["status"] = "BLOCKED"
            statuses[record["evidence_id"]]["failure_class"] = "invalid-json"
            vanilla_images = False
            continue
        inspect = deepcopy(dict(values[0]))
        release = _release_from_image(service, inspect)
        config = inspect.get("Config")
        reference = config.get("Image") if isinstance(config, Mapping) else None
        if release is None:
            vanilla_images = False
        else:
            image_releases.add(release)
        digest = inspect.get("Image")
        if (
            not isinstance(reference, str)
            or not isinstance(digest, str)
            or _DIGEST.fullmatch(digest) is None
        ):
            vanilla_images = False
        elif digest in image_digests:
            vanilla_images = False
        else:
            image_digests.add(digest)
        images[service] = {
            "Config": {"Image": reference},
            "Image": digest,
        }
        capability_evidence.append({
            "evidence_id": record["evidence_id"], "kind": "runtime-command",
            "side": "target", "service": "target-profile",
            "command": _sanitize_argv(record["command"]),
        })

    normalized_runtime = {}
    for evidence_id in RUNTIME_IDS:
        record = _command_record(runtime_records.get(evidence_id), evidence_id)
        statuses[evidence_id] = _status(record)
        normalized_runtime[evidence_id] = _normalized_record(record, safe_stdout=True)
        capability_evidence.append({
            "evidence_id": evidence_id, "kind": "runtime-command",
            "side": "target", "service": "runtime-capabilities",
            "command": _sanitize_argv(record["command"]),
        })

    migrations, authoritative_db_match = _online_evidence(
        online_migration_evidence, manage_outputs, now=now
    )

    canonical_profile = (
        all_management_passed
        and authoritative_db_match
        and len(images) == len(IMAGE_SERVICES)
        and image_releases == {CANONICAL_RELEASE}
        and vanilla_images
    )
    manage_outputs["release"] = CANONICAL_RELEASE if canonical_profile else None
    manage_outputs["distribution"] = "vanilla" if canonical_profile else None
    manage_outputs["online_migration_evidence"] = migrations
    for service, artifact in migrations.items():
        capability_evidence.append({
            "evidence_id": artifact["evidence_id"], "kind": "runtime-command",
            "side": "target", "service": "target-profile",
            "command": deepcopy(artifact["command"]),
        })

    return {
        "schema_version": SCHEMA_VERSION,
        "target_manage_outputs": manage_outputs,
        "target_image_inspects": images,
        "target_runtime_outputs": normalized_runtime,
        "target_virsh_argv": _sanitize_argv([str(value) for value in virsh_argv]),
        "target_qemu_argv": _sanitize_argv([str(value) for value in qemu_argv]),
        "schema_capabilities": {
            "nova": {
                "release": manage_outputs["release"],
                "distribution": manage_outputs["distribution"],
            },
            "target-probe-statuses": deepcopy(statuses),
        },
        "capability_evidence": capability_evidence,
        "probe_statuses": statuses,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    records_source = parser.add_mutually_exclusive_group(required=True)
    records_source.add_argument("--records", type=Path)
    records_source.add_argument("--records-stdin", action="store_true")
    parser.add_argument("--online-migration-evidence", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    raw_records = (
        sys.stdin.read(8 * 1024 * 1024 + 1)
        if args.records_stdin else args.records.read_text(encoding="utf-8")
    )
    if len(raw_records.encode("utf-8")) > 8 * 1024 * 1024:
        raise ValueError("capability records exceed safety bound")
    records = json.loads(raw_records)
    migrations = (
        json.loads(args.online_migration_evidence.read_text(encoding="utf-8"))
        if args.online_migration_evidence is not None else None
    )
    result = build_target_capability(
        records["management"], records["images"], records["runtime"], migrations,
        virsh_argv=records["target_virsh_argv"],
        qemu_argv=records["target_qemu_argv"],
    )
    payload = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    descriptor = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
