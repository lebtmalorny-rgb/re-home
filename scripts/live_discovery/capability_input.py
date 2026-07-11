#!/usr/bin/env python3
"""Build the protected target-capability input from live command records."""

from copy import deepcopy
import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence


SCHEMA_VERSION = "openstack-rehome-target-capability-input/v1alpha1"
CANONICAL_RELEASE = "2025.1"
VANILLA_REPOSITORY = "quay.io/openstack.kolla/"
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
APPROVED_MANAGEMENT_OUTPUTS = {
    "nova_api_db_version": "b30f573d3377",
    "nova_cell_db_version": "b30f573d3377",
    "cinder_db_version": "2025.1",
    "glance_db_version": "2025.1",
}
APPROVED_NEUTRON_HEADS = {"2025.1-expand", "2025.1-contract"}


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
    if stderr:
        payload["stderr_sha256"] = hashlib.sha256(stderr.encode("utf-8")).hexdigest()
    return payload


def _release_from_image(inspect: Mapping[str, Any]) -> Optional[str]:
    config = inspect.get("Config")
    if not isinstance(config, Mapping):
        return None
    image = config.get("Image")
    labels = config.get("Labels")
    if not isinstance(image, str) or not isinstance(labels, Mapping):
        return None
    tag = image.rsplit(":", 1)[-1].split("-", 1)[0] if ":" in image else None
    label_release = labels.get("openstack_release")
    if not isinstance(label_release, str) or not label_release:
        label_release = labels.get("org.opencontainers.image.version")
    if not isinstance(label_release, str) or not label_release:
        return None
    label_release = label_release.split("-", 1)[0]
    if tag is None or label_release != tag:
        return None
    return tag


def _online_evidence(value: object) -> Dict[str, Dict[str, Any]]:
    if value is None:
        return {}
    if not isinstance(value, Mapping) or not set(value).issubset({"nova", "cinder"}):
        raise ValueError("online migration evidence is invalid")
    result = {}
    for service, artifact in value.items():
        expected = {"evidence_id", "timestamp", "returncode", "command"}
        command = [f"{service}-manage", "db", "online_data_migrations"]
        if (
            not isinstance(artifact, Mapping)
            or set(artifact) != expected
            or artifact.get("command") != command
            or not isinstance(artifact.get("evidence_id"), str)
            or not artifact["evidence_id"]
            or not isinstance(artifact.get("timestamp"), str)
            or not isinstance(artifact.get("returncode"), int)
            or isinstance(artifact.get("returncode"), bool)
        ):
            raise ValueError("online migration evidence is invalid")
        result[str(service)] = deepcopy(dict(artifact))
    return result


def _management_proves_epoxy(outputs: Mapping[str, Any]) -> bool:
    if any(
        not isinstance(outputs.get(field), str)
        or outputs[field].strip() != expected
        for field, expected in APPROVED_MANAGEMENT_OUTPUTS.items()
    ):
        return False
    neutron = outputs.get("neutron_heads")
    if not isinstance(neutron, str):
        return False
    try:
        parsed = json.loads(neutron)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, list) and all(isinstance(item, str) for item in parsed):
        heads = set(parsed)
    else:
        heads = {
            token
            for token in neutron.replace(",", " ").split()
            if token.startswith("2025.1-")
        }
    return heads == APPROVED_NEUTRON_HEADS


def build_target_capability(
    management_records: Mapping[str, object],
    image_records: Mapping[str, object],
    runtime_records: Mapping[str, object],
    online_migration_evidence: object = None,
    *,
    virsh_argv: Sequence[str] = ("virsh",),
    qemu_argv: Sequence[str] = ("qemu-system-x86_64",),
) -> Dict[str, Any]:
    """Normalize live records without ever parsing stdout from failed probes."""
    management = {
        field: _command_record(management_records.get(field))
        for field in MANAGEMENT_FIELDS
    }

    images = {}
    image_releases = set()
    vanilla_images = True
    statuses = {}
    capability_evidence = []

    manage_outputs: Dict[str, Any] = {
        field: record["stdout"] if record["returncode"] == 0 else None
        for field, record in management.items()
    }
    all_management_passed = all(record["returncode"] == 0 for record in management.values())
    for record in management.values():
        statuses[record["evidence_id"]] = _status(record)
        if record["returncode"] == 0:
            capability_evidence.append({
                "evidence_id": record["evidence_id"], "kind": "runtime-command",
                "side": "target", "service": "target-profile",
                "command": deepcopy(record["command"]),
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
        release = _release_from_image(inspect)
        config = inspect.get("Config")
        reference = config.get("Image") if isinstance(config, Mapping) else None
        if release is None:
            vanilla_images = False
        else:
            image_releases.add(release)
        if not isinstance(reference, str) or not reference.startswith(VANILLA_REPOSITORY):
            vanilla_images = False
        images[service] = {
            "Config": {"Image": reference},
            "Image": inspect.get("Image"),
        }
        capability_evidence.append({
            "evidence_id": record["evidence_id"], "kind": "runtime-command",
            "side": "target", "service": "target-profile",
            "command": deepcopy(record["command"]),
        })

    normalized_runtime = {}
    for evidence_id in RUNTIME_IDS:
        record = _command_record(runtime_records.get(evidence_id), evidence_id)
        statuses[evidence_id] = _status(record)
        normalized_runtime[evidence_id] = record
        capability_evidence.append({
            "evidence_id": evidence_id, "kind": "runtime-command",
            "side": "target", "service": "runtime-capabilities",
            "command": deepcopy(record["command"]),
        })

    canonical_profile = (
        all_management_passed
        and _management_proves_epoxy(manage_outputs)
        and len(images) == len(IMAGE_SERVICES)
        and image_releases == {CANONICAL_RELEASE}
        and vanilla_images
    )
    manage_outputs["release"] = CANONICAL_RELEASE if canonical_profile else None
    manage_outputs["distribution"] = "vanilla" if canonical_profile else None
    migrations = _online_evidence(online_migration_evidence)
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
        "target_virsh_argv": [str(value) for value in virsh_argv],
        "target_qemu_argv": [str(value) for value in qemu_argv],
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
    parser.add_argument("--records", required=True, type=Path)
    parser.add_argument("--online-migration-evidence", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    records = json.loads(args.records.read_text(encoding="utf-8"))
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
