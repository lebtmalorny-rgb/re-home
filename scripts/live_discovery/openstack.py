from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .contract import CheckResult, CollectorResult, ResourceNode
from .runner import ProbeFailed


CANONICAL_RELEASE = "2025.1"
CANONICAL_DISTRIBUTION = "vanilla"
ONLINE_MIGRATION_EVIDENCE_MAX_AGE = timedelta(hours=24)
ONLINE_MIGRATION_EVIDENCE_FUTURE_TOLERANCE = timedelta(minutes=5)
ONLINE_MIGRATION_SERVICES = ("nova", "cinder")
ONLINE_MIGRATION_ARTIFACT_FIELDS = (
    "evidence_id",
    "command",
    "timestamp",
    "returncode",
)


def _has_output_format(arguments: Sequence[str]) -> bool:
    return any(
        argument in {"-f", "--format"}
        or argument.startswith("-f=")
        or argument.startswith("--format=")
        for argument in arguments
    )


def _invalid_json_failure(evidence) -> ProbeFailed:
    failure = ProbeFailed(evidence)
    failure.reason = "invalid-json"
    failure.args = (
        f"probe {evidence.evidence_id!r} failed: invalid-json",
    )
    return failure


def _sanitized_json_evidence(evidence: object) -> Dict[str, Any]:
    raw = evidence.to_dict()
    sanitized = {
        key: deepcopy(raw[key])
        for key in ("evidence_id", "id", "argv", "returncode")
        if key in raw
    }
    if "stdout" in raw:
        sanitized["stdout"] = "[REDACTED]"
    if "stderr" in raw:
        sanitized["stderr"] = "[REDACTED]"
    return sanitized


def _image_reference(inspect: object) -> Optional[str]:
    if isinstance(inspect, str) and inspect:
        return inspect
    if not isinstance(inspect, Mapping):
        return None
    config = inspect.get("Config")
    if isinstance(config, Mapping):
        configured_image = config.get("Image")
        if isinstance(configured_image, str) and configured_image:
            return configured_image
    repo_tags = inspect.get("RepoTags")
    if isinstance(repo_tags, list) and repo_tags and isinstance(repo_tags[0], str):
        return repo_tags[0]
    return None


def _parse_timestamp(value: object) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _sanitized_online_migration_evidence(
    evidence: object,
) -> Dict[str, Dict[str, Any]]:
    if not isinstance(evidence, Mapping):
        return {}
    sanitized: Dict[str, Dict[str, Any]] = {}
    for service in ONLINE_MIGRATION_SERVICES:
        artifact = evidence.get(service)
        if not isinstance(artifact, Mapping):
            continue
        sanitized[service] = {
            field: deepcopy(artifact[field])
            for field in ONLINE_MIGRATION_ARTIFACT_FIELDS
            if field in artifact
        }
    return sanitized


def _online_migration_check(
    service: str,
    artifact: object,
    now: datetime,
) -> Tuple[CheckResult, Optional[str], Optional[str]]:
    check_id = f"target.{service}.online-data-migrations"
    if not isinstance(artifact, Mapping):
        reason = f"{service} online migration evidence missing"
        return CheckResult(check_id, "UNKNOWN", reason), reason, None

    expected_command = [f"{service}-manage", "db", "online_data_migrations"]
    if artifact.get("command") != expected_command:
        reason = f"{service} online migration evidence command invalid"
        return CheckResult(check_id, "UNKNOWN", reason), reason, None

    timestamp = _parse_timestamp(artifact.get("timestamp"))
    if timestamp is None:
        reason = f"{service} online migration evidence timestamp invalid"
        return CheckResult(check_id, "UNKNOWN", reason), reason, None
    if now - timestamp > ONLINE_MIGRATION_EVIDENCE_MAX_AGE:
        reason = f"{service} online migration evidence stale"
        return CheckResult(check_id, "UNKNOWN", reason), reason, None
    if timestamp - now > ONLINE_MIGRATION_EVIDENCE_FUTURE_TOLERANCE:
        reason = f"{service} online migration evidence timestamp is in the future"
        return CheckResult(check_id, "UNKNOWN", reason), reason, None

    returncode = artifact.get("returncode")
    if isinstance(returncode, int) and not isinstance(returncode, bool) and returncode != 0:
        reason = f"{service} online migration evidence returncode is not 0"
        return CheckResult(check_id, "BLOCKED", reason), None, reason
    if not isinstance(returncode, int) or isinstance(returncode, bool):
        reason = f"{service} online migration evidence returncode missing"
        return CheckResult(check_id, "UNKNOWN", reason), reason, None

    evidence_id = artifact.get("evidence_id")
    evidence_ids = [evidence_id] if isinstance(evidence_id, str) else []
    return (
        CheckResult(
            check_id,
            "PASS",
            f"{service} online migration completion evidence is fresh",
            evidence_ids=evidence_ids,
        ),
        None,
        None,
    )


class OpenStackClient:
    def __init__(self, runner, cloud: str, container: str, clouds_path: str) -> None:
        self.runner = runner
        self.cloud = cloud
        self.container = container
        self.clouds_path = clouds_path

    def json(
        self,
        command: Sequence[object],
        evidence_id: str,
        required: bool = True,
    ) -> Tuple[Any, Dict[str, Any]]:
        arguments: List[str] = [str(value) for value in command]
        if not _has_output_format(arguments):
            arguments.extend(["-f", "json"])
        argv = [
            "docker",
            "exec",
            "-e",
            f"OS_CLIENT_CONFIG_FILE={self.clouds_path}",
            self.container,
            "openstack",
            "--os-cloud",
            self.cloud,
            *arguments,
        ]
        evidence = self.runner.run(argv, evidence_id)
        try:
            payload = json.loads(evidence.stdout)
        except (json.JSONDecodeError, TypeError) as error:
            raise _invalid_json_failure(evidence) from error
        return payload, _sanitized_json_evidence(evidence)


def collect_target_profile(
    client: OpenStackClient,
    manage_outputs: Mapping[str, Any],
    image_inspects: Mapping[str, Any],
) -> CollectorResult:
    del client
    result = CollectorResult(service="target-profile", side="target")
    outputs = deepcopy(dict(manage_outputs))
    online_evidence = _sanitized_online_migration_evidence(
        outputs.get("online_migration_evidence")
    )

    container_images: Dict[str, str] = {}
    container_image_digests: Dict[str, str] = {}
    for service, inspect in image_inspects.items():
        reference = _image_reference(inspect)
        if reference is not None:
            container_images[str(service)] = reference
        if isinstance(inspect, Mapping):
            digest = inspect.get("Image")
            if isinstance(digest, str) and digest:
                container_image_digests[str(service)] = digest

    profile = {
        key: outputs.get(key)
        for key in (
            "release",
            "distribution",
            "nova_api_db_version",
            "nova_cell_db_version",
            "neutron_heads",
            "cinder_db_version",
            "glance_db_version",
        )
    }
    profile["container_images"] = container_images
    profile["container_image_digests"] = container_image_digests
    profile["online_migration_evidence"] = deepcopy(dict(online_evidence))

    for field in (
        "nova_api_db_version",
        "nova_cell_db_version",
        "neutron_heads",
        "cinder_db_version",
        "glance_db_version",
    ):
        if profile[field] in (None, "", []):
            result.unknowns.append(f"target profile fact {field} missing")
    if not image_inspects:
        result.unknowns.append("target container image inspections missing")
    for service in image_inspects:
        if str(service) not in container_images:
            result.unknowns.append(f"target container image {service} missing")

    evidence_ids = []
    for artifact in online_evidence.values():
        if isinstance(artifact, Mapping):
            copied_artifact = deepcopy(dict(artifact))
            result.evidence.append(copied_artifact)
            evidence_id = artifact.get("evidence_id")
            if isinstance(evidence_id, str):
                evidence_ids.append(evidence_id)

    result.nodes.append(
        ResourceNode(
            kind="openstack_target_profile",
            id="vanilla-openstack-2025.1-epoxy",
            side="target",
            facts=profile,
            evidence_ids=evidence_ids,
        )
    )

    canonical_checks = (
        ("distribution", CANONICAL_DISTRIBUTION),
        ("release", CANONICAL_RELEASE),
    )
    for field, expected in canonical_checks:
        actual = profile[field]
        if actual == expected:
            result.checks.append(
                CheckResult(
                    f"target.profile.{field}",
                    "PASS",
                    f"target {field} is canonical {expected}",
                )
            )
        else:
            reason = f"target {field} is {actual!r}, expected {expected!r}"
            result.checks.append(
                CheckResult(f"target.profile.{field}", "BLOCKED", reason)
            )
            result.blockers.append(reason)

    now = datetime.now(timezone.utc)
    for service in ONLINE_MIGRATION_SERVICES:
        check, unknown, blocker = _online_migration_check(
            service,
            online_evidence.get(service),
            now,
        )
        result.checks.append(check)
        if unknown is not None:
            result.unknowns.append(unknown)
        if blocker is not None:
            result.blockers.append(blocker)

    return result
