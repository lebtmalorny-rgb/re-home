"""Deterministic, independently sanitized live-discovery artifact rendering."""

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any, Mapping

from .graph import _SENSITIVE_KEY, _SENSITIVE_VALUE, validate_graph


_GRAPH_KEYS = frozenset({"schema_version", "collectors", "nodes", "edges", "checks", "assembly_checks", "graph_sha256"})
_VERDICT_KEYS = frozenset({"schema_version", "graph_sha256", "verdict", "exit_code", "counts", "reasons", "checks"})
_CAPABILITY_KEYS = frozenset({"schema_version", "services"})
_MAPPING_KEYS = frozenset({"schema_version", "source_profile", "target_profile", "tables", "blockers"})
_UUID_FILTER_KEYS = frozenset({"schema_version", "source", "target"})
_EVIDENCE_INDEX_KEYS = frozenset({"schema_version", "entries"})
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_MAX_DEPTH = 20
_MAX_NODES = 100_000
_MAX_STRING = 64 * 1024


def _sanitize(value: object) -> object:
    budget = [_MAX_NODES]

    def walk(item: object, depth: int) -> object:
        budget[0] -= 1
        if budget[0] < 0 or depth > _MAX_DEPTH:
            raise ValueError("artifact exceeds safety bounds")
        if item is None or isinstance(item, (bool, int)):
            return item
        if isinstance(item, float):
            if item != item or item in {float("inf"), float("-inf")}:
                raise ValueError("artifact contains non-finite number")
            return item
        if isinstance(item, str):
            if len(item) > _MAX_STRING or "\x00" in item:
                raise ValueError("artifact string exceeds safety bounds")
            return "[REDACTED]" if _SENSITIVE_VALUE.search(item) else item
        if isinstance(item, (list, tuple)):
            return [walk(child, depth + 1) for child in item]
        if isinstance(item, Mapping):
            normalized = {}
            for raw_key, child in item.items():
                if not isinstance(raw_key, str) or not raw_key or len(raw_key) > 512 or "\x00" in raw_key:
                    raise ValueError("artifact key is invalid")
                normalized[raw_key] = (
                    "[REDACTED]" if _SENSITIVE_KEY.search(raw_key)
                    else walk(child, depth + 1)
                )
            return {key: normalized[key] for key in sorted(normalized)}
        raise ValueError("artifact contains unsupported value")

    return walk(value, 0)


def render_json(value: object) -> str:
    """Return canonical JSON after a fresh secret-sanitization pass."""
    return json.dumps(_sanitize(value), ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def _yaml_scalar(value: object) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(value, ensure_ascii=False)


def _yaml_lines(value: object, indent: int = 0):
    prefix = " " * indent
    if isinstance(value, Mapping):
        if not value:
            return [prefix + "{}"]
        lines = []
        for key in sorted(value):
            child = value[key]
            safe_key = json.dumps(key, ensure_ascii=False)
            if isinstance(child, (Mapping, list)) and child:
                lines.append(f"{prefix}{safe_key}:")
                lines.extend(_yaml_lines(child, indent + 2))
            else:
                rendered = "[]" if isinstance(child, list) else "{}" if isinstance(child, Mapping) else _yaml_scalar(child)
                lines.append(f"{prefix}{safe_key}: {rendered}")
        return lines
    if isinstance(value, list):
        if not value:
            return [prefix + "[]"]
        lines = []
        for child in value:
            if isinstance(child, (Mapping, list)) and child:
                lines.append(prefix + "-")
                lines.extend(_yaml_lines(child, indent + 2))
            else:
                rendered = "[]" if isinstance(child, list) else "{}" if isinstance(child, Mapping) else _yaml_scalar(child)
                lines.append(prefix + "- " + rendered)
        return lines
    return [prefix + _yaml_scalar(value)]


def render_yaml(value: object) -> str:
    return "\n".join(_yaml_lines(_sanitize(value))) + "\n"


def render_markdown(graph: Mapping[str, Any], verdict: Mapping[str, Any]) -> str:
    graph = _sanitize(graph)
    verdict = _sanitize(verdict)
    counts = Counter(
        node.get("kind") for node in graph.get("nodes", []) if isinstance(node, Mapping)
    )
    lines = [
        "# Live Discovery Readiness Report",
        "",
        f"Verdict: `{verdict.get('verdict', 'UNKNOWN')}`",
        "",
        "## Resource counts",
        "",
        f"- Instances: `{counts['instance']}`",
        f"- Ports: `{counts['port']}`",
        f"- Volumes: `{counts['volume']}`",
        f"- Images: `{counts['image']}`",
        "",
        "## Reasons",
        "",
    ]
    reasons = verdict.get("reasons", {})
    emitted = False
    if isinstance(reasons, Mapping):
        for status in ("BLOCKED", "UNKNOWN", "WARN", "PASS"):
            values = reasons.get(status, [])
            if isinstance(values, list):
                for reason in values:
                    if isinstance(reason, str):
                        lines.append(f"- `{status}`: {reason}")
                        emitted = True
    if not emitted:
        lines.append("- No reasons were recorded.")
    return "\n".join(lines) + "\n"


def _exact_mapping(value: object, keys: frozenset, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ValueError(f"{label} schema is invalid")
    return value


def _has_symlink_component(path: Path) -> bool:
    absolute = Path(path).absolute()
    return any(
        candidate.is_symlink() and candidate.parent != Path("/")
        for candidate in (absolute, *absolute.parents)
    )


def _validate_sensitive(value: object) -> None:
    budget = [_MAX_NODES]
    def walk(item, depth):
        budget[0] -= 1
        if budget[0] < 0 or depth > _MAX_DEPTH:
            raise ValueError("sensitive evidence exceeds safety bounds")
        if item is None or isinstance(item, (bool, int)):
            return
        if isinstance(item, float):
            if item != item or item in {float("inf"), float("-inf")}:
                raise ValueError("sensitive evidence contains non-finite number")
            return
        if isinstance(item, str):
            if len(item) > _MAX_STRING or "\x00" in item:
                raise ValueError("sensitive evidence exceeds safety bounds")
            return
        if isinstance(item, list):
            for child in item:
                walk(child, depth + 1)
            return
        if isinstance(item, Mapping):
            for key, child in item.items():
                if not isinstance(key, str) or not key or len(key) > 512 or "\x00" in key:
                    raise ValueError("sensitive evidence key is invalid")
                walk(child, depth + 1)
            return
        raise ValueError("sensitive evidence contains unsupported value")
    walk(value, 0)


def _validate_inputs(graph, verdict, capabilities, mapping, evidence):
    _exact_mapping(graph, _GRAPH_KEYS, "resource graph")
    if graph.get("schema_version") != "openstack-rehome-resource-graph/v1alpha1" or not isinstance(graph.get("graph_sha256"), str) or _HEX64.fullmatch(graph["graph_sha256"]) is None:
        raise ValueError("resource graph schema is invalid")
    graph_issues = validate_graph(graph)
    if any(check.status == "BLOCKED" and "hash" in check.reason for check in graph_issues):
        raise ValueError("resource graph integrity hash is invalid")
    if any(
        check.status == "BLOCKED"
        and any(marker in check.reason for marker in (
            "stored graph", "graph payload", "graph node identity is duplicated",
            "graph integrity", "provenance is malformed",
        ))
        for check in graph_issues
    ):
        raise ValueError("resource graph contains malformed payload")
    _exact_mapping(verdict, _VERDICT_KEYS, "readiness verdict")
    statuses = {"PASS", "WARN", "UNKNOWN", "BLOCKED"}
    if (
        verdict.get("schema_version") != "openstack-rehome-readiness-verdict/v1alpha1"
        or not isinstance(verdict.get("counts"), Mapping)
        or set(verdict["counts"]) != statuses
        or any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in verdict["counts"].values())
        or not isinstance(verdict.get("reasons"), Mapping)
        or set(verdict["reasons"]) != statuses
        or any(not isinstance(values, list) or not all(isinstance(value, str) for value in values) for values in verdict["reasons"].values())
        or not isinstance(verdict.get("checks"), list)
    ):
        raise ValueError("readiness verdict schema is invalid")
    for check in verdict["checks"]:
        if (
            not isinstance(check, Mapping)
            or set(check) != {"check_id", "status", "reason", "resource_ids", "evidence_ids"}
            or check.get("status") not in statuses
            or not isinstance(check.get("check_id"), str)
            or not isinstance(check.get("reason"), str)
            or not isinstance(check.get("resource_ids"), list)
            or not isinstance(check.get("evidence_ids"), list)
        ):
            raise ValueError("readiness verdict check schema is invalid")
    if verdict.get("graph_sha256") != graph.get("graph_sha256") or verdict.get("verdict") not in {"READY", "READY_WITH_WARNINGS", "UNKNOWN", "BLOCKED"}:
        raise ValueError("readiness verdict is inconsistent")
    expected_exit = {"READY": 0, "READY_WITH_WARNINGS": 0, "UNKNOWN": 2, "BLOCKED": 3}[verdict["verdict"]]
    if verdict.get("exit_code") != expected_exit:
        raise ValueError("readiness verdict exit code is invalid")
    _exact_mapping(capabilities, _CAPABILITY_KEYS, "schema capabilities")
    if capabilities.get("schema_version") != "openstack-rehome-schema-capabilities/v1alpha1" or not isinstance(capabilities.get("services"), Mapping):
        raise ValueError("schema capabilities version is invalid")
    _exact_mapping(mapping, _MAPPING_KEYS, "schema mapping")
    if mapping.get("schema_version") != "openstack-rehome-directional-schema-mapping/v1alpha1":
        raise ValueError("schema mapping version is invalid")
    if not isinstance(evidence, Mapping) or set(evidence) != {"uuid_filters", "index", "sensitive"}:
        raise ValueError("evidence schema is invalid")
    _exact_mapping(evidence["uuid_filters"], _UUID_FILTER_KEYS, "UUID filters")
    _exact_mapping(evidence["index"], _EVIDENCE_INDEX_KEYS, "evidence index")
    if evidence["uuid_filters"].get("schema_version") != "openstack-rehome-uuid-filters/v1alpha1" or evidence["index"].get("schema_version") != "openstack-rehome-evidence-index/v1alpha1" or not isinstance(evidence["index"].get("entries"), list):
        raise ValueError("evidence version is invalid")
    if not isinstance(evidence["sensitive"], Mapping):
        raise ValueError("sensitive evidence schema is invalid")
    _validate_sensitive(evidence["sensitive"])


def _safe_destination(out_dir: Path) -> Path:
    out_dir = Path(out_dir)
    if out_dir == Path("/") or out_dir.name in {"", ".", ".."}:
        raise ValueError("unsafe output directory")
    parent = out_dir.parent
    if _has_symlink_component(out_dir):
        raise ValueError("symlink output directory is forbidden")
    parent.mkdir(parents=True, exist_ok=True)
    if not parent.is_dir():
        raise ValueError("unsafe output parent")
    return out_dir


def _write(path: Path, content: str, mode: int = 0o644) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def write_artifacts(out_dir, graph, verdict, schema_capabilities, schema_mapping, evidence) -> None:
    """Write the reviewed artifact set using a rollback-safe sibling swap."""
    _validate_inputs(graph, verdict, schema_capabilities, schema_mapping, evidence)
    out_dir = _safe_destination(Path(out_dir))
    parent = out_dir.parent
    lock = parent / f".{out_dir.name}.lock"
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError as error:
        raise ValueError("another artifact writer is active") from error
    staging = None
    backup = parent / f".{out_dir.name}.backup-{os.getpid()}-{hashlib.sha256(os.urandom(16)).hexdigest()[:12]}"
    replaced = False
    try:
        staging = Path(tempfile.mkdtemp(prefix=f".{out_dir.name}.staging-", dir=parent))
        _write(staging / "resource-graph.json", render_json(graph))
        _write(staging / "resource-graph.yml", render_yaml(graph))
        _write(staging / "readiness-report.json", render_json(verdict))
        _write(staging / "readiness-report.md", render_markdown(graph, verdict))
        _write(staging / "schema-capabilities.json", render_json(schema_capabilities))
        _write(staging / "schema-mapping.json", render_json(schema_mapping))
        _write(staging / "uuid-filters.json", render_json(evidence["uuid_filters"]))
        _write(staging / "evidence-index.json", render_json(evidence["index"]))
        if evidence["sensitive"]:
            sensitive = staging / "sensitive"
            sensitive.mkdir(mode=0o700)
            os.chmod(sensitive, 0o700)
            # Sensitive evidence is deliberately not passed through normal rendering.
            raw = json.dumps(evidence["sensitive"], ensure_ascii=False, sort_keys=True, indent=2) + "\n"
            _write(sensitive / "evidence.json", raw, 0o600)
            os.chmod(sensitive / "evidence.json", 0o600)
        if out_dir.exists():
            if not out_dir.is_dir():
                raise ValueError("output path is not a directory")
            os.replace(out_dir, backup)
            replaced = True
        try:
            os.replace(staging, out_dir)
        except Exception:
            if replaced:
                os.replace(backup, out_dir)
                replaced = False
            raise
        if replaced:
            shutil.rmtree(backup, ignore_errors=True)
            replaced = False
    finally:
        if staging is not None and staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        if replaced and backup.exists() and not out_dir.exists():
            os.replace(backup, out_dir)
        try:
            lock.rmdir()
        except OSError:
            pass
