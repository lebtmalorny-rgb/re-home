"""Deterministic, independently sanitized live-discovery artifact rendering."""

from collections import Counter
import html
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import tempfile
from typing import Any, Mapping

from .graph import _SENSITIVE_KEY, _SENSITIVE_VALUE, _canonical, validate_graph


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
_RENDER_SENSITIVE_KEY = re.compile(
    r"password|passwd|(?:^|[_-])pwd(?:$|[_-])|token|secret|chap|credential|"
    r"connector|connection[_-]?(?:info|data)|api[_-]?key|access[_-]?key|"
    r"private[\s_-]*key|authorization",
    re.IGNORECASE,
)
_RENDER_SENSITIVE_VALUE = re.compile(
    r"api[\s_-]*key\s*[:=]|access[\s_-]*key\s*[:=]|secret[\s_-]*key\s*[:=]|"
    r"private[\s_-]*key\s*[:=]|authorization\s*[:=]|\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+|"
    r"\bAKIA[A-Z0-9]{16}\b",
    re.IGNORECASE,
)
_TABLE_ID = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")
_SAFE_CAPABILITY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$")


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
            return "[REDACTED]" if (_SENSITIVE_VALUE.search(item) or _RENDER_SENSITIVE_VALUE.search(item)) else item
        if isinstance(item, (list, tuple)):
            return [walk(child, depth + 1) for child in item]
        if isinstance(item, Mapping):
            normalized = {}
            for raw_key, child in item.items():
                if not isinstance(raw_key, str) or not raw_key or len(raw_key) > 512 or "\x00" in raw_key:
                    raise ValueError("artifact key is invalid")
                normalized[raw_key] = (
                    "[REDACTED]" if (_SENSITIVE_KEY.search(raw_key) or _RENDER_SENSITIVE_KEY.search(raw_key))
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
                        safe_reason = "".join(
                            " " if ord(character) < 32 or ord(character) == 127 else character
                            for character in reason
                        )
                        safe_reason = html.escape(safe_reason, quote=True)
                        for character in ("\\", "`", "|", "[", "]", "(", ")", "*", "_", "#"):
                            safe_reason = safe_reason.replace(character, "\\" + character)
                        lines.append(f"- `{status}`: {safe_reason}")
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
    if len(capabilities["services"]) > 4096:
        raise ValueError("schema capabilities exceed safety bounds")
    for service, payload in capabilities["services"].items():
        if not isinstance(service, str) or _SAFE_CAPABILITY_ID.fullmatch(service) is None or not isinstance(payload, Mapping):
            raise ValueError("schema capability service is invalid")
        _sanitize(payload)
    _exact_mapping(mapping, _MAPPING_KEYS, "schema mapping")
    if mapping.get("schema_version") != "openstack-rehome-directional-schema-mapping/v1alpha1":
        raise ValueError("schema mapping version is invalid")
    if not isinstance(evidence, Mapping) or set(evidence) != {"uuid_filters", "index", "sensitive"}:
        raise ValueError("evidence schema is invalid")
    _exact_mapping(evidence["uuid_filters"], _UUID_FILTER_KEYS, "UUID filters")
    _exact_mapping(evidence["index"], _EVIDENCE_INDEX_KEYS, "evidence index")
    if evidence["uuid_filters"].get("schema_version") != "openstack-rehome-uuid-filters/v1alpha1" or evidence["index"].get("schema_version") != "openstack-rehome-evidence-index/v1alpha1" or not isinstance(evidence["index"].get("entries"), list):
        raise ValueError("evidence version is invalid")
    for side in ("source", "target"):
        tables = evidence["uuid_filters"].get(side)
        if not isinstance(tables, Mapping) or len(tables) > 4096:
            raise ValueError("UUID filter side is invalid")
        for query_id, query in tables.items():
            if (
                not isinstance(query_id, str) or _SAFE_CAPABILITY_ID.fullmatch(query_id) is None
                or not isinstance(query, Mapping)
                or set(query) != {"schema", "table", "filters"}
                or not isinstance(query["schema"], str)
                or not isinstance(query["table"], str)
                or _TABLE_ID.fullmatch(f"{query['schema']}.{query['table']}") is None
            ):
                raise ValueError("UUID filter table is invalid")
            filters = query["filters"]
            if not isinstance(filters, Mapping) or not filters:
                raise ValueError("UUID filter table is invalid")
            for column, values in filters.items():
                if not isinstance(column, str) or not column or not isinstance(values, list) or not values or len(values) > 4096:
                    raise ValueError("UUID filter column is invalid")
                if len({_canonical(item) for item in values}) != len(values) or any(not isinstance(item, (str, int)) or isinstance(item, bool) for item in values):
                    raise ValueError("UUID filter values are invalid")
    if len(evidence["index"]["entries"]) > 100_000:
        raise ValueError("evidence index exceeds safety bounds")
    for entry in evidence["index"]["entries"]:
        common = {"evidence_id", "kind", "side", "service"}
        shapes = {
            "openstack-json": common | {"command"},
            "runtime-command": common | {"command"},
            "db-jsonl": common | {"schema", "table", "filters"},
            "storage-probe": common | {"resource_id", "backend_kind", "backend_identity", "resource_identity", "scope", "expected_size", "observed_size", "status"},
            "glance-range": common | {"resource_id", "endpoint_origin", "expected_size", "observed_size", "required", "store_ids", "status"},
        }
        if not isinstance(entry, Mapping) or entry.get("kind") not in shapes or set(entry) != shapes.get(entry.get("kind"), set()):
            raise ValueError("evidence index entry schema is invalid")
        if entry.get("side") not in {"source", "target"} or not all(isinstance(entry.get(key), str) and entry[key] for key in ("evidence_id", "service")):
            raise ValueError("evidence index provenance is invalid")
        if entry["kind"] in {"openstack-json", "runtime-command"} and (not isinstance(entry["command"], list) or not entry["command"] or not all(isinstance(value, str) and value for value in entry["command"])):
            raise ValueError("evidence command is invalid")
        if entry["kind"] == "db-jsonl" and (not isinstance(entry["schema"], str) or not isinstance(entry["table"], str) or not isinstance(entry["filters"], Mapping) or not entry["filters"]):
            raise ValueError("DB evidence is invalid")
        if entry["kind"] == "storage-probe" and (entry["scope"] not in {"source-compute", "target-storage"} or entry["status"] not in {"PASS", "WARN", "UNKNOWN", "BLOCKED"} or not isinstance(entry["expected_size"], int) or (entry["observed_size"] is not None and not isinstance(entry["observed_size"], int)) or (entry["status"] == "PASS" and entry["observed_size"] != entry["expected_size"])):
            raise ValueError("storage evidence is invalid")
        if entry["kind"] == "glance-range" and (entry["status"] not in {"PASS", "WARN", "UNKNOWN", "BLOCKED"} or not isinstance(entry["required"], bool) or not isinstance(entry["expected_size"], int) or (entry["observed_size"] is not None and not isinstance(entry["observed_size"], int)) or (entry["status"] == "PASS" and entry["observed_size"] != entry["expected_size"]) or not isinstance(entry["store_ids"], list) or not entry["store_ids"]):
            raise ValueError("Glance evidence is invalid")
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


class _AtomicArtifactWriter:
    """Owned-lock sibling swap with signal-triggered rollback."""

    def __init__(self, out_dir):
        self.out_dir = Path(out_dir)
        self.parent = self.out_dir.parent
        self.lock = self.parent / f".{self.out_dir.name}.lock"
        self.owner = self.lock / "owner.json"
        self.token = hashlib.sha256(os.urandom(32)).hexdigest()
        self.staging = None
        self.backup = None
        self.installed = False
        self.completed = False
        self.owns_lock = False
        self.previous_handlers = {}

    def _owner_payload(self):
        return {"pid": os.getpid(), "token": self.token}

    def _lock_is_owned(self):
        try:
            if self.owner.is_symlink() or not self.owner.is_file():
                return False
            return json.loads(self.owner.read_text(encoding="utf-8")) == self._owner_payload()
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return False

    def begin(self):
        self.out_dir = _safe_destination(self.out_dir)
        self.parent = self.out_dir.parent
        try:
            for signum in (signal.SIGTERM, signal.SIGINT):
                self.previous_handlers[signum] = signal.getsignal(signum)
                signal.signal(signum, self.handle_signal)
            self.lock.mkdir(mode=0o700)
            self.owns_lock = True
            _write(self.owner, json.dumps(self._owner_payload(), sort_keys=True) + "\n", 0o600)
            self.staging = Path(tempfile.mkdtemp(prefix=f".{self.out_dir.name}.staging-", dir=self.parent))
        except FileExistsError as error:
            self.cleanup()
            raise ValueError("another artifact writer is active") from error
        except BaseException:
            self.cleanup()
            raise
        return self

    def backup_existing(self):
        if self.out_dir.exists():
            if self.out_dir.is_symlink() or not self.out_dir.is_dir():
                raise ValueError("output path is not a safe directory")
            self.backup = self.parent / f".{self.out_dir.name}.backup-{self.token}"
            os.replace(self.out_dir, self.backup)

    def install_staging(self):
        if self.staging is None or not self.staging.is_dir():
            raise ValueError("artifact staging directory is unavailable")
        os.replace(self.staging, self.out_dir)
        self.staging = None
        self.installed = True

    def _restore_handlers(self):
        for signum, previous in self.previous_handlers.items():
            try:
                signal.signal(signum, previous)
            except (ValueError, OSError):
                pass
        self.previous_handlers.clear()

    def _remove_owned_lock(self):
        if not self.owns_lock:
            return
        if not self._lock_is_owned():
            try:
                self.lock.rmdir()
                self.owns_lock = False
            except OSError:
                pass
            return
        try:
            self.owner.unlink()
            self.lock.rmdir()
            self.owns_lock = False
        except OSError:
            pass

    def rollback(self):
        if self.installed and self.out_dir.exists():
            if self.out_dir.is_symlink() or not self.out_dir.is_dir():
                raise ValueError("installed artifact path is unsafe")
            shutil.rmtree(self.out_dir)
            self.installed = False
        if self.backup is not None and self.backup.exists():
            if self.out_dir.exists():
                raise ValueError("cannot restore prior artifact over existing path")
            os.replace(self.backup, self.out_dir)
            self.backup = None
        if self.staging is not None and self.staging.exists():
            shutil.rmtree(self.staging, ignore_errors=True)
            self.staging = None

    def cleanup(self):
        try:
            if not self.completed:
                self.rollback()
        finally:
            self._restore_handlers()
            self._remove_owned_lock()

    def complete(self):
        if self.backup is not None and self.backup.exists():
            shutil.rmtree(self.backup, ignore_errors=True)
            self.backup = None
        self.completed = True
        self._restore_handlers()
        self._remove_owned_lock()

    def handle_signal(self, signum, frame):
        del frame
        self.cleanup()
        raise InterruptedError(f"artifact write interrupted by signal {signum}")


def write_artifacts(out_dir, graph, verdict, schema_capabilities, schema_mapping, evidence) -> None:
    """Write the reviewed artifact set using a rollback-safe sibling swap."""
    _validate_inputs(graph, verdict, schema_capabilities, schema_mapping, evidence)
    writer = _AtomicArtifactWriter(Path(out_dir)).begin()
    try:
        staging = writer.staging
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
        writer.backup_existing()
        writer.install_staging()
        writer.complete()
    except BaseException:
        writer.cleanup()
        raise
