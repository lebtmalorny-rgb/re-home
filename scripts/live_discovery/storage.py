import json
from pathlib import PurePosixPath
import re
from typing import Any, Mapping, Optional, Sequence, Tuple

from .contract import CheckResult


_STORAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:+-]{0,254}$")
_PATH_PART = re.compile(r"^[A-Za-z0-9_.:+@#-]+$")


def _valid_name(value: object) -> Optional[str]:
    if isinstance(value, str) and _STORAGE_NAME.fullmatch(value):
        return value
    return None


def _valid_path(value: object) -> Optional[str]:
    if not isinstance(value, str) or not value.startswith("/") or "//" in value:
        return None
    path = PurePosixPath(value)
    if str(path) != value or len(path.parts) < 3:
        return None
    if any(part in {"", ".", ".."} or not _PATH_PART.fullmatch(part) for part in path.parts[1:]):
        return None
    return value


def _expected_size(resource: Mapping[str, Any]) -> Tuple[Optional[int], bool]:
    if "expected_size" not in resource:
        return None, False
    value = resource["expected_size"]
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        return None, False
    return value, True


def _allowed_names(value: object) -> Optional[set[str]]:
    if not isinstance(value, (list, tuple)) or not value:
        return None
    names = {_valid_name(item) for item in value}
    if None in names or not names:
        return None
    return {item for item in names if item is not None}


def _allowed_roots(value: object) -> Optional[Sequence[PurePosixPath]]:
    if not isinstance(value, (list, tuple)) or not value:
        return None
    roots = [_valid_path(item) for item in value]
    if any(item is None for item in roots):
        return None
    return [PurePosixPath(item) for item in roots if item is not None]


def _json_size(payload: object) -> Optional[int]:
    if isinstance(payload, Mapping):
        size = payload.get("size")
        if isinstance(size, int) and not isinstance(size, bool) and size >= 0:
            return size
    return None


def _parse_size(kind: str, stdout: object) -> Optional[int]:
    if not isinstance(stdout, str):
        return None
    if kind == "nfs":
        stripped = stdout.strip()
        if stripped.isdigit():
            return int(stripped)
        try:
            return _json_size(json.loads(stripped))
        except (json.JSONDecodeError, TypeError):
            return None
    try:
        payload = json.loads(stdout)
    except (json.JSONDecodeError, TypeError):
        return None
    if kind == "rbd":
        return _json_size(payload)
    if kind == "lvm" and isinstance(payload, Mapping):
        reports = payload.get("report")
        if isinstance(reports, list) and len(reports) == 1 and isinstance(reports[0], Mapping):
            rows = reports[0].get("lv")
            if isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], Mapping):
                raw = rows[0].get("lv_size")
                if isinstance(raw, int) and not isinstance(raw, bool) and raw >= 0:
                    return raw
                if isinstance(raw, str) and raw.isdigit():
                    return int(raw)
                if isinstance(raw, str) and re.fullmatch(r"\d+\.0+", raw):
                    return int(raw.split(".", 1)[0])
    return None


def _command(kind: str, resource: Mapping[str, Any]) -> Optional[Sequence[str]]:
    if kind == "nfs":
        path = _valid_path(resource.get("path"))
        roots = _allowed_roots(resource.get("allowed_roots"))
        if path is None or roots is None:
            return None
        parsed = PurePosixPath(path)
        if not any(root in parsed.parents for root in roots):
            return None
        return ["stat", "--format", "%s", path]
    if kind == "rbd":
        pool = _valid_name(resource.get("pool"))
        image = _valid_name(resource.get("image"))
        allowed = _allowed_names(resource.get("allowed_pools"))
        return ["rbd", "info", "--format", "json", f"{pool}/{image}"] if pool and image and allowed is not None and pool in allowed else None
    if kind == "lvm":
        vg = _valid_name(resource.get("vg"))
        lv = _valid_name(resource.get("lv"))
        allowed = _allowed_names(resource.get("allowed_vgs"))
        return [
            "lvs", "--reportformat", "json", "--units", "b", "--nosuffix",
            f"{vg}/{lv}",
        ] if vg and lv and allowed is not None and vg in allowed else None
    return None


def probe_storage(kind: object, resource: object, runner) -> CheckResult:
    normalized_kind = kind.lower() if isinstance(kind, str) else ""
    normalized_kind = "nfs" if normalized_kind == "file" else normalized_kind
    if normalized_kind not in {"nfs", "rbd", "lvm"}:
        return CheckResult(
            "cinder.storage.unsupported", "UNKNOWN", "storage driver is unsupported"
        )
    if not isinstance(resource, Mapping):
        return CheckResult(
            f"cinder.storage.{normalized_kind}", "BLOCKED", "storage resource facts invalid"
        )
    argv = _command(normalized_kind, resource)
    expected, expected_valid = _expected_size(resource)
    if argv is None or not expected_valid:
        return CheckResult(
            f"cinder.storage.{normalized_kind}", "BLOCKED", "storage resource facts invalid"
        )
    evidence_id = f"cinder-storage-{normalized_kind}-read-only"
    try:
        evidence = runner.run(argv, evidence_id)
    except Exception:
        return CheckResult(
            f"cinder.storage.{normalized_kind}", "BLOCKED", "backing object is unreadable"
        )
    actual = _parse_size(normalized_kind, getattr(evidence, "stdout", None))
    safe_evidence_id = getattr(evidence, "evidence_id", None)
    evidence_ids = [safe_evidence_id] if isinstance(safe_evidence_id, str) and safe_evidence_id else []
    if actual is None:
        return CheckResult(
            f"cinder.storage.{normalized_kind}", "BLOCKED", "backing object size evidence invalid",
            evidence_ids=evidence_ids,
        )
    if expected is not None and actual != expected:
        return CheckResult(
            f"cinder.storage.{normalized_kind}", "BLOCKED", "backing object size mismatch",
            evidence_ids=evidence_ids,
        )
    return CheckResult(
        f"cinder.storage.{normalized_kind}", "PASS", "backing object is readable with expected size",
        evidence_ids=evidence_ids,
    )
