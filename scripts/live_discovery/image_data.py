import re
import uuid
from typing import Mapping, Optional, Tuple
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .contract import CheckResult


_CONTENT_RANGE = re.compile(r"^bytes 0-0/([1-9][0-9]*)$")
_MAX_HEADERS = 128
_MAX_HEADER_BYTES = 16 * 1024
_TIMEOUT_SECONDS = 10


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        del req, fp, code, msg, headers, newurl
        return None


def _canonical_uuid(value: object) -> Optional[str]:
    if not isinstance(value, str):
        return None
    try:
        normalized = str(uuid.UUID(value))
    except (ValueError, AttributeError):
        return None
    return value if value == normalized else None


def _origin(parsed) -> Optional[Tuple[str, str, int]]:
    try:
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
        ):
            return None
        port = parsed.port
    except (ValueError, TypeError):
        return None
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return parsed.scheme, parsed.hostname.lower(), port


def _valid_target(
    url: object, endpoint_url: object, image_id: object
) -> Optional[str]:
    canonical_id = _canonical_uuid(image_id)
    if not isinstance(url, str) or not isinstance(endpoint_url, str) or canonical_id is None:
        return None
    try:
        target = urlparse(url)
        endpoint = urlparse(endpoint_url)
    except (ValueError, TypeError):
        return None
    if _origin(target) is None or _origin(endpoint) is None:
        return None
    if _origin(target) != _origin(endpoint):
        return None
    if endpoint.params or endpoint.query or endpoint.fragment:
        return None
    if endpoint.path not in {"", "/", "/v2", "/v2/"}:
        return None
    expected_path = f"/v2/images/{canonical_id}/file"
    if (
        target.path != expected_path
        or target.params
        or target.query
        or target.fragment
    ):
        return None
    return url


def _headers(response) -> Optional[Mapping[str, str]]:
    raw = getattr(response, "headers", None)
    try:
        items = iter(raw.items())
        total = 0
        normalized = {}
        count = 0
        for key, value in items:
            count += 1
            if count > _MAX_HEADERS:
                return None
            if not isinstance(key, str) or not isinstance(value, str):
                return None
            key_bytes = key.encode("utf-8")
            value_bytes = value.encode("utf-8")
            total += len(key_bytes) + len(value_bytes)
            if (
                len(key_bytes) > 1024
                or len(value_bytes) > 8192
                or total > _MAX_HEADER_BYTES
                or "\r" in key
                or "\n" in key
                or "\r" in value
                or "\n" in value
            ):
                return None
            lowered_key = key.lower()
            if lowered_key in normalized:
                return None
            normalized[lowered_key] = value.strip()
        return normalized
    except (Exception, MemoryError, RecursionError):
        return None


def _result(image_id: str, status: str, reason: str) -> CheckResult:
    return CheckResult(
        f"glance.image-data.{image_id}",
        status,
        reason,
        [f"image:{image_id}"],
    )


def _status_result(image_id: str, status: int) -> CheckResult:
    if status in {204, 403, 404, 416}:
        return _result(image_id, "BLOCKED", f"Glance image data response status {status}")
    if 300 <= status < 400:
        return _result(image_id, "BLOCKED", "Glance image data redirect rejected")
    return _result(image_id, "UNKNOWN", "Glance image data response unsupported")


def probe_image_data(
    url,
    token,
    expected_size,
    opener=None,
    *,
    endpoint_url=None,
    image_id=None,
    required=True,
) -> CheckResult:
    """Read at most one image byte through the authenticated Glance API.

    The token is used only to build the in-memory request and is never copied
    into the returned result. Redirects and endpoint/path ambiguity are denied.
    """

    del required  # Requiredness is applied by the collector; probe facts stay objective.
    canonical_id = _canonical_uuid(image_id)
    fallback_id = canonical_id or "invalid"
    if canonical_id is None:
        return _result(fallback_id, "BLOCKED", "Glance image UUID invalid")
    if not isinstance(expected_size, int) or isinstance(expected_size, bool) or expected_size <= 0:
        return _result(canonical_id, "BLOCKED", "Glance expected image size invalid")
    if (
        not isinstance(token, str)
        or token == ""
        or len(token.encode("utf-8")) > 16 * 1024
        or "\r" in token
        or "\n" in token
    ):
        return _result(canonical_id, "UNKNOWN", "Glance authentication token unavailable")
    validated_url = _valid_target(url, endpoint_url, canonical_id)
    if validated_url is None:
        return _result(canonical_id, "BLOCKED", "Glance image data URL rejected")

    request = Request(
        validated_url,
        headers={"Range": "bytes=0-0", "X-Auth-Token": token},
        method="GET",
    )
    selected_opener = opener if opener is not None else build_opener(_NoRedirect())
    response = None
    try:
        response = selected_opener.open(request, timeout=_TIMEOUT_SECONDS)
        final_url = response.geturl() if hasattr(response, "geturl") else validated_url
        if final_url != validated_url:
            return _result(canonical_id, "BLOCKED", "Glance image data redirect rejected")
        status = getattr(response, "status", None)
        if not isinstance(status, int) or isinstance(status, bool):
            return _result(canonical_id, "UNKNOWN", "Glance image data response status invalid")
        headers = _headers(response)
        if headers is None:
            return _result(canonical_id, "UNKNOWN", "Glance image data response headers invalid")
        if status == 206:
            match = _CONTENT_RANGE.fullmatch(headers.get("content-range", ""))
            content_length = headers.get("content-length")
            byte = response.read(1)
            if (
                match is None
                or int(match.group(1)) != expected_size
                or content_length != "1"
                or not isinstance(byte, bytes)
                or len(byte) != 1
            ):
                return _result(canonical_id, "BLOCKED", "Glance partial response inconsistent")
            return _result(canonical_id, "PASS", "Glance image data byte is readable")
        if status == 200:
            byte = response.read(1)
            if (
                headers.get("content-length") != str(expected_size)
                or not isinstance(byte, bytes)
                or len(byte) != 1
            ):
                return _result(canonical_id, "BLOCKED", "Glance full response size inconsistent")
            return _result(canonical_id, "WARN", "Glance server ignored the Range request")
        return _status_result(canonical_id, status)
    except HTTPError as error:
        try:
            status = int(error.code)
        except (ValueError, TypeError):
            status = 0
        try:
            error.close()
        except Exception:
            pass
        return _status_result(canonical_id, status)
    except (Exception, MemoryError, RecursionError):
        return _result(canonical_id, "UNKNOWN", "Glance image data transport failed")
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
