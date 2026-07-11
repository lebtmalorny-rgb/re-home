from io import BytesIO
from pathlib import Path
import sys
import unittest
from urllib.error import HTTPError


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from live_discovery.image_data import probe_image_data


IMAGE_ID = "11111111-1111-1111-1111-111111111111"
ENDPOINT = "https://glance.example"
URL = f"{ENDPOINT}/v2/images/{IMAGE_ID}/file"


class RecordingResponse:
    def __init__(self, status=206, headers=None, body=b"x", final_url=URL):
        self.status = status
        self.headers = headers or {}
        self.stream = BytesIO(body)
        self.final_url = final_url
        self.read_sizes = []
        self.closed = False

    def read(self, size=-1):
        self.read_sizes.append(size)
        return self.stream.read(size)

    def geturl(self):
        return self.final_url

    def close(self):
        self.closed = True


class RecordingOpener:
    def __init__(self, response=None, error=None):
        self.response = response or RecordingResponse(
            headers={"Content-Range": "bytes 0-0/1024", "Content-Length": "1"}
        )
        self.error = error
        self.request = None
        self.timeout = None

    def open(self, request, timeout=None):
        self.request = request
        self.timeout = timeout
        if self.error is not None:
            raise self.error
        return self.response


def probe(opener, **overrides):
    kwargs = {
        "url": URL,
        "token": "token-value",
        "expected_size": 1024,
        "opener": opener,
        "endpoint_url": ENDPOINT,
        "image_id": IMAGE_ID,
    }
    kwargs.update(overrides)
    return probe_image_data(**kwargs)


class ImageDataProbeTests(unittest.TestCase):
    def test_requests_one_byte_and_accepts_exact_partial_content(self):
        opener = RecordingOpener()
        check = probe(opener)
        self.assertEqual("PASS", check.status)
        self.assertEqual("bytes=0-0", opener.request.headers["Range"])
        self.assertEqual("token-value", opener.request.headers["X-auth-token"])
        self.assertEqual([1], opener.response.read_sizes)
        self.assertTrue(opener.response.closed)
        self.assertNotIn("token-value", check.reason)

    def test_200_ignored_range_is_warn_and_reads_at_most_one_byte(self):
        response = RecordingResponse(
            status=200, headers={"Content-Length": "1024"}, body=b"secret-token" * 100
        )
        check = probe(RecordingOpener(response))
        self.assertEqual("WARN", check.status)
        self.assertEqual([1], response.read_sizes)
        self.assertTrue(response.closed)
        self.assertNotIn("secret-token", check.reason)

    def test_ignored_range_with_wrong_or_missing_length_blocks(self):
        for headers in ({}, {"Content-Length": "1025"}, {"Content-Length": "x"}):
            with self.subTest(headers=headers):
                check = probe(RecordingOpener(RecordingResponse(status=200, headers=headers)))
                self.assertEqual("BLOCKED", check.status)

    def test_required_status_classification(self):
        for status, expected in ((204, "BLOCKED"), (403, "BLOCKED"), (404, "BLOCKED"), (416, "BLOCKED"), (500, "UNKNOWN")):
            with self.subTest(status=status):
                check = probe(RecordingOpener(RecordingResponse(status=status)))
                self.assertEqual(expected, check.status)

    def test_http_errors_are_constant_and_sanitized(self):
        for status, expected in ((403, "BLOCKED"), (404, "BLOCKED"), (416, "BLOCKED"), (500, "UNKNOWN")):
            with self.subTest(status=status):
                error = HTTPError(URL, status, "secret-token", {"X-Secret": "token-value"}, BytesIO(b"secret"))
                check = probe(RecordingOpener(error=error))
                self.assertEqual(expected, check.status)
                self.assertNotIn("secret", check.reason)
                self.assertNotIn("token", check.reason)

    def test_transport_errors_are_unknown_and_never_serialize_exception(self):
        opener = RecordingOpener(error=RuntimeError("secret-token https://evil.invalid"))
        check = probe(opener)
        self.assertEqual("UNKNOWN", check.status)
        self.assertNotIn("secret-token", check.reason)
        self.assertNotIn("evil.invalid", check.reason)

    def test_partial_content_requires_exact_range_length_body_and_total(self):
        cases = (
            ({"Content-Range": "bytes 0-1/1024", "Content-Length": "1"}, b"x"),
            ({"Content-Range": "bytes 0-0/2048", "Content-Length": "1"}, b"x"),
            ({"Content-Range": "bytes 0-0/1024", "Content-Length": "2"}, b"x"),
            ({"Content-Range": "bytes 0-0/1024", "Content-Length": "1"}, b""),
        )
        for headers, body in cases:
            with self.subTest(headers=headers, body=body):
                check = probe(RecordingOpener(RecordingResponse(headers=headers, body=body)))
                self.assertEqual("BLOCKED", check.status)

    def test_redirect_or_cross_origin_final_url_blocks(self):
        for status, final_url in (
            (302, URL),
            (206, f"https://other.example/v2/images/{IMAGE_ID}/file"),
            (206, f"{ENDPOINT}/v2/images/22222222-2222-2222-2222-222222222222/file"),
        ):
            with self.subTest(status=status, final_url=final_url):
                response = RecordingResponse(
                    status=status,
                    headers={"Content-Range": "bytes 0-0/1024", "Content-Length": "1"},
                    final_url=final_url,
                )
                self.assertEqual("BLOCKED", probe(RecordingOpener(response)).status)

    def test_invalid_url_origin_and_path_are_rejected_before_open(self):
        urls = (
            f"https://evil.example/v2/images/{IMAGE_ID}/file",
            f"https://user:pass@glance.example/v2/images/{IMAGE_ID}/file",
            f"{ENDPOINT}/v2/images/{IMAGE_ID}/file?x=1",
            f"{ENDPOINT}/v2/images/{IMAGE_ID}/file#fragment",
            f"{ENDPOINT}/v2/images/{IMAGE_ID}/file/extra",
            f"{ENDPOINT}/v2/images/not-a-uuid/file",
            f"{ENDPOINT}/v2/images/AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA/file",
            "file:///etc/passwd",
        )
        for url in urls:
            with self.subTest(url=url):
                opener = RecordingOpener()
                check = probe(opener, url=url)
                self.assertEqual("BLOCKED", check.status)
                self.assertIsNone(opener.request)

    def test_invalid_endpoint_and_expected_values_rejected_before_open(self):
        cases = (
            {"endpoint_url": "https://user:pass@glance.example"},
            {"endpoint_url": "file:///tmp"},
            {"endpoint_url": "https://glance.example/other"},
            {"image_id": "image-1"},
            {"expected_size": 0},
            {"expected_size": -1},
            {"expected_size": True},
            {"expected_size": "1024"},
            {"token": ""},
            {"token": 7},
            {"token": "a" * 17000},
            {"token": "good\r\nX-Evil: yes"},
        )
        for values in cases:
            with self.subTest(values=values):
                opener = RecordingOpener()
                check = probe(opener, **values)
                self.assertIn(check.status, {"BLOCKED", "UNKNOWN"})
                self.assertIsNone(opener.request)

    def test_duplicate_security_headers_are_rejected(self):
        class DuplicateHeaders:
            def items(self):
                return [
                    ("Content-Range", "bytes 0-0/1024"),
                    ("Content-Length", "1"),
                    ("Content-Length", "1"),
                ]

        response = RecordingResponse()
        response.headers = DuplicateHeaders()
        self.assertEqual("UNKNOWN", probe(RecordingOpener(response)).status)

    def test_header_iteration_stops_at_129_without_materializing(self):
        class GuardedInfiniteItems:
            def __init__(self):
                self.yielded = 0

            def __iter__(self):
                while True:
                    self.yielded += 1
                    if self.yielded > 129:
                        raise AssertionError("header iterator was over-consumed")
                    yield f"X-{self.yielded}", "a"

        class StreamingHeaders:
            def __init__(self):
                self.items_iterator = GuardedInfiniteItems()

            def items(self):
                return self.items_iterator

        response = RecordingResponse()
        response.headers = StreamingHeaders()
        check = probe(RecordingOpener(response))
        self.assertEqual("UNKNOWN", check.status)
        self.assertEqual(129, response.headers.items_iterator.yielded)
        self.assertTrue(response.closed)

    def test_throwing_header_iterator_is_sanitized_and_response_closed(self):
        class ThrowingHeaders:
            def items(self):
                yield "Content-Range", "bytes 0-0/1024"
                raise RuntimeError("secret-token https://evil.invalid")

        response = RecordingResponse()
        response.headers = ThrowingHeaders()
        check = probe(RecordingOpener(response))
        self.assertEqual("UNKNOWN", check.status)
        self.assertNotIn("secret-token", check.reason)
        self.assertTrue(response.closed)

    def test_oversized_or_malformed_headers_fail_closed(self):
        cases = (
            {**{"Content-Range": "bytes 0-0/1024", "Content-Length": "1"}, **{f"X-{i}": "a" for i in range(129)}},
            {"Content-Range": "bytes 0-0/1024", "Content-Length": "1", "X-Large": "a" * 9000},
            {"Content-Range": ["bytes 0-0/1024"], "Content-Length": "1"},
        )
        for headers in cases:
            with self.subTest(case=len(headers)):
                check = probe(RecordingOpener(RecordingResponse(headers=headers)))
                self.assertEqual("UNKNOWN", check.status)

    def test_token_never_enters_check_or_resource_ids(self):
        for status in (200, 204, 206, 403, 500):
            with self.subTest(status=status):
                headers = {"Content-Length": "1024"}
                if status == 206:
                    headers = {"Content-Range": "bytes 0-0/1024", "Content-Length": "1"}
                check = probe(RecordingOpener(RecordingResponse(status=status, headers=headers)))
                payload = repr(check.to_dict())
                self.assertNotIn("token-value", payload)


if __name__ == "__main__":
    unittest.main()
