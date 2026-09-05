"""SSRF-boundary and politeness unit tests for ``core/url_policy``.

The guard is a security boundary, so every rejection rule is pinned here
directly. Per the hardening-test convention these tests SELF-PIN the
private-target override OFF (CI sets it process-wide; the tests must hold
either way), and the override case patches the env inside the test only.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import url_policy


class FakeResponse:
    def __init__(self, status_code=200, headers=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.is_redirect = status_code in (301, 302, 303, 307, 308)
        self.closed = False

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requested = []
        self.closed = False

    def get(self, url, **kwargs):
        self.requested.append(url)
        if not kwargs.get("allow_redirects", True):
            pass  # safe_get always passes allow_redirects=False
        assert kwargs.get("allow_redirects") is False, "safe_get must follow redirects itself"
        return self.responses.pop(0)

    def close(self):
        self.closed = True


class ValidatePublicUrlTest(unittest.TestCase):
    def setUp(self):
        # Hold the boundary closed even when CI enables the override globally.
        self._env = mock.patch.dict(os.environ, {"SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS": "0"})
        self._env.start()
        self.addCleanup(self._env.stop)

    def test_scheme_host_credentials_rules(self):
        self.assertFalse(url_policy.validate_public_url("ftp://example.com/x")[0])
        self.assertFalse(url_policy.validate_public_url("http:///no-host")[0])
        self.assertFalse(url_policy.validate_public_url("https://user:pw@example.com/")[0])
        ok, reason = url_policy.validate_public_url("file:///etc/passwd")
        self.assertFalse(ok)

    def test_local_names_and_ip_literals_rejected_without_dns(self):
        for url in ("http://localhost/x", "http://127.0.0.1/", "http://[::1]/",
                    "http://169.254.169.254/latest/meta-data/", "http://10.0.0.1/"):
            with mock.patch.object(url_policy, "_resolved_addresses",
                                   side_effect=AssertionError("must not resolve")):
                ok, _ = url_policy.validate_public_url(url)
            self.assertFalse(ok, url)

    def test_resolution_rebind_is_caught(self):
        with mock.patch.object(url_policy, "_resolved_addresses", return_value=["10.1.2.3"]):
            ok, reason = url_policy.validate_public_url("https://evil.example.com/")
        self.assertFalse(ok)
        self.assertIn("resolves", reason)

    def test_dns_failure_is_not_private(self):
        with mock.patch.object(url_policy, "_resolved_addresses", return_value=[]):
            ok, _ = url_policy.validate_public_url("https://example.com/")
        self.assertTrue(ok)

    def test_override_relaxes_only_destination_checks(self):
        with mock.patch.dict(os.environ, {"SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS": "1"}):
            self.assertTrue(url_policy.validate_public_url("http://127.0.0.1:8000/")[0])
            # Scheme, hostname and credential rules stay enforced.
            self.assertFalse(url_policy.validate_public_url("ftp://127.0.0.1/")[0])
            self.assertFalse(url_policy.validate_public_url("http://u:p@127.0.0.1/")[0])
            self.assertFalse(url_policy.validate_public_url("not a url")[0])


class PolitenessTest(unittest.TestCase):
    def setUp(self):
        self._env = mock.patch.dict(os.environ, {"SCRIPTSENTRY_CRAWL_DELAY_MS": "0"})
        self._env.start()
        self.addCleanup(self._env.stop)
        url_policy._LAST_REQUEST.clear()

    def test_second_rapid_request_sleeps_up_to_cap(self):
        sleeps = []
        clock = iter([1000.0, 1000.01])
        with mock.patch.dict(os.environ, {"SCRIPTSENTRY_CRAWL_DELAY_MS": "100"}), \
                mock.patch.object(url_policy.time, "monotonic", side_effect=lambda: next(clock)), \
                mock.patch.object(url_policy.time, "sleep", side_effect=sleeps.append):
            url_policy.politeness_wait("https://a.example.com/x")
            self.assertEqual(sleeps, [], "first request must not wait")
            url_policy.politeness_wait("https://a.example.com/y")
        self.assertEqual(len(sleeps), 1)
        self.assertAlmostEqual(sleeps[0], 0.09, places=3)

    def test_delay_is_per_host(self):
        sleeps = []
        with mock.patch.dict(os.environ, {"SCRIPTSENTRY_CRAWL_DELAY_MS": "500"}), \
                mock.patch.object(url_policy.time, "monotonic", side_effect=[100.0, 100.0, 100.0, 100.0]), \
                mock.patch.object(url_policy.time, "sleep", side_effect=sleeps.append):
            url_policy.politeness_wait("https://a.example.com/x")
            url_policy.politeness_wait("https://b.example.com/x")  # other host: no wait
        self.assertEqual(sleeps, [])

    def test_cap_at_30_seconds(self):
        sleeps = []
        with mock.patch.dict(os.environ, {"SCRIPTSENTRY_CRAWL_DELAY_MS": "120000"}), \
                mock.patch.object(url_policy.time, "monotonic", side_effect=[0.0, 0.0]), \
                mock.patch.object(url_policy.time, "sleep", side_effect=sleeps.append):
            url_policy.politeness_wait("https://c.example.com/x")
        self.assertEqual(sleeps, [30.0])


class SafeGetBoundaryTest(unittest.TestCase):
    def setUp(self):
        self._env = mock.patch.dict(os.environ, {"SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS": "0"})
        self._env.start()
        self.addCleanup(self._env.stop)

    def _run(self, session, url="https://example.com/start", cancel_check=None):
        with mock.patch.object(url_policy, "requests", mock.Mock(Session=mock.Mock(return_value=session))), \
                mock.patch.object(url_policy, "_resolved_addresses", return_value=["93.184.216.34"]):
            return url_policy.safe_get(url, cancel_check=cancel_check)

    def test_follows_relative_redirect_and_returns_final(self):
        session = FakeSession([
            FakeResponse(302, {"Location": "/next?keep=1"}),
            FakeResponse(200),
        ])
        response = self._run(session)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(session.requested, ["https://example.com/start", "https://example.com/next?keep=1"])
        self.assertTrue(session.requested[1].startswith("https://example.com"), "redirects stay validated")

    def test_redirect_to_private_host_rejected(self):
        session = FakeSession([
            FakeResponse(302, {"Location": "http://169.254.169.254/latest/meta-data/"}),
        ])
        with self.assertRaises(ValueError):
            self._run(session)

    def test_cancelled_request_raises_and_closes(self):
        session = FakeSession([FakeResponse(200)])
        with self.assertRaises(ValueError):
            self._run(session, cancel_check=lambda: True)
        self.assertTrue(session.closed)

    def test_too_many_redirects(self):
        session = FakeSession([FakeResponse(302, {"Location": f"/hop{i}"}) for i in range(8)])
        with self.assertRaises(ValueError):
            self._run(session)


class ReadResponseTextTest(unittest.TestCase):
    def _resp(self, chunks, encoding="utf-8"):
        resp = mock.Mock()
        resp.iter_content = lambda chunk_size: iter(chunks)
        resp.encoding = encoding
        resp.close = mock.Mock()
        return resp

    def test_reads_and_decodes(self):
        text = url_policy.read_response_text(self._resp([b"hello ", b"world"]))
        self.assertEqual(text, "hello world")

    def test_over_limit_returns_none(self):
        big = url_policy.read_response_text(self._resp([b"x" * 100]), max_bytes=10)
        self.assertIsNone(big)

    def test_falls_back_to_raw_stream_bounded(self):
        resp = mock.Mock(spec=["raw", "encoding", "close"])
        resp.raw = mock.Mock(read=lambda n: b"raw-body")
        resp.encoding = "utf-8"
        self.assertEqual(url_policy.read_response_text(resp, max_bytes=100), "raw-body")
        # A raw stream over the limit is refused, not truncated silently.
        resp2 = mock.Mock(spec=["raw", "encoding", "close"])
        resp2.raw = mock.Mock(read=lambda n: b"y" * 51)
        resp2.encoding = "utf-8"
        self.assertIsNone(url_policy.read_response_text(resp2, max_bytes=50))

    def test_close_is_called(self):
        resp = self._resp([b"z"])
        url_policy.read_response_text(resp)
        resp.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
