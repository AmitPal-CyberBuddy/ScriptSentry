"""Crawl-politeness (per-host rate limiting) tests.

``SCRIPTSENTRY_CRAWL_DELAY_MS`` makes ``core.url_policy.safe_get`` -- the
single choke point for every network fetch -- serialize requests per host.
Off by default; the delay must never apply to a different host.
"""
import contextlib
import time
import unittest
from unittest import mock

from core.url_policy import _LAST_REQUEST, crawl_delay_seconds, politeness_wait


class CrawlDelayTest(unittest.TestCase):
    def setUp(self):
        _LAST_REQUEST.clear()

    def test_disabled_by_default(self):
        with mock.patch.dict("os.environ", {}, clear=False):
            import os
            os.environ.pop("SCRIPTSENTRY_CRAWL_DELAY_MS", None)
            self.assertEqual(crawl_delay_seconds(), 0.0)
            started = time.monotonic()
            politeness_wait("https://example.test/a.js")
            self.assertLess(time.monotonic() - started, 0.05)

    def test_delay_serializes_same_host(self):
        with mock.patch.dict("os.environ", {"SCRIPTSENTRY_CRAWL_DELAY_MS": "120"}):
            started = time.monotonic()
            politeness_wait("https://example.test/a.js")
            politeness_wait("https://example.test/b.js")
            politeness_wait("https://example.test/c.js")
            elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, 0.22, "two follow-up requests must wait ~120ms each")

    def test_delay_is_per_host(self):
        with mock.patch.dict("os.environ", {"SCRIPTSENTRY_CRAWL_DELAY_MS": "200"}):
            started = time.monotonic()
            politeness_wait("https://a.test/x.js")
            politeness_wait("https://b.test/x.js")
            elapsed = time.monotonic() - started
        self.assertLess(elapsed, 0.1, "different hosts must not wait for each other")

    def test_invalid_config_falls_back_to_off(self):
        with mock.patch.dict("os.environ", {"SCRIPTSENTRY_CRAWL_DELAY_MS": "banana"}):
            self.assertEqual(crawl_delay_seconds(), 0.0)

    def test_safe_get_waits(self):
        from core import url_policy
        waited = []
        with mock.patch.object(url_policy, "politeness_wait", side_effect=waited.append), \
                mock.patch.object(url_policy.requests, "Session", side_effect=AssertionError("no network")), \
                contextlib.suppress(AssertionError):
            url_policy.safe_get("https://example.test/x.js")
        self.assertEqual(waited, ["https://example.test/x.js"],
                         "safe_get must honor the politeness window before connecting")


if __name__ == "__main__":
    unittest.main()
