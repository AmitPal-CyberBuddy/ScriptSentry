"""Unit coverage for pure discovery/downloader logic (no network).

``core/discovery`` and ``core/downloader`` had URL-scan coverage only; the
HTML asset extraction, sitemap parsing, filename rules and download
error paths are all deterministic and belong under direct unit tests.
"""
import hashlib
import importlib.util
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import discovery, downloader

PAGE_HTML = """
<html><head>
  <script src="/static/js/app.min.js"></script>
  <script src="https://cdn.example.com/lib.mjs"></script>
  <script>var tiny = 1;</script>
  <script>import { x } from './chunk-util.js'; boot("/static/js/chunk-main.js");</script>
  <link rel="modulepreload" href="/assets/pre.mjs">
  <link rel="preload" as="script" href="/assets/next.js">
  <link rel="prefetch" href="/assets/later.js">
  <link rel="stylesheet" href="/style.css">
  <link rel="preload" as="style" href="/font.css">
</head><body>
  <script>chunk-abc123.js</script>
  <a href="https://else.where.org/remote.js">x</a>
</body></html>
"""


@unittest.skipUnless(importlib.util.find_spec("bs4") is not None,
                     "script-tag extraction needs BeautifulSoup")
class ExtractAssetsTest(unittest.TestCase):
    def test_script_srcs_absolute_and_inline_kept(self):
        scripts, inline = discovery._extract_assets(PAGE_HTML, "https://example.com/")
        self.assertIn("https://example.com/static/js/app.min.js", scripts)
        self.assertIn("https://cdn.example.com/lib.mjs", scripts)
        # All three inline scripts are kept: module/bootstrap code is kept
        # regardless of length (min_js_size is 1), unlike the old arbitrary
        # 20-character threshold.
        self.assertEqual(len(inline), 3)
        self.assertIn("chunk-util.js", inline[1])
        self.assertIn("chunk-abc123.js", inline[2])

    def test_preload_links_and_bundler_hints(self):
        scripts, _ = discovery._extract_assets(PAGE_HTML, "https://example.com/")
        self.assertIn("https://example.com/assets/pre.mjs", scripts)
        self.assertIn("https://example.com/assets/next.js", scripts)
        self.assertIn("https://example.com/assets/later.js", scripts)
        self.assertIn("https://example.com/static/js/chunk-main.js", scripts)
        self.assertIn("https://example.com/chunk-abc123.js", scripts)
        self.assertIn("https://else.where.org/remote.js", scripts)

    def test_stylesheet_and_style_preloads_ignored(self):
        scripts, _ = discovery._extract_assets(PAGE_HTML, "https://example.com/")
        self.assertNotIn("https://example.com/style.css", scripts)
        self.assertNotIn("https://example.com/font.css", scripts)

    def test_soupless_fallback_still_finds_bundler_hints(self):
        with mock.patch.object(discovery, "BeautifulSoup", None):
            scripts, inline = discovery._extract_assets(PAGE_HTML, "https://example.com/")
        self.assertIn("https://example.com/chunk-abc123.js", scripts)
        self.assertEqual(inline, [])


class FetchUrlTest(unittest.TestCase):
    def test_non_200_and_exception_yield_empty(self):
        with mock.patch.object(discovery, "safe_get", return_value=mock.Mock(status_code=404)):
            self.assertEqual(discovery.fetch_url("https://example.com/"), "")
        with mock.patch.object(discovery, "safe_get", side_effect=OSError("boom")):
            self.assertEqual(discovery.fetch_url("https://example.com/"), "")

    def test_200_returns_bounded_text(self):
        resp = mock.Mock(status_code=200)
        with mock.patch.object(discovery, "safe_get", return_value=resp), \
                mock.patch.object(discovery, "read_response_text", return_value="<html></html>") as rd:
            self.assertEqual(discovery.fetch_url("https://example.com/"), "<html></html>")
            self.assertEqual(rd.call_args.kwargs.get("max_bytes"), discovery.MAX_PAGE_BYTES)


class SitemapDiscoveryTest(unittest.TestCase):
    def test_robots_and_sitemap_pages_feed_recon(self):
        def fake_fetch(url, timeout=15, cancel_check=None):
            if url.endswith("/robots.txt"):
                return "User-agent: *\nSitemap: https://example.com/map.xml\n"
            if url.endswith("/map.xml"):
                return "<loc>https://example.com/</loc><loc>https://example.com/pricing</loc>" \
                       "<loc>https://example.com/logo.png</loc><loc>https://other.com/page</loc>"
            return ""

        with mock.patch.object(discovery, "fetch_url", side_effect=fake_fetch):
            pages, meta = discovery.sitemap_pages("https://example.com/app")
        self.assertEqual(pages, ["https://example.com/", "https://example.com/pricing"])
        self.assertTrue(meta["sitemap_found"])
        self.assertEqual(meta["sitemap_source"], "robots.txt")
        self.assertEqual(meta["sitemap_pages"], 2)

    def test_failures_are_normal(self):
        with mock.patch.object(discovery, "fetch_url", return_value=""):
            pages, meta = discovery.sitemap_pages("https://example.com/")
        self.assertEqual(pages, [])
        self.assertFalse(meta["sitemap_found"])


class SafeFilenameTest(unittest.TestCase):
    def _digest(self, url):
        return hashlib.sha256(url.encode("utf-8", errors="ignore")).hexdigest()[:12]

    def test_rules(self):
        cases = [
            ("https://x.com/a/b/app.js?v=2", f"app-{self._digest('https://x.com/a/b/app.js?v=2')}.js"),
            ("https://x.com/a/lib.mjs", f"lib-{self._digest('https://x.com/a/lib.mjs')}.mjs"),
            ("https://x.com/", f"unknown-{self._digest('https://x.com/')}.js"),
            ("https://x.com/blob", f"unknown-{self._digest('https://x.com/blob')}.js"),
        ]
        for url, expected in cases:
            self.assertEqual(downloader.get_safe_filename(url), expected, url)

    def test_long_stems_truncated_but_unique(self):
        long_url = "https://x.com/" + "n" * 200 + ".js"
        name = downloader.get_safe_filename(long_url)
        self.assertLessEqual(len(name.split("-")[0]), 81)
        self.assertEqual(name, downloader.get_safe_filename(long_url))
        self.assertNotEqual(downloader.get_safe_filename("https://x.com/other.js"), name)


class DownloadFileTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = self.tmp.name

    def _url(self, tag):
        return f"https://example.com/static/{tag}.js"

    def test_cached_file_skips_network(self):
        url = self._url("cached")
        pre_path = os.path.join(self.out, downloader.get_safe_filename(url))
        with open(pre_path, "w", encoding="utf-8") as fh:
            fh.write("console.log('already here');")
        with mock.patch.object(downloader, "safe_get", side_effect=AssertionError("no network")):
            self.assertEqual(downloader.download_file(url, output_dir=self.out), pre_path)

    def test_cancelled_before_and_during(self):
        with mock.patch.object(downloader, "safe_get", side_effect=AssertionError("no network")):
            self.assertIsNone(downloader.download_file(self._url("c"), output_dir=self.out, cancel_check=lambda: True))
        calls = {"n": 0}

        def flip(*a, **k):
            calls["n"] += 1
            return calls["n"] > 1

        with mock.patch.object(downloader, "safe_get", side_effect=AssertionError("no network")):
            self.assertIsNone(downloader.download_file(self._url("c2"), output_dir=self.out, cancel_check=flip))
            # Checked at the top of the body, then at the top of the retry
            # loop; the request itself must never be attempted.
            self.assertEqual(calls["n"], 2)

    def test_soft_404_and_tiny_bodies_rejected(self):
        html_resp = mock.Mock(status_code=200)
        with mock.patch.object(downloader, "safe_get", return_value=html_resp), \
                mock.patch.object(downloader, "read_response_text", return_value="<html>login page</html>"):
            self.assertIsNone(downloader.download_file(self._url("soft"), output_dir=self.out))
        with mock.patch.object(downloader, "safe_get", return_value=mock.Mock(status_code=404)):
            self.assertIsNone(downloader.download_file(self._url("miss"), output_dir=self.out))

    def test_success_writes_file(self):
        body = "console.log('real module');\n" * 3
        url = self._url("ok")
        with mock.patch.object(downloader, "safe_get", return_value=mock.Mock(status_code=200)), \
                mock.patch.object(downloader, "read_response_text", return_value=body):
            path = downloader.download_file(url, output_dir=self.out)
        self.assertTrue(path and os.path.exists(path))
        with open(path, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), body.strip())

    def test_download_js_dedupes_and_reports(self):
        links = ["https://x.com/a.js", "https://x.com/a.js", "https://x.com/b.js"]
        with mock.patch.object(downloader, "download_file",
                               side_effect=[os.path.join(self.out, "a.js"), None]) as dl:
            progress = []
            result = downloader.download_js(
                links, progress_callback=lambda **kw: progress.append(kw), output_dir=self.out)
        self.assertEqual(dl.call_count, 2, "duplicate links must be fetched once")
        self.assertEqual(result, [os.path.join(self.out, "a.js")])
        self.assertEqual([p["current"] for p in progress], [1, 2])
        self.assertEqual(progress[-1]["total"], 2)


if __name__ == "__main__":
    unittest.main()
