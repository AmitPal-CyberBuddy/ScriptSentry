"""Sitemap/robots.txt discovery tests.

The engine follows pages a site *declares* (robots.txt ``Sitemap:`` lines
and /sitemap.xml) to reach lazy chunks the landing page never references.
Strictly bounded: same-origin pages only, no asset URLs, at most
``MAX_SITEMAP_PAGES`` pages. These tests run against a loopback HTTP site;
``SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS`` must be set (the suite sets it in
conftest-style env or the tests skip).
"""
import http.server
import os
import shutil
import socketserver
import tempfile
import threading
import unittest
from functools import partial
from unittest import mock

from core.analyzer_service import analyze_url
from core.discovery import MAX_SITEMAP_PAGES, sitemap_pages

# Loopback targets are subject to the same SSRF guard as public scans; run
# these tests only when the guard is deliberately relaxed (same contract as
# the other loopback pipeline tests). Module level must NOT set the flag:
# unittest discover imports every module before running any test, and a set
# here would disable the SSRF guard for the whole process.
requires_private_targets = unittest.skipUnless(
    os.environ.get("SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS"),
    "loopback scan targets need SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS=1",
)


class _SiteHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


class SitemapSite:
    def __init__(self, root, port):
        self.workdir = root
        js = os.path.join(root, "js")
        os.makedirs(js, exist_ok=True)
        origin = f"http://127.0.0.1:{port}"
        # Landing page: references app.js only.
        with open(os.path.join(root, "index.html"), "w", encoding="utf-8") as fh:
            fh.write('<!doctype html><html><body><script src="/js/app.js"></script></body></html>')
        # A second page reachable ONLY via the sitemap; it loads a lazy chunk.
        with open(os.path.join(root, "admin.html"), "w", encoding="utf-8") as fh:
            fh.write('<!doctype html><html><body><script src="/js/admin-chunk.js"></script></body></html>')
        with open(os.path.join(js, "app.js"), "w", encoding="utf-8") as fh:
            fh.write("const app = 1;\n")
        with open(os.path.join(js, "admin-chunk.js"), "w", encoding="utf-8") as fh:
            fh.write("const q = location.hash; document.body.innerHTML = q;\n")
        # robots.txt declares the sitemap.
        with open(os.path.join(root, "robots.txt"), "w", encoding="utf-8") as fh:
            fh.write("User-agent: *\nSitemap: /sitemap.xml\n")
        with open(os.path.join(root, "sitemap.xml"), "w", encoding="utf-8") as fh:
            fh.write('<?xml version="1.0"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                     f"<url><loc>{origin}/admin.html</loc></url>"
                     f"<url><loc>{origin}/js/app.js</loc></url>"
                     "<url><loc>http://other-origin.example/page</loc></url>"
                     "</urlset>")


@requires_private_targets
class SitemapPagesTest(unittest.TestCase):
    def setUp(self):
        self.workdir = tempfile.mkdtemp(prefix="scriptsentry-sitemap-")
        handler = partial(_SiteHandler, directory=self.workdir)
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
        self.port = self.server.server_address[1]
        SitemapSite(self.workdir, self.port)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.workdir, ignore_errors=True)

    def test_robots_declared_pages_are_returned_sanitized(self):
        pages, meta = sitemap_pages(f"http://127.0.0.1:{self.port}/", timeout=5)
        self.assertTrue(meta["sitemap_found"])
        self.assertEqual(meta["sitemap_source"], "robots.txt")
        # The .js URL and the cross-origin URL are dropped; the page stays.
        self.assertEqual(pages, [f"http://127.0.0.1:{self.port}/admin.html"])

    def test_page_cap_is_enforced(self):
        body = "<?xml version='1.0'?><urlset>" + "".join(
            f"<url><loc>http://127.0.0.1:{self.port}/p{i}.html</loc></url>"
            for i in range(50)) + "</urlset>"
        with open(os.path.join(self.workdir, "sitemap.xml"), "w", encoding="utf-8") as fh:
            fh.write(body)
        pages, meta = sitemap_pages(f"http://127.0.0.1:{self.port}/", timeout=5)
        self.assertLessEqual(len(pages), MAX_SITEMAP_PAGES)
        self.assertEqual(meta["sitemap_pages"], len(pages))

    def test_missing_sitemap_is_a_clean_empty(self):
        os.remove(os.path.join(self.workdir, "sitemap.xml"))
        os.remove(os.path.join(self.workdir, "robots.txt"))
        pages, meta = sitemap_pages(f"http://127.0.0.1:{self.port}/", timeout=5)
        self.assertEqual(pages, [])
        self.assertFalse(meta["sitemap_found"])


@requires_private_targets
class SitemapScanIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.workdir = tempfile.mkdtemp(prefix="scriptsentry-sitemap-scan-")
        handler = partial(_SiteHandler, directory=self.workdir)
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
        self.port = self.server.server_address[1]
        SitemapSite(self.workdir, self.port)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.workdir, ignore_errors=True)

    def test_scan_reaches_sitemap_only_scripts(self):
        url = f"http://127.0.0.1:{self.port}/index.html"
        results = analyze_url(url, max_depth=2, timeout=8, max_files=10, max_workers=2)
        # Result keys are local workspace paths; the sitemap-only chunk is
        # recognized by its (preserved) file-name stem.
        self.assertTrue(any("admin-chunk" in key for key in results),
                        f"the sitemap-declared lazy chunk must be analyzed: {list(results)}")
        summary_page = (results.get("__scan_summary__", {}).get("page") or {})
        self.assertTrue(summary_page.get("sitemap", {}).get("sitemap_found"))

    def test_kill_switch_skips_sitemap_discovery(self):
        url = f"http://127.0.0.1:{self.port}/index.html"
        with mock.patch.dict(os.environ, {"SCRIPTSENTRY_SITEMAP_DISCOVERY": "0"}):
            results = analyze_url(url, max_depth=1, timeout=8, max_files=10, max_workers=2)
        self.assertNotIn("js/admin-chunk.js", " ".join(results.keys()))
        summary_page = (results.get("__scan_summary__", {}).get("page") or {})
        self.assertNotIn("sitemap", summary_page)


if __name__ == "__main__":
    unittest.main()
