import json
import os
import threading
import time
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from core.jobs import JobManager
from core.url_policy import validate_public_url


class URLPolicyTest(unittest.TestCase):
    def test_rejects_private_and_credential_urls(self):
        for url in (
            "http://127.0.0.1:8000/",
            "http://localhost/",
            "http://169.254.169.254/latest/meta-data/",
            "http://user:password@example.com/",
        ):
            allowed, reason = validate_public_url(url, resolve=False)
            self.assertFalse(allowed, url)
            self.assertTrue(reason)

    def test_allows_public_syntax_without_forcing_dns_in_unit(self):
        allowed, reason = validate_public_url("https://example.com/app.js", resolve=False)
        self.assertTrue(allowed, reason)

    def test_private_target_override_reaches_the_crawler_boundary(self):
        # The override must relax the destination checks *inside* the URL
        # boundary (safe_get re-validates every URL and redirect hop), not
        # only at the top-level call sites -- otherwise private-target scans
        # silently return zero files.
        previous = os.environ.get("SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS")
        try:
            os.environ["SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS"] = "1"
            for url in ("http://127.0.0.1:8000/", "http://localhost/", "http://192.168.1.10/x.js"):
                allowed, reason = validate_public_url(url, resolve=False)
                self.assertTrue(allowed, (url, reason))
            # Credential and scheme rules stay enforced even with the override.
            allowed, reason = validate_public_url("http://user:pass@127.0.0.1/", resolve=False)
            self.assertFalse(allowed)
            allowed, reason = validate_public_url("ftp://127.0.0.1/", resolve=False)
            self.assertFalse(allowed)
        finally:
            if previous is None:
                os.environ.pop("SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS", None)
            else:
                os.environ["SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS"] = previous


class JobLifecycleTest(unittest.TestCase):
    def test_terminal_jobs_are_evicted_and_active_jobs_are_bounded(self):
        manager = JobManager(max_jobs=1, retention_seconds=60)
        first = manager.create(mode="code", source="one.js")
        first.cancel()
        second = manager.create(mode="code", source="two.js")
        self.assertIsNone(manager.get(first.id))
        self.assertIsNotNone(manager.get(second.id))

        with self.assertRaises(RuntimeError):
            manager.create(mode="code", source="third.js")

    def test_cancel_before_start_prevents_target_execution(self):
        manager = JobManager(max_jobs=3)
        job = manager.create(mode="code", source="cancel.js")
        manager.cancel(job.id)
        ran = []
        manager.start(job.id, lambda: ran.append(True))
        time.sleep(0.03)
        self.assertEqual(job.snapshot()["status"], "canceled")
        self.assertEqual(ran, [])


class APISecuritySmokeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import server
        cls.server_module = server
        cls.httpd = server.make_server("127.0.0.1", 0)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)
        cls.server_module.jobs.clear_all()

    def request(self, path, method="GET", body=None, token=None, origin=None):
        headers = {}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if token:
            headers["X-ScriptSentry-Token"] = token
        if origin:
            headers["Origin"] = origin
        request = Request(
            self.base + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers=headers,
            method=method,
        )
        try:
            with urlopen(request, timeout=3) as response:
                return response.status, response.headers, response.read()
        except HTTPError as exc:
            return exc.code, exc.headers, exc.read()

    def test_health_is_public_but_analysis_requires_pairing(self):
        status, headers, body = self.request("/api/health")
        self.assertEqual(status, 200)
        health = json.loads(body)
        self.assertTrue(health["auth_required"])
        self.assertNotIn(self.server_module.API_TOKEN, body.decode())

        status, _, body = self.request("/api/analyze", method="POST", body={"mode": "code", "code": "const x = 1;"})
        self.assertEqual(status, 401)
        self.assertIn("token", body.decode().lower())

    def test_directories_without_an_index_are_not_listed(self):
        """/assets/ must 404 instead of serving a directory listing."""
        status, _, _ = self.request("/assets/")
        self.assertEqual(status, 404)
        # Real pages (dirs with index.html) keep working.
        status, _, _ = self.request("/home/")
        self.assertEqual(status, 200)

    def test_origin_and_payload_boundaries_are_enforced(self):
        status, _, _ = self.request(
            "/api/analyze",
            method="POST",
            body={"mode": "code", "code": "const x = 1;"},
            token=self.server_module.API_TOKEN,
            origin="https://evil.example",
        )
        self.assertEqual(status, 403)

        status, headers, body = self.request(
            "/api/analyze",
            method="POST",
            body={"mode": "code", "code": "const value = 1;", "filename": "inline.js"},
            token=self.server_module.API_TOKEN,
            origin="http://localhost:3000",
        )
        self.assertEqual(status, 200, body.decode())
        job_id = json.loads(body)["job_id"]
        self.assertTrue(headers.get("Cache-Control") == "no-store")

        for _ in range(250):
            status, _, status_body = self.request(
                f"/api/status?job_id={job_id}", token=self.server_module.API_TOKEN
            )
            self.assertEqual(status, 200)
            job = json.loads(status_body)["job"]
            if job["status"] == "done":
                break
            time.sleep(0.02)
        self.assertEqual(job["status"], "done")

        status, _, result_body = self.request(
            f"/api/result?job_id={job_id}", token=self.server_module.API_TOKEN
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(result_body)["ready"])

        status, report_headers, report_body = self.request(
            "/api/report?format=sarif",
            method="POST",
            body={"job_id": job_id},
            token=self.server_module.API_TOKEN,
        )
        self.assertEqual(status, 200)
        self.assertEqual(report_headers.get_content_type(), "application/sarif+json")
        self.assertIn('"runs"', report_body.decode())

    def test_private_target_is_rejected_before_a_job_is_created(self):
        status, _, body = self.request(
            "/api/analyze",
            method="POST",
            body={"mode": "url", "url": "http://127.0.0.1:1/"},
            token=self.server_module.API_TOKEN,
        )
        self.assertEqual(status, 400)
        self.assertIn("local", body.decode().lower())


class WebUICompletenessTest(unittest.TestCase):
    """The dashboard is three static pages sharing one stylesheet and script.

    ``home/index.html`` is the landing page, ``tool/index.html`` hosts the
    analysis console, and ``changelog/index.html`` is generated from
    CHANGELOG.md. All must stay self-contained: local assets only, a CSP, no
    third-party font/CDN dependencies.
    """

    def _read(self, *parts):
        root = os.path.join(os.path.dirname(os.path.dirname(__file__)), "webui")
        with open(os.path.join(root, *parts), encoding="utf-8") as handle:
            return handle.read()

    def test_pages_use_local_assets_and_declare_a_csp(self):
        for page in ("home/index.html", "tool/index.html"):
            with self.subTest(page=page):
                html = self._read(*page.split("/"))
                self.assertIn('href="../styles.css"', html)
                self.assertIn('src="../app.js"', html)
                self.assertIn('src="../config.js"', html)
                self.assertIn("Content-Security-Policy", html)
                self.assertNotIn("fonts.googleapis.com", html)

    def test_console_page_exposes_pairing_and_scan_controls(self):
        html = self._read("tool", "index.html")
        self.assertIn('id="engine-token"', html)
        self.assertIn('id="cancel-scan"', html)
        self.assertIn('id="code-input"', html)
        self.assertIn('id="url-input"', html)

    def test_landing_page_links_to_the_console(self):
        html = self._read("home", "index.html")
        self.assertIn('href="tool/"', html)
        # Brand assets referenced by <link rel="icon"> must exist on disk.
        root = os.path.join(os.path.dirname(os.path.dirname(__file__)), "webui")
        for asset in ("assets/favicon.svg", "assets/site.webmanifest", "assets/og-card.png"):
            with self.subTest(asset=asset):
                self.assertIn(asset, html)
                self.assertTrue(os.path.isfile(os.path.join(root, asset)))


if __name__ == "__main__":
    unittest.main()
