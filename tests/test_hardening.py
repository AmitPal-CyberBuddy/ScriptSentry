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
    def test_ui_uses_local_assets_and_exposes_pairing_controls(self):
        root = os.path.join(os.path.dirname(os.path.dirname(__file__)), "webui")
        with open(os.path.join(root, "index.html"), encoding="utf-8") as handle:
            html = handle.read()
        self.assertIn('href="styles.css"', html)
        self.assertIn('src="app.js"', html)
        self.assertIn('id="engine-token"', html)
        self.assertIn('id="cancel-scan"', html)
        self.assertIn("Content-Security-Policy", html)
        self.assertNotIn("fonts.googleapis.com", html)


if __name__ == "__main__":
    unittest.main()
