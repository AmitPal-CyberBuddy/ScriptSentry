"""\"Data & storage" trust-surface contract tests.

The engine is local-first, so this suite makes the claim verifiable:

* ``/api/storage`` inventories the engine's files (SQLite WAL history +
  the ETA calibration file) and names the browser keys;
* destructive history routes are DELETE-only, pairing-token-gated, and
  reject untrusted origins (same checks as the analysis routes);
* wiping ALL history is a real wipe in WAL mode — the ``history.db``,
  ``-wal`` and ``-shm`` files are removed and an empty DB is recreated —
  while ``eta_calibration.json`` survives unless explicitly requested;
* the export carries scans + findings + diffs, and stored report payloads
  only behind ``include=payload``;
* the tool page ships the storage panel with the honest "never stored"
  copy.

Endpoint tests follow the server-based style of ``test_hardening.py``
(``server.make_server("127.0.0.1", 0)`` + ``server_module.API_TOKEN``).
"""
import json
import os
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest import mock

from core import history

APP_JS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "webui", "app.js")
TOOL_HTML = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "webui", "tool", "index.html")


def _results(findings_by_doc, bytes_scanned=500_000, files=1):
    docs = {}
    for name, findings in findings_by_doc.items():
        docs[name] = {"loc_id": name, "findings": findings}
    docs["__scan_summary__"] = {"total_files": files, "bytes_scanned": bytes_scanned}
    return docs


def _finding(fid="dom_injection", title="DOM XSS", file="app.js"):
    return {"id": fid, "severity": "HIGH", "title": title,
            "file": file, "evidence": ["q -> el.innerHTML"]}


class StorageEndpointTest(unittest.TestCase):
    """Live-server checks for /api/storage and the destructive routes."""

    @classmethod
    def setUpClass(cls):
        import server
        cls.server_module = server
        cls._tmpdir = tempfile.TemporaryDirectory(prefix="scriptsentry-storage-api-")
        cls._env = mock.patch.dict(os.environ, {
            "SCRIPTSENTRY_STATE_DIR": cls._tmpdir.name,
            "SCRIPTSENTRY_HISTORY": "1",
        })
        cls._env.start()
        cls.httpd = server.make_server("127.0.0.1", 0)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)
        cls._env.stop()
        cls._tmpdir.cleanup()

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

    @classmethod
    def _seed(cls, scans=2, findings=2):
        added = []
        for i in range(scans):
            docs = {"app.js": [_finding(fid=f"f{i}-{j}", title=f"T{i}-{j}") for j in range(findings)]}
            added.append(history.record_scan(
                _results(docs), mode="url", target=f"https://x{i}.test/", duration_ms=10))
        return added

    def test_storage_requires_token_and_trusted_origin(self):
        history.wipe_history()
        status, _, _ = self.request("/api/storage")
        self.assertEqual(status, 401)
        status, _, body = self.request(
            "/api/storage", token=self.server_module.API_TOKEN,
            origin="https://evil.example",
        )
        self.assertEqual(status, 403)
        self.assertIn("origin", body.decode().lower())

    def test_storage_reports_live_facts(self):
        history.wipe_history()
        info = self._seed(scans=2, findings=2)[-1]
        status, _, body = self.request("/api/storage", token=self.server_module.API_TOKEN)
        self.assertEqual(status, 200)
        storage = json.loads(body)["storage"]
        self.assertTrue(storage["history_enabled"])
        self.assertTrue(storage["db_path"].endswith("history.db"))
        self.assertGreater(storage["db_size_bytes"], 0)
        self.assertGreaterEqual(storage["wal_size_bytes"], 0)
        self.assertEqual(storage["scan_count"], 2)
        self.assertEqual(storage["finding_count"], 4)
        self.assertIsNotNone(storage["oldest_scan_at"])
        self.assertIsNotNone(storage["newest_scan_at"])
        self.assertGreaterEqual(storage["newest_scan_at"], storage["oldest_scan_at"])
        self.assertEqual(storage["retention_limit"], 200)
        self.assertGreater(storage["report_bytes_stored"], 0)
        self.assertGreaterEqual(storage["eta_calibration_bytes"], 0)
        self.assertEqual(storage["browser_notes"], {
            "triage": "localStorage",
            "last_result": "sessionStorage",
            "token": "sessionStorage",
        })
        self.assertGreaterEqual(info["scan_id"], 1)

    def test_delete_one_scan_removes_row_and_findings(self):
        history.wipe_history()
        first, second = self._seed(scans=2, findings=2)
        status, _, _ = self.request(
            f"/api/history/{first['scan_id']}",
            method="DELETE", token=self.server_module.API_TOKEN,
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(history.list_scans()), 1)
        self.assertEqual(history.list_scans()[0]["scan_id"], second["scan_id"])
        # Deleting the same scan again is a 404, and a missing token is 401.
        status, _, _ = self.request(
            f"/api/history/{first['scan_id']}", method="DELETE",
            token=self.server_module.API_TOKEN,
        )
        self.assertEqual(status, 404)
        status, _, _ = self.request(f"/api/history/{second['scan_id']}", method="DELETE")
        self.assertEqual(status, 401)

    def test_destructive_routes_reject_untrusted_origins(self):
        history.wipe_history()
        self._seed(scans=1, findings=1)
        status, _, body = self.request(
            "/api/history", method="DELETE",
            token=self.server_module.API_TOKEN, origin="https://evil.example",
        )
        self.assertEqual(status, 403)
        self.assertIn("origin", body.decode().lower())
        # POST is not a destructive route: it must never delete history.
        status, _, _ = self.request(
            "/api/history", method="POST", body={},
            token=self.server_module.API_TOKEN,
        )
        self.assertEqual(status, 404)
        self.assertEqual(len(history.list_scans()), 1)

    def test_delete_all_recreates_clean_db_and_keeps_calibration(self):
        history.wipe_history()
        self._seed(scans=3, findings=1)
        calibration = os.path.join(os.path.dirname(history.db_path()), "eta_calibration.json")
        with open(calibration, "w", encoding="utf-8") as fh:
            fh.write('{"entries": {"analyze:process": {"ratio": 1.0}}}')
        db_path = history.db_path()
        self.assertTrue(os.path.exists(db_path))
        status, _, body = self.request(
            "/api/history", method="DELETE", token=self.server_module.API_TOKEN,
        )
        self.assertEqual(status, 200)
        wiped = json.loads(body)
        self.assertEqual(wiped["deleted_scans"], 3)
        self.assertEqual(wiped["deleted_findings"], 3)
        self.assertTrue(wiped["recreated"])
        # The database file comes back clean: rows are gone, schema works.
        self.assertTrue(os.path.exists(db_path))
        self.assertEqual(history.list_scans(), [])
        self.assertTrue(os.path.exists(calibration), "ETA stats are not user content")
        # A fresh scan after the wipe works.
        info = history.record_scan(_results({"app.js": [_finding()]}), mode="code", target="after.js")
        self.assertIsNotNone(info)
        self.assertEqual(len(history.list_scans()), 1)
        # include_calibration=true explicitly removes the anonymous stats too.
        calibration_deleted = history.wipe_history(include_calibration=True)
        self.assertTrue(calibration_deleted["calibration_deleted"])
        self.assertFalse(os.path.exists(calibration))

    def test_export_shape_without_and_with_payloads(self):
        history.wipe_history()
        self._seed(scans=2, findings=2)
        status, headers, body = self.request(
            "/api/history/export", token=self.server_module.API_TOKEN,
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers.get_content_type(), "application/json")
        self.assertIn("attachment", headers.get("Content-Disposition", ""))
        data = json.loads(body)
        self.assertEqual(data["scan_count"], 2)
        self.assertEqual(data["finding_count"], 4)
        self.assertEqual(len(data["scans"]), 2)
        by_id = {s["scan_id"]: s for s in data["scans"]}
        self.assertEqual(list(by_id), sorted(by_id))
        for scan in data["scans"]:
            self.assertIn("created_at", scan)
            self.assertIn("target", scan)
            self.assertIn("mode", scan)
            self.assertEqual(len(scan["findings"]), 2)
            self.assertIn("diff", scan)
            self.assertNotIn("report", scan, "payloads must be opt-in")

        status, _, body = self.request(
            "/api/history/export?include=payload", token=self.server_module.API_TOKEN,
        )
        data = json.loads(body)
        for scan in data["scans"]:
            self.assertIn("report", scan)
            # Stored payload is the raw results dict (loc_id per document).
            self.assertEqual(scan["report"]["app.js"]["loc_id"], "app.js")
        self.assertEqual(data["finding_count"], 4)

    def test_export_requires_token(self):
        status, _, _ = self.request("/api/history/export")
        self.assertEqual(status, 401)


class HistoryWipeTest(unittest.TestCase):
    """File-level wipe checks (no server): WAL files die, DB is recreated."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="scriptsentry-storage-wipe-")
        self.addCleanup(tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {"SCRIPTSENTRY_STATE_DIR": tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)
        history.wipe_history()

    def test_wipe_removes_database_files_and_recreates_empty_db(self):
        history.record_scan(_results({"a.js": [_finding()]}), mode="code", target="a.js")
        path = history.db_path()
        self.assertTrue(os.path.exists(path))
        info = history.wipe_history()
        self.assertTrue(info["recreated"])
        self.assertTrue(os.path.exists(path))
        self.assertEqual(history.list_scans(), [])
        # No stale -wal/-shm content: a fresh insert is clean (1 scan, 1 row).
        again = history.record_scan(_results({"b.js": [_finding()]}), mode="code", target="b.js")
        self.assertIsNotNone(again)
        self.assertEqual(len(history.list_scans()), 1)

    def test_wipe_keeps_eta_calibration_by_default(self):
        eta = os.path.join(os.environ["SCRIPTSENTRY_STATE_DIR"], "eta_calibration.json")
        with open(eta, "w", encoding="utf-8") as fh:
            fh.write('{"entries": {}}')
        history.wipe_history()
        self.assertTrue(os.path.exists(eta))
        history.wipe_history(include_calibration=True)
        self.assertFalse(os.path.exists(eta))

    def test_delete_scan_cascade_removes_findings(self):
        info = history.record_scan(_results({"a.js": [_finding(), _finding(fid="x2")]}),
                                   mode="url", target="t")
        self.assertTrue(history.delete_scan(info["scan_id"]))
        self.assertEqual(history.list_scans(), [])
        self.assertFalse(history.delete_scan(info["scan_id"]))
        self.assertFalse(history.delete_scan("not-a-number"))


class StorageUiContractTest(unittest.TestCase):
    """The tool page ships the panel and the honest "never stored" copy."""

    def setUp(self):
        with open(TOOL_HTML, encoding="utf-8") as fh:
            self.tool = fh.read()
        with open(APP_JS, encoding="utf-8") as fh:
            self.app = fh.read()

    def test_panel_lives_in_the_setup_modal_aside(self):
        aside_at = self.tool.index('class="modal-col modal-col-aside"')
        storage_at = self.tool.index('id="storage-section"')
        self.assertLess(
            aside_at, storage_at,
            "storage panel must live inside the modal-col-aside column, not "
            "as a fourth page",
        )
        for needle in (
            'id="storage-section"', 'id="storage-title"', 'id="storage-facts"',
            'id="storage-scan-list"', 'id="storage-delete-all"',
            'id="storage-clear-browser"', 'id="storage-export"',
            'id="storage-clear-token"', 'id="history-storage-link"',
        ):
            self.assertIn(needle, self.tool, f"tool page is missing {needle}")

    def test_never_stored_copy_states_the_negatives(self):
        for needle in (
            "Never stored:", "cookie values", "request bodies",
            "localStorage values", "form inputs",
            "Scan content never leaves your machine",
        ):
            self.assertIn(needle, self.tool, f"missing honesty copy: {needle}")

    def test_app_wires_storage_endpoints_and_destructive_actions(self):
        for needle in (
            '"/api/storage"', '"/api/history/export?include=payload"',
            'method: "DELETE"', "data-storage-delete", 'scriptsentry-triage',
            "scriptsentry_last_result", "storage-clear-token", "confirm(",
        ):
            self.assertIn(needle, self.app, f"app.js is missing {needle}")

    def test_storage_controls_are_scan_busy_disabled(self):
        self.assertIn("#storage-delete-all", self.app,
                      "delete-all must be disabled while a scan runs")
        self.assertIn('querySelectorAll(".storage-scan-delete")', self.app,
                      "per-scan delete buttons must be disabled while a scan runs")
        self.assertIn("refreshStoragePanel", self.app)
        self.assertIn("openPrivacyModal", self.app)


if __name__ == "__main__":
    unittest.main()
