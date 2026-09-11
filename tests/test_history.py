"""Local scan history + diffing (SQLite) contract tests.

Covers core.history (record/diff/list/get/prune, kill switch), the
JobManager recording hook (results gain __history__ before complete), and
the shipped UI wiring (literal source checks, same style as
DashboardPollContractTest). Every test points SCRIPTSENTRY_STATE_DIR at its
own temp directory so the suite never touches a real history database.
"""
import json
import os
import tempfile
import threading
import time
import unittest
from unittest import mock

from core import history
from core.jobs import JobManager

APP_JS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "webui", "app.js")
TOOL_HTML = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "webui", "tool", "index.html")


def _results(findings_by_doc, bytes_scanned=500_000, files=1):
    docs = {}
    for name, findings in findings_by_doc.items():
        docs[name] = {"loc_id": name, "findings": findings}
    docs["__scan_summary__"] = {"total_files": files, "bytes_scanned": bytes_scanned}
    return docs


class HistoryBase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="scriptsentry-history-tests-")
        self.addCleanup(tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {"SCRIPTSENTRY_STATE_DIR": tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)


class HistoryStoreTest(HistoryBase):
    def test_first_scan_reports_all_new_without_previous(self):
        info = history.record_scan(
            _results({"app.js": [
                {"id": "dom_injection", "severity": "HIGH", "title": "DOM XSS",
                 "file": "app.js", "evidence": ["q -> el.innerHTML"]},
            ]}),
            mode="url", target="https://x.test/", duration_ms=1200)
        self.assertIsNone(info["previous_scan_id"])
        self.assertEqual(info["new_count"], 1)
        self.assertEqual(info["resolved_count"], 0)

    def test_unchanged_findings_do_not_flap(self):
        finding = {"id": "dom_injection", "severity": "HIGH", "title": "DOM XSS",
                   "file": "app.js", "evidence": ["q -> el.innerHTML"]}
        history.record_scan(_results({"app.js": [finding]}), mode="url", target="https://x.test/")
        # Same finding, different line/file metadata noise must not matter.
        moved = dict(finding)
        moved["line"] = 999
        info = history.record_scan(_results({"app.js": [moved]}), mode="url", target="https://x.test/")
        self.assertEqual(info["new_count"], 0)
        self.assertEqual(info["resolved_count"], 0)
        self.assertEqual(info["unchanged_count"], 1)

    def test_resolved_and_new_are_counted(self):
        base = {"id": "dom_injection", "severity": "HIGH", "title": "DOM XSS",
                "file": "app.js", "evidence": ["q -> el.innerHTML"]}
        history.record_scan(_results({"app.js": [base]}), mode="url", target="https://x.test/")
        fixed = {"id": "unsafe_runtime", "severity": "MEDIUM", "title": "eval", "file": "app.js"}
        info = history.record_scan(_results({"app.js": [fixed]}), mode="url", target="https://x.test/")
        self.assertEqual(info["new_count"], 1)
        self.assertEqual(info["resolved_count"], 1)

    def test_different_targets_do_not_cross_diff(self):
        finding = {"id": "dom_injection", "severity": "HIGH", "title": "T", "file": "a.js"}
        history.record_scan(_results({"a.js": [finding]}), mode="url", target="https://a.test/")
        info = history.record_scan(_results({"a.js": [dict(finding)]}), mode="url", target="https://b.test/")
        self.assertIsNone(info["previous_scan_id"])
        self.assertEqual(info["new_count"], 1)

    def test_list_get_and_report_roundtrip(self):
        results = _results({"app.js": [{"id": "s", "severity": "LOW", "title": "x", "file": "app.js"}]})
        info = history.record_scan(results, mode="code", target="paste.js", duration_ms=10)
        scans = history.list_scans()
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["scan_id"], info["scan_id"])
        stored = history.get_scan(info["scan_id"], include_report=True)
        self.assertTrue(stored["report_stored"])
        self.assertEqual(stored["report"]["app.js"]["loc_id"], "app.js")

    def test_oversized_reports_keep_summary_only(self):
        big = _results({"app.js": [{"id": "s", "severity": "LOW", "title": "x" * 20,
                                    "file": "app.js"}]})
        with mock.patch.object(history, "MAX_REPORT_BYTES", 10):
            info = history.record_scan(big, mode="code", target="big.js")
        stored = history.get_scan(info["scan_id"], include_report=True)
        self.assertFalse(stored["report_stored"])
        self.assertIsNone(stored.get("report"))

    def test_retention_prunes_old_scans(self):
        finding = {"id": "s", "severity": "LOW", "title": "x", "file": "a.js"}
        with mock.patch.dict(os.environ, {"SCRIPTSENTRY_HISTORY_MAX": "10"}):
            for _ in range(14):
                history.record_scan(_results({"a.js": [finding]}), mode="url", target="t")
        self.assertEqual(len(history.list_scans(limit=200)), 10)

    def test_kill_switch_disables_recording(self):
        with mock.patch.dict(os.environ, {"SCRIPTSENTRY_HISTORY": "0"}):
            info = history.record_scan(_results({"a.js": []}), mode="url", target="t")
        self.assertIsNone(info)
        self.assertFalse(os.path.exists(history.db_path()))

    def test_history_failure_never_raises(self):
        with mock.patch.object(history, "_connect", side_effect=RuntimeError("boom")):
            self.assertIsNone(history.record_scan(_results({"a.js": []}), mode="url", target="t"))

    def test_diff_endpoint_shape(self):
        first = history.record_scan(_results({"a.js": [{"id": "x", "title": "t"}]}), mode="url", target="t")
        second = history.record_scan(_results({"a.js": []}), mode="url", target="t")
        diff = history.diff_scans(first["scan_id"], second["scan_id"])
        self.assertEqual(diff["resolved_count"], 1)
        self.assertEqual(diff["new_count"], 0)


class JobRecordingTest(HistoryBase):
    def test_completed_job_gains_history_info(self):
        manager = JobManager()
        job = manager.create(mode="url", source="https://x.test/")
        result = _results({"app.js": [{"id": "dom_injection", "title": "T", "file": "app.js"}]},
                          files=1)
        thread = manager.start(job.id, lambda: result)
        thread.join(timeout=10)
        self.assertEqual(job.status, "done")
        info = jobs_result_history(manager.result(job.id))
        self.assertIsNotNone(info)
        self.assertEqual(info["target"], "https://x.test/")
        self.assertIsNotNone(info["scan_id"])

    def test_failing_jobs_record_nothing(self):
        manager = JobManager()
        job = manager.create(mode="url", source="https://x.test/")

        def boom():
            raise ValueError("nope")

        thread = manager.start(job.id, boom)
        thread.join(timeout=10)
        self.assertEqual(job.status, "error")
        self.assertEqual(history.list_scans(), [])


def jobs_result_history(result):
    info = (result or {}).get("__history__")
    return info


class HistoryUiContractTest(unittest.TestCase):
    """The dashboard must surface the diff and the panel (literal checks)."""

    def setUp(self):
        with open(APP_JS, encoding="utf-8") as fh:
            self.app = fh.read()
        with open(TOOL_HTML, encoding="utf-8") as fh:
            self.tool = fh.read()

    def test_chip_and_panel_exist(self):
        for needle in ("renderHistoryChip", "refreshHistory", "viewHistoryScan",
                       "history-diff", "history-card"):
            self.assertIn(needle, self.app)
        for needle in ("history-card", "history-diff", "history-list"):
            self.assertIn(needle, self.tool)

    def test_rescan_and_compare_is_wired(self):
        """P1: re-running the last scan and showing the diff is one click."""
        for needle in ("rescanAndCompare", "updateRescanButton", "rescan-compare",
                       "lastQuery && !viewedScanNote"):
            self.assertIn(needle, self.app)
        self.assertIn('id="rescan-compare"', self.tool)
        # The demo report is not re-runnable: the button must hide for it.
        self.assertIn("updateRescanButton();  // the demo is not re-runnable", self.app)
        # And the listener is actually attached.
        self.assertIn('$("#rescan-compare")', self.app)

    def test_history_views_are_busy_disabled(self):
        self.assertIn('querySelectorAll(".history-view")', self.app,
                      "history View buttons must be disabled while a scan runs")

    def test_payload_history_is_rendered_when_present(self):
        self.assertIn("payload.history", self.app)


if __name__ == "__main__":
    unittest.main()
