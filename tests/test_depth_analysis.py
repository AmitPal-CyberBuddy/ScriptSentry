import os
import tempfile
import unittest
import unittest.mock

from core import analyzer_service
from core import downloader
from core.analyzer_service import (
    _merge_into,
    extract_script_refs,
)
from core.downloader import download_js, get_safe_filename
from core.jobs import Job
from core.reporter import build_dashboard_payload


class MergeAndRefsTest(unittest.TestCase):
    def test_merge_into_dedups_by_content_hash(self):
        results = {}
        seen = set()
        self.assertTrue(_merge_into(results, "a.js", "const x = 1;", seen_hashes=seen))
        self.assertTrue("a.js" in results)
        self.assertFalse(_merge_into(results, "b.js", "const x = 1;", seen_hashes=seen))
        self.assertNotIn("b.js", results)

    def test_extract_script_refs_covers_import_require_dynamic_and_chunk(self):
        content = """
        import main from "./dep.js";
        import data from "./data.json";
        const helper = require("../utils/helper.js");
        import("./pages/home_123.js");
        const name = "chunk-42.js";
        fetch("/api/v1/items");
        new WebSocket("wss://example.com/live");
        """
        refs = extract_script_refs(content)
        self.assertIn("./dep.js", refs)
        self.assertIn("../utils/helper.js", refs)
        self.assertIn("./pages/home_123.js", refs)
        self.assertIn("chunk-42.js", refs)
        self.assertNotIn("./data.json", refs)
        self.assertNotIn("/api/v1/items", refs)
        self.assertNotIn("wss://example.com/live", refs)

    def test_safe_filename_is_url_unique(self):
        first = get_safe_filename("https://a.test/app.js")
        second = get_safe_filename("https://b.test/app.js")
        self.assertNotEqual(first, second)
        self.assertTrue(first.endswith(".js"))


class ProgressAndSummaryTest(unittest.TestCase):
    def test_download_js_reports_progress_without_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_dir = downloader.JS_DIR
            downloader.JS_DIR = tmp
            try:
                url = "https://example.com/assets/app.js"
                path = os.path.join(tmp, get_safe_filename(url))
                with open(path, "w", encoding="utf-8") as f:
                    f.write("const x = 1;" * 20)

                calls = []
                found = download_js([url], progress_callback=lambda **kw: calls.append(kw))
                self.assertEqual(len(found), 1)
                self.assertTrue(calls)
                self.assertEqual(calls[-1].get("phase"), "download")
                self.assertEqual(calls[-1].get("current"), 1)
                self.assertEqual(calls[-1].get("total"), 1)
            finally:
                downloader.JS_DIR = old_dir

    def test_job_tracks_percent_elapsed_and_eta(self):
        job = Job(max_files=10)
        job.start()
        job.update(phase="download", current=5, total=10, scanned_bytes=2000, total_bytes=5000)
        snap = job.snapshot()
        self.assertEqual(snap["phase"], "download")
        self.assertEqual(snap["percent"], 50.0)
        self.assertEqual(snap["files_scanned"], 5)
        self.assertEqual(snap["bytes_scanned"], 2000)
        self.assertGreaterEqual(snap["elapsed_ms"], 0)
        self.assertIsNotNone(snap["eta_seconds"])

    def test_url_scan_reports_all_discovered_files_and_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            js_dir = os.path.join(tmp, "js")
            beautify_dir = os.path.join(tmp, "beautified")
            os.makedirs(js_dir, exist_ok=True)
            os.makedirs(beautify_dir, exist_ok=True)
            p1 = os.path.join(beautify_dir, "app-1111111111.js")
            p2 = os.path.join(beautify_dir, "chunk-2222222222.js")
            with open(p1, "w", encoding="utf-8") as f:
                f.write("const a = 1;")
            with open(p2, "w", encoding="utf-8") as f:
                f.write("const b = 2;")

            calls = []
            with unittest.mock.patch.object(analyzer_service, "JS_DIR", js_dir), \
                 unittest.mock.patch.object(analyzer_service, "BEAUTIFY_DIR", beautify_dir), \
                 unittest.mock.patch.object(analyzer_service, "extract_js", return_value=[
                     "https://example.com/app.js",
                     "https://example.com/chunk-1.js",
                 ]), \
                 unittest.mock.patch.object(analyzer_service, "extract_inline_scripts", return_value=[
                     "const inline = 3;",
                 ]), \
                 unittest.mock.patch.object(analyzer_service, "download_js", return_value=[p1, p2]), \
                 unittest.mock.patch.object(analyzer_service, "beautify", return_value=[p1, p2]), \
                 unittest.mock.patch.object(analyzer_service, "_attach_runtime", side_effect=lambda results, *a, **k: results):
                results = analyzer_service.analyze_url(
                    "https://example.com/",
                    max_files=10,
                    max_depth=3,
                    progress_callback=lambda **kw: calls.append(kw),
                )

            self.assertEqual(len([k for k in results if not str(k).startswith("__")]), 3)
            summary = results["__scan_summary__"]
            self.assertEqual(summary["total_files"], 3)
            self.assertEqual(summary["total_discovered"], 3)
            self.assertEqual(summary["skipped_files"], 0)
            self.assertGreater(summary["bytes_scanned"], 0)
            self.assertIn("done", [c.get("phase") for c in calls])
            self.assertTrue(any(c.get("phase") == "inline_scan" for c in calls))

    def test_dashboard_payload_carries_scan_summary(self):
        results = {
            "a.js": {
                "file_size": 10,
                "secrets": [],
                "findings": [],
                "dataflows": [],
                "framework_findings": [],
                "risk_signals": [],
                "attack_surface": {},
                "dependency_scan": [],
                "transport": [],
                "request_methods": [],
                "api_calls": [],
                "api_inventory": [],
                "endpoints": [],
                "auth_summary": [],
                "storage_analysis": [],
                "technology_stack": [],
                "dom_risks": [],
                "data_flow_summary": [],
                "obfuscation_analysis": {},
                "notable_features": [],
                "decoded_strings": [],
                "suspicious_calls": [],
                "crypto_flows": [],
                "hardcoded_configs": [],
                "keys": [],
                "ivs": [],
                "configs": [],
                "dependency_scan": [],
            },
            "__scan_summary__": {
                "total_discovered": 8,
                "total_files": 2,
                "skipped_files": 6,
                "skipped_reasons": ["scanned_files_limit"],
                "bytes_scanned": 12345,
                "total_bytes": 99999,
                "max_files": 100,
                "capped": True,
            },
        }
        payload = build_dashboard_payload(results, metadata={"mode": "url", "source": "https://example.com/"})
        self.assertEqual(payload["meta"]["scan_summary"]["skipped_files"], 6)
        self.assertEqual(payload["summary"]["skipped_files"], 6)
        self.assertEqual(payload["summary"]["bytes_scanned"], 12345)
        self.assertEqual(payload["scan_summary"]["total_discovered"], 8)


if __name__ == "__main__":
    unittest.main()
