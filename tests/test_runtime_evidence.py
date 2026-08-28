import unittest

from core.reporter import build_dashboard_payload, build_report_model, generate_csv_report, generate_sarif_report
from core.runtime_evidence import attach_runtime_evidence, build_runtime_findings


class RuntimeEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.evidence = {
            "enabled": True,
            "available": True,
            "captured": True,
            "status": "captured",
            "reason": "",
            "url": "https://example.com/",
            "identity": "https://example.com/",
            "final_url": "https://example.com/app",
            "title": "Example",
            "duration_ms": 1234,
            "requests": [
                {"method": "POST", "url": "https://api.example.com/v1/login", "status": 200, "resource_type": "xhr"},
                {"method": "GET", "url": "https://example.com/chunk-abc.js", "status": 200, "resource_type": "script"},
            ],
            "console": [{"type": "error", "text": "boom", "url": "https://example.com/app", "line": 4}],
            "page_errors": [],
            "failed_requests": [{"url": "https://example.com/legacy.js", "failure": "net::ERR_ABORTED"}],
            "websockets": ["wss://example.com/socket"],
            "frames": ["https://example.com/frame.html"],
            "forms": ["/login"],
            "scripts": ["https://example.com/chunk-abc.js"],
            "frame_urls": ["https://example.com/frame.html"],
            "local_storage_keys": ["token"],
            "session_storage_keys": ["session"],
            "cookie_names": ["JSESSIONID", "theme"],
            "cookies": [{"name": "JSESSIONID", "domain": "example.com", "secure": True, "http_only": True}],
            "eval_calls": [{"kind": "eval", "code": "return 1", "url": "https://example.com/app"}],
            "string_timers": [{"kind": "setTimeout", "code": "alert(1)", "url": "https://example.com/app"}],
            "dom_sinks": [{"sink": "innerHTML", "value": "<b>user</b>", "url": "https://example.com/app"}],
            "storage_writes": [{"storage": "localStorage", "key": "token", "valueLength": 200, "url": "https://example.com/app"}],
            "storage_removals": [],
        }

    def test_build_runtime_findings(self):
        findings = build_runtime_findings(self.evidence, "https://example.com/")
        by_id = {f.get("id"): f for f in findings}
        self.assertIn("runtime_eval", by_id)
        self.assertIn("runtime_dom_sink", by_id)
        self.assertIn("runtime_sensitive_storage", by_id)
        self.assertIn("runtime_websocket", by_id)
        self.assertTrue(all(f.get("evidence_type") == "runtime_browser" for f in findings))
        self.assertEqual(by_id["runtime_eval"]["severity"], "HIGH")
        self.assertEqual(by_id["runtime_dom_sink"]["status"], "confirmed")

    def test_missing_or_disabled_evidence_produces_no_findings(self):
        offline = {"enabled": True, "available": False, "captured": False, "status": "missing_dependency", "reason": "no playwright"}
        self.assertEqual(build_runtime_findings(offline, "https://example.com/"), [])
        results = {}
        attach_runtime_evidence(results, offline, "https://example.com/")
        self.assertEqual(results.get("__runtime_findings__"), [])
        self.assertEqual(results["__runtime_evidence__"]["status"], "missing_dependency")

    def test_reporter_includes_runtime_findings_and_exports(self):
        results = {
            "static.js": {
                "secrets": [], "keys": [], "ivs": [], "crypto": [], "endpoints": [],
                "headers": [], "storage": [], "dom_risks": [], "suspicious_calls": [],
                "hardcoded_configs": [], "decoded_strings": [], "risk_signals": [],
                "dataflows": [], "framework_findings": [], "findings": [],
                "finding_statuses": {}, "dependency_scan": [], "technology_stack": [],
                "api_inventory": [], "auth_summary": [], "storage_analysis": [],
                "config_summary": [], "data_flow_summary": [], "notable_features": [],
                "ast_analysis": {}, "transport": [], "request_methods": [],
                "secret_analysis": [], "obfuscation_analysis": {}, "file_size": 10, "line_count": 1,
                "score": 0,
            }
        }
        attach_runtime_evidence(results, self.evidence, "https://example.com/")

        model = build_report_model(results, metadata={"mode": "url", "source": "https://example.com/"})
        payload = build_dashboard_payload(results, metadata={"mode": "url", "source": "https://example.com/"})

        self.assertEqual(model["runtime"]["status"], "captured")
        self.assertEqual(payload["runtime_evidence"]["status"], "captured")
        self.assertGreaterEqual(len(model["runtime_findings"]), 1)
        runtime_ids = {f.get("id") for f in payload["runtime_findings"]}
        self.assertIn("runtime_eval", runtime_ids)
        self.assertTrue(payload["meta"]["runtime_evidence"])
        self.assertIn("runtime_eval", model["summary"]["signals"][0].get("id", ""))

        csv = generate_csv_report(results)
        sarif = generate_sarif_report(results)
        self.assertIn("runtime_eval", csv)
        self.assertIn("runtime_browser", sarif)


if __name__ == "__main__":
    unittest.main()
