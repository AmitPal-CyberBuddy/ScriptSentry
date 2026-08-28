import unittest

from core.reporter import build_dashboard_payload, build_report_model, generate_csv_report, generate_sarif_report
from core.script_intel import build_script_intel, data_exfiltration_candidates


class ScriptIntelTest(unittest.TestCase):
    def setUp(self):
        self.target = "https://example.com/"
        self.app_data = {
            "file_size": 400,
            "line_count": 20,
            "content_sha256": "abc123",
            "secrets": [],
            "keys": [],
            "ivs": [],
            "crypto": [],
            "endpoints": ["/api/v1/profile"],
            "api_calls": ["/api/v1/profile"],
            "headers": [],
            "storage": ["localStorage.setItem"],
            "hardcoded_configs": [],
            "decoded_strings": [],
            "suspicious_calls": [],
            "dom_risks": ["innerHTML"],
            "risk_signals": [],
            "dataflows": [{"id": "dom_injection", "source": "URL query string", "sink": "innerHTML", "severity": "HIGH"}],
            "framework_findings": [],
            "findings": [],
            "finding_statuses": {},
            "dependency_scan": [],
            "technology_stack": [],
            "attack_surface": {"endpoints": [{"method": "GET", "url": "/api/v1/profile"}], "websockets": [], "parameters": ["q"]},
            "notable_features": ["http_client", "client_storage"],
            "transport": ["fetch"],
            "request_methods": ["GET"],
            "ast_analysis": {},
            "data_flow_summary": [],
            "obfuscation_analysis": {},
        }
        self.vendor_data = {
            "file_size": 900,
            "line_count": 40,
            "secrets": [],
            "keys": [],
            "ivs": [],
            "crypto": [],
            "endpoints": ["https://analytics.example.net/collect"],
            "api_calls": ["https://analytics.example.net/collect"],
            "headers": [],
            "storage": ["localStorage.setItem", "document.cookie"],
            "hardcoded_configs": [],
            "decoded_strings": [],
            "suspicious_calls": ["eval("],
            "dom_risks": ["innerHTML"],
            "risk_signals": [],
            "dataflows": [],
            "framework_findings": [],
            "findings": [],
            "finding_statuses": {},
            "dependency_scan": [{"name": "tracker", "kind": "third-party"}],
            "technology_stack": [],
            "attack_surface": {"endpoints": [{"method": "POST", "url": "https://analytics.example.net/collect"}], "websockets": [{"url": "wss://track.example.net/socket", "kind": "WS"}], "parameters": ["email"]},
            "notable_features": ["client_storage", "post_message"],
            "transport": ["fetch", "WebSocket"],
            "request_methods": ["POST"],
            "ast_analysis": {},
            "data_flow_summary": [],
            "obfuscation_analysis": {},
        }

    def test_build_script_intel_classifies_and_risks(self):
        results = {
            "https://example.com/app.js": {**self.app_data, "url": "https://example.com/app.js"},
            "https://cdn.vendor.net/vendor.js": {**self.vendor_data, "url": "https://cdn.vendor.net/vendor.js"},
        }
        runtime = {
            "url": self.target,
            "captured": True,
            "scripts": ["https://cdn.vendor.net/legacy-tracker.js"],
            "requests": [],
            "eval_calls": [],
            "storage_writes": [],
            "local_storage_keys": [],
            "session_storage_keys": [],
            "cookie_names": [],
        }
        inventory = build_script_intel(results, runtime, self.target)
        by_name = {i["name"]: i for i in inventory}

        self.assertEqual(by_name["app.js"]["party"], "first_party")
        self.assertEqual(by_name["vendor.js"]["party"], "third_party")
        self.assertGreater(by_name["vendor.js"]["risk"]["score"], by_name["app.js"]["risk"]["score"])
        self.assertTrue(any(a["key"] == "storage" and a["enabled"] for a in by_name["vendor.js"]["browser_apis"]))
        self.assertTrue(any(a["key"] == "post_message" and a["enabled"] for a in by_name["vendor.js"]["browser_apis"]))
        self.assertIn("legacy-tracker.js", by_name)

    def test_data_exfiltration_candidates_static(self):
        results = {"https://cdn.vendor.net/vendor.js": {**self.vendor_data, "url": "https://cdn.vendor.net/vendor.js"}}
        candidates = data_exfiltration_candidates(results, page_url=self.target)
        self.assertTrue(candidates)
        self.assertEqual(candidates[0]["id"], "data_exfiltration_candidate")
        self.assertIn("browser_storage", candidates[0]["source"])
        self.assertIn("analytics.example.net", candidates[0]["sink"])

    def test_dashboard_and_reports_include_script_inventory(self):
        results = {
            "https://example.com/app.js": {**self.app_data, "url": "https://example.com/app.js"},
        }
        payload = build_dashboard_payload(results, metadata={"mode": "url", "source": self.target})
        model = build_report_model(results, metadata={"mode": "url", "source": self.target})
        self.assertTrue(payload["script_inventory"])
        self.assertTrue(model["script_inventory"])
        self.assertTrue(payload["files"][0]["script_intel"])
        self.assertEqual(payload["script_inventory"][0]["party"], "first_party")

    def test_csv_and_sarif_include_behavioral_correlation(self):
        results = {"https://cdn.vendor.net/vendor.js": {**self.vendor_data, "url": "https://cdn.vendor.net/vendor.js"}}
        csv = generate_csv_report(results)
        sarif = generate_sarif_report(results)
        self.assertIn("data_exfiltration_candidate", csv)
        self.assertIn("behavioral_correlation", sarif)


if __name__ == "__main__":
    unittest.main()
