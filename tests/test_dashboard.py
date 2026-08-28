import json
import unittest

from core.analyzer_service import analyze_content
from core.crypto import extract_crypto_material
from core.reporter import build_dashboard_payload, build_report_model, generate_html_report


class DashboardAnalysisTest(unittest.TestCase):
    def test_paste_code_detects_crypto_key_and_iv(self):
        code = '''
const key = EncryptionKey = "aVeryStrongEncryptionKey123!";
const iv = EncryptionIV = "1b2c3d4e5f6a7b8c";
CryptoJS.AES.encrypt(data, key, { iv: iv });
'''
        results = analyze_content(code, filename="sample.js")
        data = results["sample.js"]
        crypto = extract_crypto_material(code, filename="sample.js")
        data.update(crypto)

        self.assertTrue(data["real_crypto_detected"])
        values = {k["value"] for k in data.get("keys", []) if isinstance(k, dict)}
        self.assertIn("aVeryStrongEncryptionKey123!", values)
        iv_values = {i["value"] for i in data.get("ivs", []) if isinstance(i, dict)}
        self.assertIn("1b2c3d4e5f6a7b8c", iv_values)

    def test_endpoint_like_values_do_not_become_keys(self):
        code = '''
const normal = CryptoJS.AES.encrypt(data, key, {iv: iv});
fetch("/api/v1/profile");
import("./assets/logo.png");
'''
        crypto = extract_crypto_material(code, filename="noise.js")
        for k in crypto.get("keys", []):
            value = k["value"] if isinstance(k, dict) else k
            self.assertNotIn("/api/", value)
            self.assertNotIn(".js", value.lower())

    def test_dashboard_payload_has_visual_sections(self):
        code = '''
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def";
fetch("/api/v1/profile", {headers:{Authorization:"Bearer abc123"}});
localStorage.setItem("token", token);
eval(userInput);
'''
        results = analyze_content(code, filename="inline.js")
        payload = build_dashboard_payload(results, metadata={"mode": "code", "source": "inline.js"})
        self.assertEqual(payload["meta"]["analysis_mode"], "code")
        self.assertIn("summary", payload)
        self.assertIn("files", payload)
        self.assertIn("radar", payload)
        self.assertIn("donut", payload)
        self.assertIn("timeline", payload)
        self.assertEqual(len(payload["files"]), 1)

    def test_scan_builds_ast_profile_and_dependencies(self):
        code = '''
import axios from "axios";
import {getAuth} from "firebase/auth";
export const app = () => fetch("/api/v2/items", {method:"POST"});
class Service { constructor(){ this.x = 1; } }
'''
        results = analyze_content(code, filename="module.js")
        data = results["module.js"]
        ast = data.get("ast_analysis", {})
        self.assertEqual(ast.get("module_system"), "ES modules")
        self.assertGreaterEqual(ast.get("imports_count", 0), 0)
        self.assertIn("axios", json.dumps(ast.get("imports", [])).lower() if ast.get("imports") else "")
        self.assertTrue(data.get("dependency_scan"))
        self.assertTrue(data.get("risk_signals", []))
        self.assertTrue(data.get("transport", []))
        self.assertTrue(data.get("request_methods", []))

    def test_report_model_has_risk_signals_and_remediation(self):
        code = '''
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def";
localStorage.setItem("auth", token);
fetch("/api/v1/profile", {headers:{Authorization:"Bearer abc123"}});
eval(userInput);
'''
        results = analyze_content(code, filename="inline.js")
        model = build_report_model(results, metadata={"mode": "code", "source": "inline.js"})
        self.assertEqual(model["summary"]["risk_label"], "CRITICAL")
        self.assertGreaterEqual(model["summary"]["total_findings"], 1)
        signal_ids = [s.get("id") for s in model["summary"]["signals"]]
        self.assertIn("sensitive_storage", signal_ids)
        self.assertIn("dom_injection", signal_ids)
        self.assertIn("api_surface", signal_ids)
        self.assertTrue(model["all_endpoints"])

    def test_html_report_is_self_contained_and_has_sections(self):
        sample = {
            "sample.js": {
                "secrets": ["apiKey=abc"], "api_inventory": [{"endpoint": "/api/v1/profile", "method": "GET"}],
                "auth_summary": [{"type": "jwt", "evidence": "jwt"}],
                "storage_analysis": [{"storage": "localStorage", "classification": "sensitive"}],
                "technology_stack": [{"name": "React", "version": "18"}],
                "dom_risks": ["eval"], "data_flow_summary": ["input -> storage -> api"],
                "obfuscation_analysis": {"decoded_values": ["secret"], "evidence": ["encoding helpers"]},
                "risk_signals": [{"id": "api_surface", "severity": "LOW", "title": "API surface mapped", "evidence": ["/api/v1/profile"]}],
            }
        }
        html = generate_html_report(sample)
        self.assertIn("ScriptSentry Analysis Report", html)
        self.assertIn("Executive Summary", html)
        self.assertIn("Risk Signals", html)
        self.assertIn("Authentication Analysis", html)
        self.assertIn("API Inventory", html)
        self.assertIn("Technology Stack", html)


if __name__ == "__main__":
    unittest.main()
