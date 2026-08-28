import json
import unittest

from core.analysis_model import correlate_findings, deduplicate_findings
from core.analyzer_service import analyze_content
from core.attack_surface import extract_attack_surface
from core.crypto import extract_crypto_material
from core.reporter import build_dashboard_payload, build_report_model, generate_csv_report, generate_html_report, generate_sarif_report
from core.taint import analyze_taint


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

    def test_dependency_scan_recognizes_bundle_aliases(self):
        code = """
        CryptoJS.AES.encrypt(data, key, { iv });
        return <div dangerouslySetInnerHTML={{__html:q}} />;
        Vue.createApp(App).mount('#app');
        jQuery('#x').html(q);
        """
        data = analyze_content(code, "aliases.js")["aliases.js"]
        names = {d.get("name") for d in data.get("dependency_scan", []) if isinstance(d, dict)}
        self.assertIn("CryptoJS", names)
        self.assertIn("React", names)
        self.assertIn("Vue", names)
        self.assertIn("jQuery", names)

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


    def test_taint_url_search_params_to_innerhtml(self):
        code = """
        const p = new URLSearchParams(location.search);
        const q = p.get('q');
        const el = document.getElementById('msg');
        el.innerHTML = q;
        """
        flows = analyze_taint(code, "t.js")
        confirmed = [x for x in flows if x.get("status") == "confirmed"]
        self.assertTrue(any("innerHTML" in (x.get("sink") or "") for x in confirmed))

    def test_taint_sanitized_flow_is_informational(self):
        code = """
        const q = new URLSearchParams(location.search).get('q');
        const clean = DOMPurify.sanitize(q);
        document.body.innerHTML = clean;
        """
        flows = analyze_taint(code, "t.js")
        info = [x for x in flows if x.get("status") == "informational"]
        self.assertTrue(any(x.get("sanitization_detected") or "sanitized" in str(x.get("evidence") or "").lower() for x in info))

    def test_taint_open_redirect(self):
        code = """
        const q = new URLSearchParams(location.search).get('next');
        window.location.href = q;
        """
        flows = analyze_taint(code, "t.js")
        self.assertTrue(any(x.get("id") == "open_redirect" and x.get("status") == "confirmed" for x in flows))

    def test_taint_postmessage_wildcard(self):
        code = "window.parent.postMessage(userData, '*');"
        flows = analyze_taint(code, "t.js")
        self.assertTrue(any("postMessage" in (x.get("type") or "") and "*" in (x.get("evidence") or "") for x in flows))

    def test_taint_interprocedural_function_param(self):
        code = """
        function setMsg(x){ document.body.innerHTML = x; }
        const q = location.search;
        setMsg(q);
        """
        flows = analyze_taint(code, "t.js")
        self.assertTrue(any(x.get("status") == "confirmed" and "URL query" in x.get("source", "") for x in flows))

    def test_taint_object_property(self):
        code = """
        const cfg = { q: location.search };
        document.body.innerHTML = cfg.q;
        """
        flows = analyze_taint(code, "t.js")
        self.assertTrue(any(x.get("status") == "confirmed" and "URL query" in x.get("source", "") for x in flows))

    def test_attack_surface_extracts_endpoints_and_flags(self):
        code = """
        fetch('/api/v1/users?limit=10&admin=1', { method: 'POST', body: JSON.stringify({ name, email }), headers: { 'Authorization': 'Bearer token' } });
        fetch('/internal/health');
        new WebSocket('wss://example.com/socket?token=abc');
        """
        surface = extract_attack_surface(code, "a.js")
        self.assertTrue(any(e.get("url", "").startswith("/api/v1/users") for e in surface.get("endpoints", [])))
        self.assertTrue(any(e.get("url") == "/internal/health" and e.get("internal") for e in surface.get("endpoints", [])))
        self.assertTrue(any("wss://example.com/socket" in (e.get("url") or "") for e in surface.get("websockets", [])))
        self.assertTrue(surface.get("auth_hints"))
        # Header/object keys like "Authorization" must not become fake endpoints.
        self.assertFalse(any(e.get("url") == "Authorization" for e in surface.get("endpoints", [])))
        # Realtime URLs are not duplicated as plain HTTP GET endpoints.
        self.assertFalse(any(e.get("url", "").startswith("wss://") for e in surface.get("endpoints", [])))

    def test_csv_and_sarif_reports_gen(self):
        results = analyze_content("const q = location.search; document.getElementById('x').innerHTML = q;", "p.js")
        csv = generate_csv_report(results)
        sarif = generate_sarif_report(results)
        self.assertIn("id,type,severity", csv)
        self.assertIn("runs", sarif)

    def test_html_report_includes_flows_and_attack_surface(self):
        code = """
        function setMsg(x){ document.body.innerHTML = x; }
        const q = location.search;
        setMsg(q);
        fetch('/api/v1/users', { method: 'POST' });
        new WebSocket('wss://example.com/socket?token=abc');
        """
        results = analyze_content(code, "report.js")
        html = generate_html_report(results)
        self.assertIn("Source→Sink Data Flows", html)
        self.assertIn("Attack Surface", html)
        self.assertIn("wss://example.com/socket", html)

    def test_correlation_dedupes_and_preserves_evidence(self):
        flows = [{
            "id": "dom_injection", "type": "DOM injection", "severity": "HIGH",
            "confidence": "high", "status": "confirmed", "file": "x.js", "line": 1,
            "sink": "innerHTML", "flow": ["read location.search"], "evidence": "snippet",
        }]
        risk = [{"id": "dom_injection", "severity": "HIGH", "title": "DOM injection", "evidence": ["dom_risks"]}]
        out = correlate_findings(flows, [], risk, filename="x.js")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].get("evidence_type"), "source_to_sink")
        self.assertIn("read location.search", out[0].get("flow", []))

        dupes = [flows[0], {**flows[0], "source": "URL query string", "flow": ["alias = location.search", "innerHTML = alias"]}]
        self.assertEqual(len(deduplicate_findings(dupes)), 1)

    def test_local_engine_origin_allowlist(self):
        from server import DashboardHandler
        self.assertTrue(DashboardHandler._is_allowed_origin("http://localhost:8000"))
        self.assertTrue(DashboardHandler._is_allowed_origin("https://user.github.io"))
        self.assertFalse(DashboardHandler._is_allowed_origin("https://evil.example"))


if __name__ == "__main__":
    unittest.main()
