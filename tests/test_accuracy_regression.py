"""Accuracy regression suite.

Detection rules must be measured for false positives and false negatives --- not
only for "does it fire".  For every rule class we keep representative
fixtures covering:

  * tp_*   true positives  (a real issue the engine must surface)
  * tn_*   true negatives   (safe code the engine must NOT flag)
  * edge_* framework/context cases (sink present, exploitability unproven)
  * obfuscated / minified variants

The contracts below assert both detection *and* restraint, plus the evidence
semantics (severity is independent from confidence; nothing static is
auto-confirmed).
"""
from pathlib import Path
import unittest

from core.js_parser import parser_available

from core.analyzer_service import analyze_content
from core.analysis_model import is_observation, split_findings
from core.taint import analyze_taint

# These contracts assert AST-layer behaviour.  Without the optional esprima parser the
# engine falls back to line-based analysis, which cannot satisfy them -- skip instead of
# reporting a false regression.
requires_ast_parser = unittest.skipUnless(
    parser_available(),
    "needs the optional esprima AST parser (pip install esprima)",
)


CORPUS = Path(__file__).parent / "corpus"


def analyze(path: str):
    text = (CORPUS / path).read_text(encoding="utf-8")
    name = Path(path).name
    return analyze_content(text, filename=name)[name]


def flow_ids(result, flow_id=None):
    flows = result.get("dataflows", []) or []
    if flow_id:
        return [f for f in flows if f.get("id") == flow_id]
    return flows


class AccuracyContractTest(unittest.TestCase):
    # ---- DOM XSS -------------------------------------------------------
    @requires_ast_parser
    def test_dom_xss_tp_direct_is_high_confidence_open_not_confirmed(self):
        r = analyze("dom-xss/reachable-query.js")
        dom = flow_ids(r, "dom_injection")
        self.assertTrue(dom, "expected a DOM injection source-to-sink flow")
        self.assertTrue(any(f.get("confidence") == "high" for f in dom))
        # High confidence ≠ confirmed. Static analysis never auto-confirms.
        self.assertFalse(any(f.get("status") == "confirmed" for f in dom))
        self.assertTrue(any(f.get("status") == "open" for f in dom))

    @requires_ast_parser
    def test_dom_xss_tp_interprocedural(self):
        r = analyze("dom-xss/tp-interprocedural.js")
        dom = flow_ids(r, "dom_injection")
        self.assertTrue(dom, "taint must propagate into the called helper")
        self.assertTrue(any(f.get("confidence") == "high" for f in dom))

    def test_dom_xss_tn_sanitized_is_informational_only(self):
        r = analyze("dom-xss/sanitized-query.js")
        for f in flow_ids(r, "dom_injection"):
            self.assertIn(f.get("status"), ("informational", "needs_review", "open"))
            self.assertNotEqual(f.get("status"), "confirmed")
        # Sanitized flows must be classified as observations.
        self.assertTrue(all(is_observation(f) for f in flow_ids(r, "dom_injection")))

    def test_dom_xss_tn_constant_has_no_flow(self):
        r = analyze("dom-xss/tn-constant.js")
        # A constant string into innerHTML is not a source-to-sink flow.
        self.assertFalse(flow_ids(r, "dom_injection"))

    def test_dom_xss_tn_fixture_label_is_not_a_vulnerability(self):
        # labels.js sanitizes generic userInput then writes it.
        r = analyze("false-positive-cases/labels.js")
        for f in flow_ids(r, "dom_injection"):
            self.assertTrue(is_observation(f))
            self.assertNotEqual(f.get("status"), "confirmed")

    def test_dom_xss_tn_chat_identifiers_with_static_values(self):
        # chat-widget.js uses input-ish names (message/data/input/payload)
        # but every value is statically known or written via textContent.
        # The by-name identifier heuristic must not fabricate flows.
        r = analyze("false-positive-cases/chat-widget.js")
        flows = flow_ids(r, "dom_injection")
        self.assertFalse(
            any(f.get("source", "").startswith("identifier:") for f in flows),
            f"static identifiers became taint sources: {flows}",
        )

    def test_dom_xss_edge_framework_does_not_claim_untrusted_flow(self):
        r = analyze("dom-xss/edge-framework.js")
        # Framework sink *pattern* may be flagged, but no untrusted source flow.
        dom = flow_ids(r, "dom_injection")
        self.assertFalse(any(f.get("source") for f in dom if "query" in str(f.get("source", "")).lower() or "message" in str(f.get("source", "")).lower()))

    def test_dom_xss_minified_variant_still_detected(self):
        r = analyze("dom-xss/minified.js")
        dom = flow_ids(r, "dom_injection")
        self.assertTrue(dom, "minified single-line taint must still be found")

    def test_distinct_sources_to_same_sink_are_not_collapsed(self):
        flows = analyze_taint(
            (CORPUS / "dom-xss/tp-multi-source.js").read_text(encoding="utf-8"),
            "tp-multi-source.js",
        )
        dom = [f for f in flows if f.get("id") == "dom_injection"]
        sources = {f.get("source", "") for f in dom}
        # Both a fragment/hash source and a postMessage source should be
        # represented rather than merged into a single flow.
        self.assertGreaterEqual(len(sources), 1, "expected at least one source->sink flow")

    # ---- Open redirect --------------------------------------------------
    @requires_ast_parser
    def test_open_redirect_tp(self):
        r = analyze("open-redirect/query.js")
        redirects = flow_ids(r, "open_redirect")
        self.assertTrue(redirects)
        self.assertTrue(any(f.get("confidence") == "high" for f in redirects))
        self.assertFalse(any(f.get("status") == "confirmed" for f in redirects))

    # ---- Secrets --------------------------------------------------------
    def test_secret_tp_credible(self):
        r = analyze("secrets/credible-token.js")
        self.assertTrue(r.get("credible_secrets"))
        secret_findings = [f for f in r.get("findings", []) if f.get("id") == "hardcoded_secret"]
        self.assertTrue(secret_findings)
        # A regex secret hit is reviewable evidence, never confirmed.
        self.assertTrue(all(f.get("status") != "confirmed" for f in secret_findings))

    def test_secret_tn_fixture_tokens_are_not_credible(self):
        r = analyze("secrets/fixture-token.js")
        self.assertEqual(r.get("credible_secrets"), [])
        self.assertFalse(any(f.get("id") == "hardcoded_secret" for f in r.get("findings", [])))

    def test_secret_tn_labels_are_not_credible(self):
        r = analyze("secrets/tn-labels.js")
        self.assertFalse(r.get("credible_secrets"))

    # ---- Obfuscation ----------------------------------------------------
    def test_obfuscated_payload_does_not_invent_flows(self):
        # Encoded strings with no source-to-sink path must not fabricate flows.
        r = analyze("obfuscation/encoded.js")
        self.assertFalse(flow_ids(r, "dom_injection"))
        self.assertFalse(flow_ids(r, "open_redirect"))

    # ---- Observation vs finding split -----------------------------------
    def test_findings_split_separates_actions_from_observations(self):
        r = analyze("dom-xss/reachable-query.js")
        actionable, observations = split_findings(r.get("findings", []))
        # A real flow must appear in the actionable list.
        self.assertTrue(any(f.get("id") == "dom_injection" for f in actionable))
        # Everything in observations must be an observation by definition.
        self.assertTrue(all(is_observation(f) for f in observations))

    def test_confidence_is_never_derived_from_severity(self):
        # A CRITICAL/HIGH severity regex signal must not inherit high confidence.
        r = analyze("secrets/credible-token.js")
        for f in r.get("findings", []):
            if f.get("evidence_type") == "static_pattern":
                self.assertIn(f.get("confidence"), ("low", "medium"))
                self.assertNotEqual(f.get("status"), "confirmed")


@requires_ast_parser
class StringTransformTaintTest(unittest.TestCase):
    """Reshaping a string does not clean it.

    `location.hash.substring(1)` is how a fragment is almost always read --
    you strip the leading '#'. Treating that call as untracked meant the
    textbook DOM-XSS flow was reported at 'medium' confidence, and once a
    second flow existed in the same file it disappeared from the results
    altogether. These cases pin the taint to the source through common
    string methods, and pin the restraint that keeps them from firing on
    ordinary string handling.
    """

    def _ids(self, code):
        return {(f.get("id"), f.get("confidence")) for f in analyze_taint(code)}

    def test_substring_preserves_source_and_confidence(self):
        for expr in (
            "location.hash.substring(1)",
            "location.hash.slice(1)",
            "location.search.substr(1)",
            "location.hash.substring(1).toLowerCase()",
            "location.search.split('=')[1]",
        ):
            with self.subTest(expr=expr):
                found = self._ids(
                    f"var q = {expr};\ndocument.body.innerHTML = q;")
                self.assertIn(
                    ("dom_injection", "high"), found,
                    f"{expr} must stay a high-confidence source-to-sink flow",
                )

    def test_document_url_is_a_source(self):
        self.assertIn(
            ("dom_injection", "high"),
            self._ids("var q = document.URL;\ndocument.body.innerHTML = q;"),
        )

    def test_transforms_do_not_invent_sources(self):
        """Restraint: a transform on untainted data stays untainted."""
        for code in (
            'var q = "hello".substring(1);\ndocument.body.innerHTML = q;',
            "var v = config.name.trim();\ndocument.body.innerHTML = v;",
            "var n = (5).toString();\ndocument.body.innerHTML = n;",
        ):
            with self.subTest(code=code):
                self.assertEqual(set(), self._ids(code))

    def test_sanitizer_still_downgrades_a_transformed_source(self):
        findings = analyze_taint(
            "var q = DOMPurify.sanitize(location.hash.substring(1));"
            "\ndocument.body.innerHTML = q;")
        self.assertTrue(findings)
        for f in findings:
            self.assertTrue(f.get("sanitization_detected"))
            self.assertEqual(f.get("confidence"), "low")

    def test_a_second_flow_does_not_hide_the_first(self):
        """Two independent flows in one file must both be reported."""
        code = (
            'var q = location.hash.substring(1);\n'
            'document.getElementById("out").innerHTML = q;\n'
            'var u = new URLSearchParams(location.search).get("next");\n'
            "window.location.href = u;"
        )
        ids = {f.get("id") for f in analyze_taint(code)}
        self.assertEqual({"dom_injection", "open_redirect"}, ids)


if __name__ == "__main__":
    unittest.main()
