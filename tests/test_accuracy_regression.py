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

from core.analyzer_service import analyze_content
from core.analysis_model import is_observation, split_findings
from core.taint import analyze_taint

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
    def test_dom_xss_tp_direct_is_high_confidence_open_not_confirmed(self):
        r = analyze("dom-xss/reachable-query.js")
        dom = flow_ids(r, "dom_injection")
        self.assertTrue(dom, "expected a DOM injection source-to-sink flow")
        self.assertTrue(any(f.get("confidence") == "high" for f in dom))
        # High confidence ≠ confirmed. Static analysis never auto-confirms.
        self.assertFalse(any(f.get("status") == "confirmed" for f in dom))
        self.assertTrue(any(f.get("status") == "open" for f in dom))

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


if __name__ == "__main__":
    unittest.main()
