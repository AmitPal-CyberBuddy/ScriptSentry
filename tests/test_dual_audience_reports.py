"""Dual-audience reporting and intelligent finding revalidation.

Two contracts:

1.  **Every report carries a plain-language layer** a non-technical reader
    (manager, stakeholder) can act on: verdict sentence, counts in words, one
    block per distinct finding kind ("what it means" / "what to do"), honest
    notes — while the technical sections keep their evidence, locations and
    remediation for the security team.
2.  **Revalidation is evidence, not a gimmick.** Comparing two scans of the
    same target yields per-finding verdicts (persisted / worsened / improved /
    resolved / new) joined on the line-independent fingerprint, says *what*
    changed, and is honest when the newer scan saw only part of the previous
    file set (a "resolved" finding in a file that was not seen again is
    "unknown", not "fixed").
"""
import unittest

from core.analyzer_service import analyze_content
from core.revalidation import revalidate_rows, summarize_revalidation
from core.reporter import (
    build_dashboard_payload,
    build_report_model,
    executive_summary,
    generate_html_report,
    generate_json_report,
    generate_report,
)

import json


CODE = (
    'var apiKey = "kx9vQm2LpTn8Rb4Wc6Yd3Zf7Hj5";\n'
    "const q = new URLSearchParams(location.search).get('q');\n"
    "document.getElementById('x').innerHTML = q;\n"
)


def _row(fp, **kw):
    return {
        "fingerprint": fp,
        "finding_id": kw.get("id", "dom_injection"),
        "severity": kw.get("sev", "HIGH"),
        "confidence": kw.get("conf", "medium"),
        "title": kw.get("title", "DOM injection"),
        "file": kw.get("file", "app.js"),
        "detail": "location.search -> innerHTML",
        "observation": kw.get("obs", False),
    }


class ExecutiveSummaryTest(unittest.TestCase):
    def setUp(self):
        self.results = analyze_content(CODE, filename="app.js")
        self.model = build_report_model(self.results,
                                        metadata={"mode": "code", "source": "app.js"})

    def test_summary_answers_what_it_means_and_what_to_do(self):
        es = executive_summary(self.model, self.results)
        self.assertIn("risk", es["verdict"].lower())
        self.assertIn("file(s)", es["counts_in_words"])
        plain = {f["finding_id"]: f for f in es["findings_in_plain_terms"]}
        self.assertIn("dom_injection", plain)
        self.assertIn("hardcoded_secret", plain)
        for item in plain.values():
            self.assertTrue(item["meaning"].endswith("."))
            self.assertTrue(item["action"], "every plain finding needs an action")
        # No raw jargon in the plain layer.
        for item in plain.values():
            for field in ("meaning", "action"):
                self.assertNotIn("source_to_sink", item[field])
                self.assertNotIn("static_pattern", item[field])

    def test_unknown_finding_kind_gets_an_honest_placeholder(self):
        es = executive_summary({"summary": {
            "risk_label": "MEDIUM", "total_score": 20, "total_files": 1,
            "actionable_findings": [{"id": "martian_signal", "type": "Martian signal",
                                     "severity": "LOW"}],
            "observations": [], "priorities": []}}, results={})
        self.assertEqual(len(es["findings_in_plain_terms"]), 1)
        self.assertIn("not yet available", es["findings_in_plain_terms"][0]["meaning"])

    def test_txt_report_leads_with_the_plain_language_section(self):
        txt = generate_report(self.results, metadata={"mode": "code", "source": "app.js"})
        self.assertLess(txt.index("WHAT THIS RESULT MEANS"), txt.index("EXECUTIVE SUMMARY"))
        self.assertIn("What it means:", txt)
        self.assertIn("What to do:", txt)

    def test_html_json_and_dashboard_carry_the_layer(self):
        html = generate_html_report(self.results, metadata={"mode": "code", "source": "app.js"})
        self.assertIn("What This Result Means", html)
        j = json.loads(generate_json_report(self.results))
        self.assertTrue(j["executive_summary"]["verdict"])
        payload = build_dashboard_payload(self.results)
        es = payload["executive_summary"]
        self.assertTrue(es["verdict"])
        self.assertTrue(es["findings_in_plain_terms"])
        # The security team keeps its anchor: each plain item links to the
        # technical finding (id, file, line, confidence).
        anchor = es["findings_in_plain_terms"][0]["for_security_team"]
        self.assertIn("id", anchor)
        self.assertIn("file", anchor)


class RevalidationTest(unittest.TestCase):
    def test_persisted_worsened_improved_resolved_new(self):
        old = [
            _row("a", id="dom_injection", sev="HIGH"),
            _row("b", id="hardcoded_secret", sev="HIGH"),
            _row("c", id="sensitive_storage", sev="MEDIUM", file="login.js"),
            _row("d", id="open_redirect", sev="MEDIUM", file="redirect.js"),
        ]
        new = [
            _row("a", id="dom_injection", sev="CRITICAL"),          # worsened (severity)
            _row("b", id="hardcoded_secret", sev="HIGH", conf="high"),  # worsened (confidence)
            _row("c", id="sensitive_storage", sev="LOW", file="login.js"),   # improved
            _row("e", id="api_surface", sev="LOW", obs=True),       # new
        ]
        out = summarize_revalidation(revalidate_rows(old, new), old, new, 1, 2)
        self.assertEqual(out["counts"]["worsened"], 2)
        self.assertEqual(out["counts"]["improved"], 1)
        self.assertEqual(out["counts"]["resolved"], 1)
        self.assertEqual(out["counts"]["new"], 1)
        # Legacy keys still present for existing consumers.
        self.assertEqual(out["unchanged_count"], 3)
        self.assertEqual(out["resolved_count"], 1)
        # Worsened verdicts say WHAT moved.
        worsened = [v for v in out["verdicts"] if v["verdict"] == "worsened"]
        changes = {v["finding_id"]: v["change"] for v in worsened}
        self.assertIn("severity HIGH->CRITICAL", changes["dom_injection"])
        self.assertIn("confidence medium->high", changes["hardcoded_secret"])

    def test_line_independent_identity_is_the_join_key(self):
        # The history fingerprint excludes line numbers by design; rows are
        # joined on it, so this contract is inherited from the fingerprint.
        from core.history import fingerprint
        a = {"id": "dom_injection", "file": "app.js", "sink": "innerHTML",
             "title": "DOM injection", "source": "q", "evidence": []}
        b = dict(a, line=3)
        self.assertEqual(fingerprint(a), fingerprint(b))

    def test_partial_coverage_is_called_out(self):
        old = [_row("a", file="app.js"), _row("b", file="gone.js")]
        new = [_row("a", file="app.js")]
        out = summarize_revalidation(revalidate_rows(old, new), old, new, 1, 2)
        self.assertTrue(out["coverage"]["partial"])
        self.assertIn("Comparison is partial", out["summary"])
        self.assertIn("unknown, not fixed", out["summary"])
        self.assertIn("gone.js", out["coverage"]["missing_files"])

    def test_full_coverage_resolved_is_stated_honestly(self):
        old = [_row("a", file="app.js"), _row("b", file="app.js")]
        new = [_row("a", file="app.js")]
        out = summarize_revalidation(revalidate_rows(old, new), old, new, 1, 2)
        self.assertFalse(out["coverage"]["partial"])
        self.assertIn("no longer detected", out["summary"])
        self.assertNotIn("Comparison is partial", out["summary"])

    def test_empty_scans_do_not_crash(self):
        out = summarize_revalidation(revalidate_rows([], []), [], [], 1, 2)
        self.assertIn("nothing to revalidate", out["summary"].lower())


class RevalidationEndpointTest(unittest.TestCase):
    """The diff API returns the revalidation payload (legacy keys intact)."""

    def test_revalidate_scans_end_to_end(self):
        # The state dir must stay patched for the WHOLE test: revalidate_scans
        # re-opens the history connection, and unpatching the env early would
        # silently point it at the default (empty) database.
        import os
        import tempfile
        from unittest import mock
        from core import history
        from core.revalidation import revalidate_scans

        tmp = tempfile.TemporaryDirectory(prefix="scriptsentry-reval-test-")
        self.addCleanup(tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {"SCRIPTSENTRY_STATE_DIR": tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)

        first = history.record_scan(analyze_content(CODE, filename="app.js"),
                                    mode="code", target="app.js")
        fixed = CODE.replace("innerHTML = q", "textContent = q")
        second = history.record_scan(analyze_content(fixed, filename="app.js"),
                                     mode="code", target="app.js")
        self.assertTrue(first and second)
        out = revalidate_scans(first["scan_id"], second["scan_id"])
        self.assertIsNotNone(out)
        self.assertIn("verdicts", out)
        self.assertIn("summary", out)
        # The DOM injection was fixed in the second snippet; the secret stays.
        verdicts = {v["finding_id"]: v["verdict"] for v in out["verdicts"]}
        self.assertEqual(verdicts.get("hardcoded_secret"), "persisted")
        self.assertEqual(verdicts.get("dom_injection"), "resolved")


if __name__ == "__main__":
    unittest.main()
