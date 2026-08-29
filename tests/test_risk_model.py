"""Tests for the explainable risk-score model and evidence tiers."""
import json
import unittest

from core.analyzer_service import analyze_content
from core.reporter import build_report_model, generate_csv_report, generate_sarif_report
from core.risk_model import overall_risk, top_priorities


class RiskModelTest(unittest.TestCase):
    def test_confirmed_runtime_effect_outranks_open_flow(self):
        weak = overall_risk(findings=[{
            "id": "x", "type": "t", "severity": "HIGH", "confidence": "high",
            "status": "open", "evidence_type": "source_to_sink",
        }])
        strong = overall_risk(findings=[{
            "id": "y", "type": "t", "severity": "HIGH", "confidence": "confirmed",
            "status": "confirmed", "evidence_type": "runtime_effect",
        }])
        self.assertGreater(strong["score"], weak["score"])
        self.assertIn("Confirmed/demonstrated dangerous behavior",
                      " ".join(c["label"] for c in strong["contributors"]))

    def test_score_is_bounded_and_explained(self):
        result = overall_risk(findings=[{
            "id": "dom_injection", "type": "DOM injection", "severity": "HIGH",
            "confidence": "high", "status": "open", "evidence_type": "source_to_sink",
        }])
        self.assertGreaterEqual(result["score"], 0)
        self.assertLessEqual(result["score"], 100)
        self.assertTrue(result["contributors"])
        # Every contributor carries points and a label.
        self.assertTrue(all("points" in c and "label" in c for c in result["contributors"]))

    def test_observations_score_lower_than_actionable(self):
        action = overall_risk(findings=[{
            "id": "dom_injection", "type": "DOM injection", "severity": "HIGH",
            "confidence": "high", "status": "open", "evidence_type": "source_to_sink",
        }])
        observation = overall_risk(findings=[{
            "id": "api_surface", "type": "API surface mapped", "severity": "LOW",
            "confidence": "low", "status": "informational", "evidence_type": "static_pattern",
            "observation": True,
        }])
        self.assertGreater(action["score"], observation["score"])

    def test_top_priorities_orders_by_evidence_then_severity(self):
        findings = [
            {"id": "a", "type": "low sev obs", "severity": "LOW", "confidence": "low",
             "status": "informational", "evidence_type": "static_pattern", "observation": True},
            {"id": "b", "type": "high flow", "severity": "HIGH", "confidence": "high",
             "status": "open", "evidence_type": "source_to_sink", "file": "a.js", "line": 3},
        ]
        priorities = top_priorities(findings)
        self.assertTrue(priorities)
        # Observations are excluded from priorities; the actionable flow leads.
        self.assertEqual(priorities[0]["type"], "high flow")

    def test_end_to_end_score_is_explained_in_report_model(self):
        code = (
            "const q = new URLSearchParams(location.search).get('q');\n"
            "document.getElementById('x').innerHTML = q;\n"
            "localStorage.setItem('auth', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def');\n"
        )
        results = analyze_content(code, filename="app.js")
        model = build_report_model(results, metadata={"mode": "code", "source": "app.js"})
        summary = model["summary"]
        explained = sum(c["points"] for c in summary["risk_contributors"])
        self.assertEqual(summary["total_score"], max(0, min(100, round(explained))))
        self.assertTrue(summary["priorities"])

    def test_exports_carry_quality_and_limitations(self):
        code = "const q = location.search; document.getElementById('x').innerHTML = q;\n"
        results = analyze_content(code, filename="app.js")
        csv = generate_csv_report(results)
        self.assertIn("analysis_quality", csv.splitlines()[0])
        self.assertIn("limitations", csv.splitlines()[0])
        sarif = json.loads(generate_sarif_report(results))
        self.assertTrue(any(
            "analysis_quality" in (r.get("properties") or {})
            for r in sarif["runs"][0]["results"]
        ))


if __name__ == "__main__":
    unittest.main()
