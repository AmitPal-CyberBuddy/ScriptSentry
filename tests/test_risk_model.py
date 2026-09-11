"""Tests for the explainable risk-score model and evidence tiers."""
import json
import unittest

from core.analyzer_service import analyze_content
from core.reporter import build_report_model, generate_csv_report, generate_sarif_report
from core.risk_model import (
    CONFIRMED_SEVERITY_FLOOR,
    THIRD_PARTY_CAP,
    file_risk,
    overall_risk,
    top_priorities,
)


def _confirmed(severity, **extra):
    return {
        "id": extra.pop("id", "runtime_effect"), "type": "t", "severity": severity,
        "confidence": "confirmed", "status": "confirmed",
        "evidence_type": "runtime_effect", **extra,
    }


def _third_party(script_score=60, reads=True):
    return {
        "party": "third_party", "risk": {"score": script_score},
        "capabilities": {
            "reads": ["document.cookie"] if reads else [],
            "external_destinations": ["https://analytics.example.net"],
        },
    }


class CalibrationTest(unittest.TestCase):
    """The numeric score must agree with the evidence and its own label.

    Pre-calibration, one runtime-proven CRITICAL read 30/100 next to a HIGH
    label, while twelve unproven third-party behavioral correlations
    saturated the score to 100/CRITICAL -- exactly backwards.
    """

    def test_single_confirmed_critical_reaches_the_critical_band(self):
        result = overall_risk(findings=[_confirmed("CRITICAL")])
        self.assertGreaterEqual(result["score"], CONFIRMED_SEVERITY_FLOOR["CRITICAL"])
        self.assertEqual(result["label"], "CRITICAL")

    def test_single_confirmed_high_reaches_the_high_band(self):
        result = overall_risk(findings=[_confirmed("HIGH")])
        self.assertGreaterEqual(result["score"], CONFIRMED_SEVERITY_FLOOR["HIGH"])
        self.assertLess(result["score"], CONFIRMED_SEVERITY_FLOOR["CRITICAL"])
        self.assertEqual(result["label"], "HIGH")

    def test_confirmed_medium_gets_no_severity_floor(self):
        # The floor is reserved for demonstrated HIGH/CRITICAL effects; a
        # confirmed MEDIUM keeps its evidence-weighted points untouched.
        result = overall_risk(findings=[_confirmed("MEDIUM")])
        self.assertLess(result["score"], CONFIRMED_SEVERITY_FLOOR["HIGH"])
        self.assertFalse(any(
            "severity floor" in c["label"] for c in result["contributors"]))

    def test_severity_floor_is_an_explainable_contributor(self):
        # The lift must be a visible contributor, never a silent clamp, so
        # "why is this 75?" still has an answer that adds up.
        result = overall_risk(findings=[_confirmed("CRITICAL")])
        floor = [c for c in result["contributors"] if "severity floor" in c["label"]]
        self.assertTrue(floor, "the floor lift must appear in the contributor list")
        explained = sum(c["points"] for c in result["contributors"])
        self.assertEqual(result["score"], max(0, min(100, round(explained))))

    def test_floor_never_lowers_a_score_that_already_earned_more(self):
        # Several confirmed findings already sum past the floor: the lift
        # must be zero, not a pull-down.
        result = overall_risk(findings=[_confirmed("CRITICAL", id="rt_eval"),
                                        _confirmed("CRITICAL", id="rt_dom_xss"),
                                        _confirmed("HIGH", id="rt_storage")])
        self.assertFalse(any("severity floor" in c["label"] for c in result["contributors"]))
        self.assertGreaterEqual(result["score"], CONFIRMED_SEVERITY_FLOOR["CRITICAL"])

    def test_third_party_bucket_is_capped(self):
        # Twenty trackers reading cookies and beaconing externally are strong
        # posture signals, but unproven: they must not outrank one
        # demonstrated vulnerability or saturate the score.
        scripts = [_third_party() for _ in range(20)]
        result = overall_risk(script_inventory=scripts)
        self.assertLessEqual(result["score"], THIRD_PARTY_CAP)
        self.assertNotEqual(result["label"], "CRITICAL")
        self.assertNotEqual(result["label"], "HIGH")
        # Every script still counts; only the points are capped.
        self.assertEqual(result["counts"]["third_party_exfil"], 20)
        self.assertEqual(result["counts"]["third_party_points"], THIRD_PARTY_CAP)

    def test_one_confirmed_critical_outranks_twenty_trackers(self):
        trackers = overall_risk(script_inventory=[_third_party() for _ in range(20)])
        proven = overall_risk(findings=[_confirmed("CRITICAL")])
        self.assertGreater(proven["score"], trackers["score"])

    def test_mixed_proven_and_trackers_stay_explainable(self):
        result = overall_risk(
            findings=[_confirmed("CRITICAL")],
            script_inventory=[_third_party() for _ in range(20)],
        )
        explained = sum(c["points"] for c in result["contributors"])
        self.assertEqual(result["score"], max(0, min(100, round(explained))))
        self.assertEqual(result["label"], "CRITICAL")


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

    def test_file_risk_uses_the_same_model_as_the_overall_score(self):
        """Per-file chips must not contradict the overall score.

        The old per-file chip came from a separate additive counter, so a
        file could show CRITICAL (13) next to an overall HIGH (58).  Both
        must now come from the same evidence-weighted 0-100 model.
        """
        finding = {
            "id": "dom_injection", "type": "DOM injection", "severity": "HIGH",
            "confidence": "high", "status": "open", "evidence_type": "source_to_sink",
        }
        data = {"findings": [finding]}
        risk = file_risk(data)
        self.assertEqual(risk["score"], overall_risk(findings=[finding])["score"])
        self.assertGreaterEqual(risk["score"], 0)
        self.assertLessEqual(risk["score"], 100)

    def test_file_risk_observation_only_never_claims_critical(self):
        """A file full of inventory observations is posture, not CRITICAL."""
        data = {"findings": [
            {"id": "api_surface", "type": "API surface mapped", "severity": "LOW",
             "confidence": "low", "status": "informational",
             "evidence_type": "static_pattern", "observation": True},
            {"id": "obfuscation", "type": "Obfuscation signals", "severity": "LOW",
             "confidence": "low", "status": "informational",
             "evidence_type": "static_pattern", "observation": True},
        ]}
        risk = file_risk(data)
        self.assertNotEqual(risk["label"], "CRITICAL")
        self.assertLess(risk["score"], 25)

    def test_report_model_file_chips_are_evidence_weighted(self):
        code = (
            "const q = new URLSearchParams(location.search).get('q');\n"
            "document.getElementById('x').innerHTML = q;\n"
        )
        results = analyze_content(code, filename="app.js")
        model = build_report_model(results, metadata={"mode": "code", "source": "app.js"})
        self.assertEqual(len(model["files"]), 1)
        file = model["files"][0]
        # The chip must agree with the per-file evidence model exactly.
        expected = file_risk(file)["score"]
        self.assertEqual(file["score"], expected)
        self.assertIn(file["risk"], ("LOW", "MEDIUM", "HIGH", "CRITICAL"))
        # A high-confidence source-to-sink flow is actionable, never LOW.
        self.assertIn(file["risk"], ("MEDIUM", "HIGH", "CRITICAL"))

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
