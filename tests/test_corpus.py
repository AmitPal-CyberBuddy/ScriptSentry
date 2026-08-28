from pathlib import Path
import unittest

from core.analyzer_service import analyze_content
from core.script_intel import data_exfiltration_candidates


CORPUS = Path(__file__).parent / "corpus"


def analyze_fixture(relative_path):
    path = CORPUS / relative_path
    return analyze_content(path.read_text(encoding="utf-8"), filename=path.name)[path.name]


class CorpusContractTest(unittest.TestCase):
    """Accuracy contracts for representative behavior and false positives."""

    def test_reachable_dom_flow_is_stronger_than_sanitized_flow(self):
        reachable = analyze_fixture("dom-xss/reachable-query.js")
        sanitized = analyze_fixture("dom-xss/sanitized-query.js")
        reachable_flows = reachable.get("dataflows", [])
        sanitized_flows = sanitized.get("dataflows", [])
        self.assertTrue(any(flow.get("status") == "confirmed" for flow in reachable_flows))
        self.assertTrue(any(flow.get("status") == "informational" for flow in sanitized_flows))
        self.assertFalse(any(flow.get("status") == "confirmed" for flow in sanitized_flows))

    def test_fixture_secrets_are_not_credible(self):
        fixture = analyze_fixture("secrets/fixture-token.js")
        credible = fixture.get("credible_secrets", [])
        self.assertEqual(credible, [])
        self.assertFalse(any(f.get("id") == "hardcoded_secret" for f in fixture.get("findings", [])))

    def test_realistic_secret_is_reviewable_not_confirmed(self):
        data = analyze_fixture("secrets/credible-token.js")
        self.assertTrue(data.get("credible_secrets"))
        secret_findings = [f for f in data.get("findings", []) if f.get("id") == "hardcoded_secret"]
        self.assertTrue(secret_findings)
        self.assertTrue(all(f.get("status") != "confirmed" for f in secret_findings))

    def test_high_value_sources_and_sinks_are_tracked(self):
        redirect = analyze_fixture("open-redirect/query.js")
        self.assertTrue(any(f.get("id") == "open_redirect" and f.get("status") == "confirmed" for f in redirect.get("dataflows", [])))

        candidate = analyze_fixture("data-exfiltration/candidate.js")
        candidates = data_exfiltration_candidates({"candidate.js": candidate}, page_url="https://example.com/")
        self.assertTrue(candidates)
        self.assertEqual(candidates[0].get("evidence_type"), "behavioral_correlation")

    def test_all_fixture_files_are_readable(self):
        fixture_paths = sorted(CORPUS.rglob("*.js"))
        self.assertGreaterEqual(len(fixture_paths), 10)
        for path in fixture_paths:
            self.assertTrue(path.read_text(encoding="utf-8").strip(), path)


if __name__ == "__main__":
    unittest.main()
