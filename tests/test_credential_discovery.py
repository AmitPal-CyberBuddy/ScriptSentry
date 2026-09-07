"""Credential discovery accuracy: value shapes, folding, line numbers.

Pins the three detection upgrades from the 2026-09 accuracy review:

1.  **Canonical provider formats override fixture heuristics.** A value that
    matches a documented credential shape (AWS ``AKIA…``, GitHub ``ghp_…``,
    Slack, Stripe, SendGrid, Twilio, npm) — or a JWT/PEM that actually
    decodes — is stronger evidence than entropy/marker heuristics, so it must
    not be dropped for containing "example"/"xxx"-like substrings a real key
    can legitimately carry. Public-by-design client keys stay excluded.
2.  **String-literal concatenation is folded before discovery.**
    ``"AKIA" + "IOSFODNN7EXAMPLE"`` was invisible to every pattern; folded
    values flow through the same credibility pipeline, carry the chain's line
    number, and respect the assignment name when one exists.
3.  **Secret findings carry a line number.** Every export used to show
    line 0; the signal now points at the first credible secret (or chain).
"""
import unittest

from core.scanner import _folded_concat_candidates, scan_content
from core.secret_validation import validate


def _ids(code):
    return {f["id"] for f in (scan_content(code).get("findings") or [])}


def _secret_finding(code):
    for f in scan_content(code).get("findings") or []:
        if f["id"] == "hardcoded_secret":
            return f
    return None


class CanonicalFormatDiscoveryTest(unittest.TestCase):
    """A well-shaped credential is found regardless of its variable name."""

    def test_bare_aws_key_is_found_even_with_example_substring(self):
        # The canonical AWS docs example key: shape-identical to a live key.
        f = _secret_finding('var real = "AKIAIOSFODNN7EXAMPLE";')
        self.assertIsNotNone(f)
        self.assertEqual(f["confidence"], "high")  # validated provider format
        self.assertEqual(f["line"], 1)

    def test_bare_github_token_is_found(self):
        f = _secret_finding('var real = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";')
        self.assertIsNotNone(f)
        self.assertEqual(f["confidence"], "high")

    def test_sendgrid_key_is_found(self):
        part1 = "abcdefghijKLMNOPQRSTuv"                      # 22 chars
        part2 = "wxYz0123456789abcdefghijklmNOPQRSTUVWabcdef"  # 43 chars
        value = f"SG.{part1}.{part2}"
        self.assertEqual(validate(value)["provider"], "sendgrid_key")
        f = _secret_finding(f'var sg = "{value}";')
        self.assertIsNotNone(f)
        self.assertEqual(f["confidence"], "high")

    def test_twilio_and_npm_shapes_are_found(self):
        self.assertIsNotNone(_secret_finding('var t = "SK0123456789abcdef0123456789abcdef";'))
        self.assertIsNotNone(_secret_finding('var n = "npm_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";'))

    def test_public_client_keys_stay_excluded(self):
        # Public-by-design identifiers are inventory, not credentials, and the
        # public check deliberately wins over any format bypass.
        code = (
            'var g = "AIzaSyB1234567890abcdefghijklmnopqrstuv";\n'
            'var s = "pk_live_51H8xQz2eZvKYlo2CabcDEF123";\n'
            'var o = "GOCSPX-0123456789-abcdefghijklmnopqr";\n'
        )
        self.assertNotIn("hardcoded_secret", _ids(code))

    def test_placeholders_are_still_filtered(self):
        code = (
            'const token = "sample-placeholder-token";\n'
            'const k = "YOUR_API_TOKEN_HERE";\n'
            'const docs = "https://api.example.com/v1";\n'
        )
        self.assertNotIn("hardcoded_secret", _ids(code))


class ConcatFoldingTest(unittest.TestCase):
    def test_fold_extracts_chained_literals_with_line(self):
        code = 'var a=1;\nvar k = "AKIA" + "IOSFODNN7EXAMPLE";\nsend(k);'
        pairs = _folded_concat_candidates(code)
        self.assertEqual(len(pairs), 1)
        candidate, line = pairs[0]
        self.assertIn("AKIAIOSFODNN7EXAMPLE", candidate)
        self.assertEqual(line, 2)

    def test_folded_provider_key_is_detected_at_chain_line(self):
        code = 'var config = 1;\nvar aws = "AKIA" + "IOSFODNN7EXAMPLE";\nsend(aws);'
        f = _secret_finding(code)
        self.assertIsNotNone(f, "concat-split AWS key was not discovered")
        self.assertEqual(f["line"], 2)

    def test_folded_named_password_is_detected(self):
        code = 'var a=1;\nvar b=2;\nvar password = "Sup3r" + "S3cretB4tteryStaple";\nlogin(password);'
        f = _secret_finding(code)
        self.assertIsNotNone(f, "name-assigned concat secret was not discovered")
        self.assertEqual(f["line"], 3)

    def test_folding_ignores_url_concatenation(self):
        code = 'var u = "https://api." + "example.com/v1"; fetch(u);'
        self.assertNotIn("hardcoded_secret", _ids(code))

    def test_folding_skips_short_fragments(self):
        code = 'var s = "ab" + "cd";'
        self.assertEqual(_folded_concat_candidates(code), [])


class SecretLineNumbersTest(unittest.TestCase):
    def test_finding_points_at_the_secret_line(self):
        code = (
            "var a = 1;\n"
            "var b = 2;\n"
            'var apiKey = "kx9vQm2LpTn8Rb4Wc6Yd3Zf7Hj5";\n'
            "var c = 3;\n"
        )
        f = _secret_finding(code)
        self.assertIsNotNone(f)
        self.assertEqual(f["line"], 3)

    def test_line_survives_into_exports(self):
        from core.reporter import generate_csv_report, generate_sarif_report
        import csv
        import io
        import json

        code = 'var a=1;\nvar apiKey = "kx9vQm2LpTn8Rb4Wc6Yd3Zf7Hj5";\n'
        results = {"inline.js": scan_content(code)}
        row = next(iter(csv.DictReader(io.StringIO(generate_csv_report(results)))))
        self.assertEqual(row["id"], "hardcoded_secret")
        self.assertEqual(row["line"], "2")
        sarif = json.loads(generate_sarif_report(results))
        result = sarif["runs"][0]["results"][0]
        # SARIF lines are 0-indexed.
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startLine"], 1)


if __name__ == "__main__":
    unittest.main()
