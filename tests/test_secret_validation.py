"""Credential validation tiers: the value itself proves what it is.

Entropy heuristics guess; JWTs that decode and canonical provider formats
are *evidence*. These tests pin the tiered validator, its integration into
the secret analyzer (which, it turned out, had never produced a finding at
all -- a tuple/int TypeError on every match was silently swallowed), and the
confidence upgrade on the unified hardcoded-secret signal.
"""
import base64
import json
import unittest

from analyzers.secret_analyzer import analyze
from core.scanner import scan_content
from core.secret_validation import validate


def b64url(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def make_jwt(alg="HS256", payload=None, signature="SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"):
    header = b64url({"alg": alg, "typ": "JWT"})
    body = b64url(payload if payload is not None else {"sub": "1", "exp": 1735689600})
    return f"{header}.{body}.{signature}"


def make_pem():
    body = base64.b64encode(b"0" * 200).decode()
    return f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----"


class ValidateTest(unittest.TestCase):
    def test_structurally_valid_jwt_is_tier_structure(self):
        verdict = validate(make_jwt(payload={"sub": "1", "exp": 1735689600}))
        self.assertEqual(verdict["provider"], "jwt")
        self.assertEqual(verdict["tier"], "structure")
        self.assertIn("alg=HS256", verdict["detail"])
        self.assertIn("exp", verdict["detail"])

    def test_broken_jwt_is_not_validated(self):
        self.assertIsNone(validate("eyJhbGciOiJIUzI1NiJ9.!!!not-base64!!!.sig"))
        self.assertIsNone(validate("a.b.c"))
        # Header decodes but has no alg claim -> not a real JWT.
        self.assertIsNone(validate(f"{b64url({})}.{b64url({'a': 1})}.sig"))

    def test_pem_block_is_tier_structure(self):
        verdict = validate(make_pem())
        self.assertEqual(verdict["tier"], "structure")
        self.assertIn("Private Key", verdict["provider"])

    def test_canonical_provider_formats(self):
        cases = {
            "xoxb-123456789-abcdefghijklmnopqrstuv": "slack_token",
            "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Qr7s": "github_token",
            "sk_live_A1b2C3d4E5f6G7h8I9j0K1l2": "stripe_secret_key",
            "AKIA" + "A1B2C3D4E5F6G7H8": "aws_access_key_id",
            "SG." + "a" * 22 + "." + "b" * 43: "sendgrid_key",
            "npm_" + "a1B2" * 9: "npm_token",
        }
        for value, provider in cases.items():
            verdict = validate(value)
            self.assertIsNotNone(verdict, value)
            self.assertEqual(verdict["provider"], provider, value)
            self.assertEqual(verdict["tier"], "format")

    def test_ordinary_strings_gain_nothing(self):
        for value in ("aaaaaaaaaaaaaaaaaaaa", "hello world this is prose", "",
                      "Ab3x9Kq1Zp7m9", "the user password is hunter2"):
            self.assertIsNone(validate(value), value)


class SecretAnalyzerFixTest(unittest.TestCase):
    """Regression: the analyzer errored on EVERY match (tuple/int compare)."""

    CODE = (
        'const apiKey = "sk_live_A1b2C3d4E5f6G7h8I9j0K1l2";\n'
        f'const jwt = "{make_jwt()}";\n'
        'const config = "just a long config value";\n'
    )

    def test_matches_produce_findings_again(self):
        findings = analyze(self.CODE)
        kinds = {f["kind"] for f in findings}
        self.assertIn("api_key", kinds, "the analyzer must actually emit findings")
        self.assertIn("jwt", kinds)

    def test_validated_candidates_carry_their_verdict(self):
        findings = analyze(self.CODE)
        by_kind = {f["kind"]: f for f in findings}
        self.assertEqual(by_kind["api_key"]["validated"]["provider"], "stripe_secret_key")
        self.assertEqual(by_kind["jwt"]["validated"]["tier"], "structure")

    def test_unvalidated_candidates_carry_no_verdict(self):
        findings = analyze('const config = "just a long config value";')
        for finding in findings:
            self.assertNotIn("validated", finding)


class SignalConfidenceUpgradeTest(unittest.TestCase):
    def _signal(self, code):
        results = scan_content(code, filename="app.js")
        for signal in results["risk_signals"]:
            if signal["id"] == "hardcoded_secret":
                return signal
        return None

    def test_validated_candidate_upgrades_confidence_to_high(self):
        signal = self._signal(
            f'const token = "{make_jwt()}";\n'
            'const slack = "xoxb-123456789-abcdefghijklmnopqrstuv";\n'
        )
        self.assertIsNotNone(signal)
        self.assertEqual(signal["confidence"], "high")
        providers = {v["provider"] for v in signal.get("validated", [])}
        self.assertIn("slack_token", providers)

    def test_plain_entropy_candidate_stays_medium(self):
        # High-entropy but provider-unknown: credible, but honestly medium.
        signal = self._signal('const apiKey = "Zx9Qw3Er5Tt7Yu2Io4Pp8La5Sd6Fh1Gj";\n')
        if signal is not None:
            self.assertEqual(signal["confidence"], "medium")
            self.assertNotIn("validated", signal)

    def test_public_client_keys_never_become_signals(self):
        # AIza... keys are public-by-design inventory: no hardcoded-secret
        # signal, validated or otherwise.
        results = scan_content('const g = "AIzaSyA1bC2dE3fG4hI5jK6lL7mM8nN9oO0pP1qQ";\n', filename="app.js")
        self.assertFalse(any(s["id"] == "hardcoded_secret" for s in results["risk_signals"]))


if __name__ == "__main__":
    unittest.main()
