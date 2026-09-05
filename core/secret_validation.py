"""Provider-aware validation for credential-shaped candidates.

Entropy and character-class heuristics cannot tell a real Slack token from a
loud constant. For a growing set of providers the *value itself* proves what
it is: JWTs must base64url-decode into JSON with an ``alg`` header, PEM keys
must carry a decodable body, and Slack/GitHub/Stripe/SendGrid/AWS tokens
have canonical, documented shapes that random strings do not match by
accident.

``validate`` returns a tiered verdict:

* ``structure``  — the value internally decodes (JWT/PEM): strongest static
  evidence short of an authenticated probe;
* ``format``     — canonical provider shape: strong signal, honest about
  being shape-only.

Callers use the tier to upgrade a candidate from "candidate" to
"validated format/structure" — and, just as importantly, ``validate``
returns ``None`` for everything else so ordinary strings gain nothing.
"""
import base64
import json
import re

__all__ = ["validate", "PROVIDER_PATTERNS"]

# Canonical, documented value shapes. Lengths are part of the format where
# the provider specifies one; every pattern is anchored.
PROVIDER_PATTERNS = [
    ("slack_token", re.compile(r"^xox[abprs]-[A-Za-z0-9-]{10,}$")),
    ("github_token", re.compile(r"^gh[pousr]_[A-Za-z0-9]{36}$")),
    ("sendgrid_key", re.compile(r"^SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}$")),
    ("stripe_secret_key", re.compile(r"^[sr]k_(live|test)_[A-Za-z0-9]{24,}$")),
    ("aws_access_key_id", re.compile(r"^(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}$")),
    ("twilio_api_key", re.compile(r"^SK[0-9a-fA-F]{32}$")),
    ("google_oauth_client_secret", re.compile(r"^GOCSPX-[A-Za-z0-9_\-]{27}$")),
    ("npm_token", re.compile(r"^npm_[A-Za-z0-9]{36}$")),
]


def _b64url_decode(segment):
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded.encode())


def _validate_jwt(value):
    """A JWT must be three base64url segments whose header and payload JSON-decode."""
    parts = value.split(".")
    if len(parts) != 3 or not all(parts):
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    if not header.get("alg"):
        return None
    detail = f"JWT decodes cleanly (alg={header.get('alg')}"
    if isinstance(payload.get("exp"), (int, float)):
        detail += ", exp claim present"
    return {"provider": "jwt", "tier": "structure", "detail": detail + ")"}


def _validate_pem(value):
    """A PEM block: header, base64 body, footer."""
    if not value.startswith("-----BEGIN"):
        return None
    if "-----END" not in value:
        return None
    kind_match = re.match(r"-----BEGIN ([A-Z0-9 ]+)-----", value)
    body = re.sub(r"-----[A-Z ]+-----|\s+", "", value)
    if not kind_match or len(body) < 100:
        return None
    try:
        base64.b64decode(body[: 256] + "=" * (-len(body[:256]) % 4), validate=True)
    except Exception:
        return None
    return {"provider": kind_match.group(1).title(), "tier": "structure",
            "detail": f"PEM {kind_match.group(1)} block with decodable body"}


def validate(value):
    """Tiered validation verdict for one candidate value, or ``None``.

    >>> validate("xoxb-123456789-abcdefghijklmnopqrstuv")
    {'provider': 'slack_token', 'tier': 'format', ...}
    >>> validate("not-a-secret")  # returns None
    """
    text = str(value or "").strip()
    if not text or len(text) < 12:
        return None

    # Structural proofs first: a JWT contains no spaces anyway, and a PEM
    # block's header ("-----BEGIN PRIVATE KEY-----") legitimately does.
    jwt = _validate_jwt(text)
    if jwt:
        return jwt
    pem = _validate_pem(text)
    if pem:
        return pem

    # The canonical provider formats are single tokens; spaces mean prose.
    if " " in text:
        return None
    for provider, pattern in PROVIDER_PATTERNS:
        if pattern.match(text):
            return {"provider": provider, "tier": "format",
                    "detail": f"matches the canonical {provider} format"}
    return None
