"""Pairing-token and origin-trust checks for the local API.

Threat model: the engine binds to loopback and prints a per-process pairing
token. Any local process could otherwise ride a browser tab's same-origin
credentials (or a plain local socket) into the analysis API. Two gates:

  * the ``Origin`` header must be one we serve/trust (no prefix allowlists —
    exact origins only), and
  * API endpoints must present the pairing token in ``X-ScriptSentry-Token``
    (constant-time comparison).

GitHub Pages is a deployment surface, not an authentication boundary: its
origin is allowed for CORS but the token is still required.
"""
import hmac
import os
from urllib.parse import urlparse

from api.settings import API_TOKEN

TRUSTED_LOOPBACK_HTTP = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
TRUSTED_LOOPBACK_HTTPS = {"127.0.0.1", "::1"}


def is_allowed_origin(origin):
    """Check an exact browser origin; never use a prefix allowlist."""
    if not origin:
        return True
    if origin.lower() in ("null", "file://"):
        return True
    try:
        parsed = urlparse(origin)
        scheme = (parsed.scheme or "").lower()
        host = (parsed.hostname or "").lower().rstrip(".")
    except Exception:
        return False
    if scheme == "http" and host in TRUSTED_LOOPBACK_HTTP:
        return True
    if scheme == "https" and host in TRUSTED_LOOPBACK_HTTPS:
        return True
    if scheme == "https" and host.endswith(".github.io") and host != "github.io":
        return True
    configured = {
        value.strip().lower().rstrip("/")
        for value in os.environ.get("SCRIPTSENTRY_ALLOWED_ORIGINS", "").split(",")
        if value.strip()
    }
    return origin.lower().rstrip("/") in configured


class AuthMixin:
    """Origin/token gates mixed into the dashboard handler."""

    @staticmethod
    def _is_allowed_origin(origin):
        # Legacy hook kept: tests (and embedders) probe the trust decision
        # through the handler class.
        return is_allowed_origin(origin)

    def _reject_untrusted_origin(self):
        origin = self.headers.get("Origin", "")
        if origin and not is_allowed_origin(origin):
            self._send_error_json("Origin not allowed by the local engine", 403)
            return True
        return False

    def _require_api_auth(self):
        presented = self.headers.get("X-ScriptSentry-Token", "")
        if not presented or not hmac.compare_digest(str(presented), API_TOKEN):
            self._send_error_json("Engine pairing token required", 401)
            return False
        return True
