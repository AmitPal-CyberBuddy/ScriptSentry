"""Crypto-implementation detection.

The marker catalogue lives in :mod:`core.js_patterns`, shared with
``core.scanner`` so the raw inventory and this analyzer report the same
findings.  Patterns are word-bounded and case-sensitive where the casing
carries meaning (AES vs aes, DES vs des): a plain substring test flags "DES"
inside "desktop" and "AES" inside "aesthetics", which turned every design-token
or desktop-theme helper into a crypto finding.
"""
from core.js_patterns import CRYPTO_CALL_RE, CRYPTO_MARKERS, crypto_markers_in

# Re-exported: callers and tests import these names from here.
__all__ = ["CRYPTO_MARKERS", "CRYPTO_CALL_RE", "analyze"]


def analyze(content, previous=None):
    findings = crypto_markers_in(content)
    if CRYPTO_CALL_RE.search(content or ""):
        findings.append({"name": "crypto_flow", "evidence": "cryptographic operation detected"})
    return findings
