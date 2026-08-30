"""API / transport inventory.

``auth_required`` is decided from the code *around each individual call*, not
from the file as a whole.  The previous version scanned the entire file for the
word "auth", so a single unrelated comment marked every endpoint in the file as
authenticated.
"""
import re

# The call/transport catalogue lives in core.js_patterns so a new transport
# type is picked up by every consumer at once.
from core.js_patterns import (
    AUTH_HINT_RE,
    CALL_PATTERNS,
    CONTEXT_CHARS,
    NEXT_CALL_RE,
    PATH_FALLBACK_RE,
)

# Re-exported: callers and tests import these names from here.
__all__ = ["CALL_PATTERNS", "PATH_FALLBACK_RE", "analyze"]

def _call_has_auth(content, start, end):
    """True when auth material appears in the code surrounding one call."""
    following = NEXT_CALL_RE.search(content, end)
    limit = following.start() if following else min(len(content), end + CONTEXT_CHARS)
    # Look back only within the current statement, so an Authorization header
    # belonging to a previous call is not attributed to this one.
    cut = max(content.rfind(";", 0, start), content.rfind("}", 0, start))
    start_from = cut + 1 if cut >= 0 else 0
    window = content[start_from:limit]
    return bool(AUTH_HINT_RE.search(window))


def analyze(content, previous=None):
    content = content or ""
    inventory = []
    seen = set()

    for kind, pattern in CALL_PATTERNS:
        for match in pattern.finditer(content):
            endpoint = match.group(1) if match.groups() else ""
            key = (kind, endpoint, match.start())
            if key in seen:
                continue
            seen.add(key)
            inventory.append({
                "kind": kind,
                "endpoint": endpoint,
                "auth_required": _call_has_auth(content, match.start(), match.end()),
            })
            if len(inventory) >= 40:
                break

    if not inventory:
        for match in PATH_FALLBACK_RE.finditer(content):
            inventory.append({
                "kind": "path",
                "endpoint": match.group(0),
                "auth_required": _call_has_auth(content, match.start(), match.end()),
            })
            if len(inventory) >= 40:
                break

    return inventory
