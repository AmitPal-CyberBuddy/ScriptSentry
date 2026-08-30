"""One catalogue of JavaScript detection patterns.

``core/taint.py``, ``core/scanner.py`` and the modules under ``analyzers/`` all
answer questions about the same language.  When each of them kept its own
regex table the copies drifted: a sink added to the taint engine was invisible
to the DOM analyzer, and the two could disagree about whether ``eval(`` counts
as a sink.  This module is the single source of truth -- everything else
imports from here.

Adding a sink here makes it visible to *both* the source-to-sink engine and
the per-file analyzers.
"""
import re

# ---------------------------------------------------------------------------
# Sources: where attacker- or user-controlled data enters the script
# ---------------------------------------------------------------------------
SOURCE_PATTERNS = {
    "location.search": "URL query string",
    "url.search": "URL query string",
    "searchParams": "URL search params",
    "location.hash": "URL fragment",
    "url.hash": "URL fragment",
    "location.href": "full URL",
    "window.location": "full URL",
    "document.referrer": "referrer",
    "document.baseURI": "document base URL",
    "history.state": "history state",
    "event.data": "postMessage/window message data",
    "e.data": "postMessage/window message data",
    "message.data": "postMessage/window message data",
    "localStorage": "localStorage",
    "sessionStorage": "sessionStorage",
    "document.cookie": "document.cookie",
    "window.name": "window.name",
    "location": "location object",
    "innerText": "DOM text content",
    "value": "form/input value",
}

# Data that is worth stealing -- used by the exfiltration heuristic.
SENSITIVE_READ_RE = re.compile(
    r"document\s*\.\s*cookie"
    r"|localStorage|sessionStorage"
    r"|navigator\s*\.\s*userAgent"
    r"|(?:auth|access|refresh|id)[_-]?token"
    r"|password|credential",
    re.I,
)

# ---------------------------------------------------------------------------
# Sinks: where data becomes dangerous
# ---------------------------------------------------------------------------
DANGEROUS_SINK_ASSIGN = {
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "srcdoc",
    "href",
    "src",
}

DANGEROUS_SINK_CALL_KEYWORDS = {
    "eval",
    "Function",
    "setTimeout",
    "setInterval",
    "document.write",
    "document.writeln",
    "insertAdjacentHTML",
    "replace",
    "assign",
    "open",
    "postMessage",
    "html",
    "append",
    "dangerouslySetInnerHTML",
}

SANITIZER_HINTS = (
    "sanitize", "_sanitize", "escapehtml", "escape_html", "htmlencode",
    "encodeuricomponent", "encodeuri", "textcontent", "createtextnode",
    "dopurify", "stringreplace", "xss", "deburr", "striptags",
)

# ---------------------------------------------------------------------------
# DOM sinks (shared by core.taint and analyzers.dom_analyzer)
# ---------------------------------------------------------------------------
# Anchored to real code, not to any line that happens to contain two keywords:
# the old ``script_injection`` rule used ``\bscript\b.*\bsrc\b``, which matched
# the comment ``// load the script src from config``.
DOM_SINK_PATTERNS = [
    ("innerHTML", re.compile(r"\binnerHTML\s*(?:=(?!=)|\+=)")),
    ("outerHTML", re.compile(r"\bouterHTML\s*(?:=(?!=)|\+=)")),
    ("insertAdjacentHTML", re.compile(r"\binsertAdjacentHTML\s*\(")),
    ("document_write", re.compile(r"\bdocument\s*\.\s*write(?:ln)?\s*\(")),
    ("eval", re.compile(r"\beval\s*\(")),
    ("new_function", re.compile(r"\bnew\s+Function\s*\(")),
    # Real dynamic script loading: an element is created and given a src.
    ("script_injection", re.compile(
        r"createElement\s*\(\s*['\"]script['\"]\s*\)"
        r"|(?:\.src\s*=\s*[^;\n]+\.js\b)",
    )),
    ("srcdoc", re.compile(r"\bsrcdoc\s*=")),
    ("setAttribute_sink", re.compile(r"\bsetAttribute\s*\(\s*['\"](?:href|src|srcdoc)['\"]")),
    ("dangerous_innerhtml_call", re.compile(r"\.(?:html|append|prepend)\s*\(")),
]

# Sinks that are dangerous on their own versus sinks that need tainted data.
FRAMEWORK_SINKS = ("dangerouslySetInnerHTML", "v-html", "bypassSecurityTrust")

# ---------------------------------------------------------------------------
# Crypto markers (shared by core.scanner and analyzers.crypto_analyzer)
# ---------------------------------------------------------------------------
# Case sensitive on purpose: a plain substring test flags "DES" inside
# "desktop" and "AES" inside "aesthetics", which turned every design-token or
# desktop-theme helper into a crypto finding.
CRYPTO_MARKERS = [
    ("AES", re.compile(r"\bAES(?:-[0-9]+)?\b")),
    ("DES", re.compile(r"\b(?:DES|3DES|TripleDES)\b")),
    ("RC4", re.compile(r"\bRC4\b")),
    ("CBC", re.compile(r"\bCBC\b")),
    ("ECB", re.compile(r"\bECB\b")),
    ("GCM", re.compile(r"\bGCM\b")),
    ("HMAC", re.compile(r"\bHmac(?:SHA[0-9]+|MD5)?\b")),
    ("SHA256", re.compile(r"\bSHA-?256\b", re.I)),
    ("SHA512", re.compile(r"\bSHA-?512\b", re.I)),
    ("CryptoJS", re.compile(r"\bCryptoJS\b")),
    ("Forge", re.compile(r"\bforge\b")),
    ("sjcl", re.compile(r"\bsjcl\b")),
    ("OpenPGP", re.compile(r"\bOpenPGP\b")),
    ("WebCrypto", re.compile(r"crypto\s*\.\s*subtle|window\s*\.\s*crypto")),
    ("SHA1", re.compile(r"\bSHA-?1\b", re.I)),
    ("Base64", re.compile(r"\bBase\s*-?\s?64\b", re.I)),
    ("Utf8", re.compile(r"\bUtf\s*-?\s?8\b", re.I)),
    ("Hex", re.compile(r"\bHex\b")),
    ("encrypt", re.compile(r"\bencrypt(?:ion)?\b", re.I)),
    ("decrypt", re.compile(r"\bdecrypt(?:ion)?\b", re.I)),
]

CRYPTO_CALL_RE = re.compile(
    r"\b(?:encrypt|decrypt|cipher|decipher|createCipheriv|createDecipheriv"
    r"|createHmac|deriveKey|generateKey)\s*\("
)

# ---------------------------------------------------------------------------
# Network / transport (shared by core.scanner and analyzers.api_analyzer)
# ---------------------------------------------------------------------------
CALL_PATTERNS = [
    ("fetch", re.compile(r"\bfetch\s*\(\s*['\"]([^'\"]+)['\"]")),
    ("axios", re.compile(r"\baxios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]")),
    ("xhr", re.compile(r"\bnew\s+XMLHttpRequest\s*\(")),
    ("graphql", re.compile(r"\bgraphql\b", re.I)),
    ("websocket", re.compile(r"\bnew\s+WebSocket\s*\(\s*['\"]([^'\"]*)['\"]")),
    ("sse", re.compile(r"\bnew\s+EventSource\s*\(\s*['\"]([^'\"]*)['\"]")),
]

PATH_FALLBACK_RE = re.compile(r"/(?:api|auth|graphql|v[0-9]+|oauth|login|logout)/[A-Za-z0-9/_\-]*")

# How far forward a call's context reaches before it belongs to the next call.
CONTEXT_CHARS = 220

# The start of another request marks the end of this call's context, so an
# Authorization header on a *different* call does not leak backwards.
NEXT_CALL_RE = re.compile(r"\b(?:fetch|axios|XMLHttpRequest)\s*[\(\.]")

AUTH_HINT_RE = re.compile(
    r"Authorization|Bearer\s|authToken|access[_-]?token|id[_-]?token"
    r"|headers\s*:\s*\{[^}]*(?:auth|token)|credentials\s*:\s*['\"]include",
    re.I,
)


def dom_sinks_in(content):
    """Names of the DOM sinks present in ``content`` (order-stable)."""
    return [name for name, pattern in DOM_SINK_PATTERNS if pattern.search(content or "")]


def crypto_markers_in(content):
    """``[{name, evidence}]`` for every crypto marker present in ``content``."""
    markers = []
    for name, pattern in CRYPTO_MARKERS:
        match = pattern.search(content or "")
        if match:
            markers.append({"name": name, "evidence": match.group(0)})
    return markers
