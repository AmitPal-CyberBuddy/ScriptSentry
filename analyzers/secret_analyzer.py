"""Credential-shaped assignment detection.

Only genuinely secret-bearing names are reported.  Identity fields such as
``user``, ``username`` and ``email`` are inventory, not credentials -- the
previous version reported ``user: "johndoe"`` as a credential finding.
"""
import re

from core.secret_validation import validate

# name patterns -> classification
PATTERNS = [
    (
        "api_key",
        re.compile(
            r"(?i)(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret"
            r"|private[_-]?key|secret[_-]?key|auth[_-]?token)\s*[:=]\s*[\"']([^\"']+)[\"']"
        ),
        "SENSITIVE",
    ),
    (
        "auth_header",
        re.compile(r"(?i)(?:authorization|bearer)\s*[:=]\s*[\"']([^\"']+)[\"']"),
        "SENSITIVE",
    ),
    (
        "credential",
        re.compile(
            r"(?i)(?:password|passwd|pwd|secret|smtp[_-]?pass|db[_-]?password"
            r"|database[_-]?url|connection[_-]?string)\s*[:=]\s*[\"']([^\"']+)[\"']"
        ),
        "CRITICAL",
    ),
    (
        "jwt",
        re.compile(r"(eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)"),
        "SENSITIVE",
    ),
]

# Values that are placeholders rather than real material.
PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:xxx+|\*+|todo|tbd|changeme|placeholder|your[_-]?\w*|<[^>]+>|\$\{[^}]+\})$"
)


def _classify_secret(name, value):
    text = f"{name} {value}".lower()
    if any(term in text for term in (
        "client_secret", "private_key", "service_account", "password", "passwd",
        "pwd", "aws_secret", "azure_secret", "gcp_key", "connection_string",
    )):
        return "CRITICAL"
    if any(term in text for term in (
        "token", "api_key", "access_token", "refresh_token", "jwt",
        "authorization", "bearer", "firebase", "smtp", "database", "secret",
    )):
        return "SENSITIVE"
    if len(str(value)) > 12 and not str(value).isalpha():
        return "INTERNAL"
    return "PUBLIC"


def analyze(content, previous=None):
    findings = []
    seen = set()
    for kind, pattern, _default in PATTERNS:
        for match in pattern.finditer(content or ""):
            # `match.groups() > 1` compared a tuple to an int (TypeError on
            # every match, silently swallowed into analyzer_errors) -- the
            # analyzer never produced a single finding. Use group counts.
            groups = match.groups()
            if len(groups) >= 2:
                name, value = groups[0], groups[-1]
            elif groups:
                name, value = kind, groups[0]
            else:
                name, value = kind, match.group(0)
            if not value or len(str(value)) < 6:
                continue
            if PLACEHOLDER_RE.match(str(value).strip()):
                continue
            key = (kind, str(value).lower())
            if key in seen:
                continue
            seen.add(key)
            # The value itself can prove what it is (JWT structure, canonical
            # provider formats) -- carry that verdict so reports can say
            # "validated format" instead of a bare heuristic guess.
            verdict = validate(str(value))
            findings.append({
                "kind": kind,
                "name": str(name)[:80],
                "value": str(value)[:160],
                "classification": _classify_secret(str(name), str(value)),
                **({"validated": verdict} if verdict else {}),
            })
    return findings
