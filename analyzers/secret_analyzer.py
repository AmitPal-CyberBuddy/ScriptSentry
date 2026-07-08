import re


def _classify_secret(name, value):
    text = f"{name} {value}".lower()
    if any(term in text for term in ["client_secret", "private_key", "service_account", "password", "passwd", "pwd", "aws_secret", "azure_secret", "gcp_key"]):
        return "CRITICAL"
    if any(term in text for term in ["token", "api_key", "access_token", "refresh_token", "jwt", "authorization", "bearer", "firebase", "smtp", "database", "connection_string"]):
        return "SENSITIVE"
    if len(value) > 12 and not value.isalpha():
        return "INTERNAL"
    return "PUBLIC"


def analyze(content, previous=None):
    findings = []
    patterns = [
        ("api_key", r'(?i)(api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key)\s*[:=]\s*["\']([^"\']+)["\']'),
        ("auth_header", r'(?i)(authorization|bearer|token)\s*[:=]\s*["\']([^"\']+)["\']'),
        ("credential", r'(?i)(password|passwd|pwd|username|user|email|smtp|database)\s*[:=]\s*["\']([^"\']+)["\']'),
        ("jwt", r'(eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)'),
    ]
    for kind, pattern in patterns:
        for match in re.finditer(pattern, content):
            name = match.group(1) if len(match.groups()) > 1 else kind
            value = match.group(2) if len(match.groups()) > 1 else match.group(0)
            if not value or len(str(value)) < 4:
                continue
            findings.append({
                "kind": kind,
                "name": str(name),
                "value": str(value)[:160],
                "classification": _classify_secret(str(name), str(value)),
            })
    return findings
