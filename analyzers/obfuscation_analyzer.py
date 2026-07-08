import re


def analyze(content, previous=None):
    findings = {"decoded_values": [], "evidence": []}
    for pattern in [r'([A-Za-z0-9+/]{20,}={0,2})', r'([A-Fa-f0-9]{20,})']:
        for match in re.findall(pattern, content):
            candidate = match.strip()
            if len(candidate) > 16 and candidate.isalnum():
                findings["decoded_values"].append(candidate[:80])
    if re.search(r'\\x[0-9a-f]{2}|\\u[0-9a-f]{4}', content):
        findings["evidence"].append("escaped strings")
    if re.search(r'\[\s*["\'][^"\']+["\']\s*,\s*["\'][^"\']+["\']\s*\]', content):
        findings["evidence"].append("array lookup structure")
    if re.search(r'\b(?:atob|btoa|decodeURIComponent|encodeURIComponent)\s*\(', content):
        findings["evidence"].append("encoding helpers")
    return findings
