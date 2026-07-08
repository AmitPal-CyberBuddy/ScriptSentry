import re


def analyze(content, previous=None):
    findings = []
    patterns = [
        ("environment", r'(?i)(process\.env|import\.meta\.env|window\.[A-Z_]+)'),
        ("feature_flag", r'(?i)(feature.?flag|enable.*debug|debug.*mode)'),
        ("production_url", r'https?://(?:api|www|app|cdn)[^\s"\']+'),
        ("cdn_url", r'(?i)(cdn|unpkg|jsdelivr|cloudflare)'),
    ]
    for name, pattern in patterns:
        if re.search(pattern, content):
            findings.append({"name": name, "evidence": name})
    return findings
