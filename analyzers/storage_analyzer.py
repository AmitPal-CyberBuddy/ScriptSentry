import re


def analyze(content, previous=None):
    findings = []
    patterns = [
        ("localStorage", r'\blocalStorage\.(?:getItem|setItem|removeItem)\s*\('),
        ("sessionStorage", r'\bsessionStorage\.(?:getItem|setItem|removeItem)\s*\('),
        ("cookie", r'\bdocument\.cookie\b|\bCookies?\.(?:get|set|remove)\b'),
        ("indexedDB", r'\bindexedDB\b'),
        ("cacheStorage", r'\bcaches?\b'),
    ]
    for name, pattern in patterns:
        if re.search(pattern, content, re.I):
            classification = "credential storage" if name in {"localStorage", "sessionStorage"} and re.search(r'(token|auth|secret|password)', content, re.I) else "sensitive storage" if name in {"cookie", "indexedDB"} else "safe storage"
            findings.append({"storage": name, "classification": classification})
    return findings
