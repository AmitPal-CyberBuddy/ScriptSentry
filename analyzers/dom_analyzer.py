import re


def analyze(content, previous=None):
    findings = []
    patterns = [
        ("innerHTML", r'\binnerHTML\b'),
        ("outerHTML", r'\bouterHTML\b'),
        ("eval", r'\beval\s*\('),
        ("new_function", r'\bnew\s+Function\s*\('),
        ("document_write", r'\bdocument\.write\s*\('),
        ("script_injection", r'\bscript\b.*\bsrc\b|createElement\(\s*["\']script["\']\)'),
    ]
    for name, pattern in patterns:
        if re.search(pattern, content):
            findings.append(name)
    return findings
