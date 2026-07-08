import re


def analyze(content, previous=None):
    findings = []
    auth_markers = [
        ("jwt", r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'),
        ("oauth", r'(?i)oauth|openid|oidc'),
        ("auth0", r'(?i)auth0'),
        ("firebase_auth", r'(?i)firebase.*auth|signInWith|getAuth'),
        ("msal", r'(?i)msal|azure ad|aad'),
        ("passport", r'(?i)passport'),
        ("nextauth", r'(?i)nextauth'),
    ]
    for name, pattern in auth_markers:
        if re.search(pattern, content):
            findings.append({"type": name, "evidence": name})
    if re.search(r'\b(localStorage|sessionStorage|document\.cookie|Cookies?)\.(?:setItem|getItem|set|remove)\b', content):
        findings.append({"type": "token_storage", "evidence": "token storage access detected"})
    if re.search(r'\b(fetch|axios|XMLHttpRequest)\s*\(', content):
        findings.append({"type": "token_transmission", "evidence": "authenticated request channel detected"})
    return findings
