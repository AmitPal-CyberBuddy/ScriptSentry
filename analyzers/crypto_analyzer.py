import re


def analyze(content, previous=None):
    findings = []
    keywords = ["AES", "DES", "RC4", "CBC", "ECB", "GCM", "HmacSHA", "SHA256", "SHA512", "CryptoJS", "Forge", "sjcl", "OpenPGP"]
    for keyword in keywords:
        if keyword.lower() in content.lower():
            findings.append({"name": keyword, "evidence": keyword})
    if re.search(r'\b(?:encrypt|decrypt|cipher|decipher)\s*\(', content):
        findings.append({"name": "crypto_flow", "evidence": "cryptographic operation detected"})
    return findings
