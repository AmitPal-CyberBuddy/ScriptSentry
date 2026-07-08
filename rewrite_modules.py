from pathlib import Path

crypto_code = r'''import base64
import re


# =========================================
# 🧠 SMART FILTER (BALANCED VERSION ✅)
# =========================================
def is_valid_key(value):
    val = value.strip('"').strip("'")

    if len(val) < 12 or len(val) > 64:
        return False

    blacklist = [
        "arrow", "enter", "ctrl", "shift",
        "draw", "render", "chart", "axis",
        "tooltip", "legend", "monaco",
        "encrypted", "header",
        "mat", "mdc", "ng", "p-", "btn",
        "form", "label", "component", "icon",
        "style", "class"
    ]

    if any(b in val.lower() for b in blacklist):
        return False

    if len(set(val)) < 5:
        return False

    if "/" in val and not re.match(r'^[A-Za-z0-9+/=]+$', val):
        return False

    return True


# =========================================
# 🔐 CRYPTO EXTRACTION ENGINE
# =========================================
def extract_crypto_material(content):
    findings = {
        "keys": [],
        "ivs": [],
        "base64_decoded": [],
        "aes_cbc_detected": False,
        "real_crypto_detected": False,
        "crypto_flows": [],
        "crypto_contexts": [],
        "logic_snippets": [],
        "function_defs": [],
        "deep_crypto": [],
        "target_imports": [],
        "env_vars": [],
        "secrets": [],
        "decoded_secrets": [],
        "derived_keys": [],
        "crypto_apis": [],
        "key_vars": [],
        "iv_vars": [],
        "crypto_modes": [],
        "flow_map": [],
        "confidence": "LOW"
    }

    crypto_patterns = [
        r'\w*encrypt\w*\(',
        r'\w*decrypt\w*\(',
        r'CryptoJS',
        r'\bAES\b',
        r'\bcrypto\.subtle\b',
        r'\bcreateCipheriv\b',
        r'\bcreateDecipheriv\b',
        r'\bpbkdf2\b',
        r'\bscrypt\b',
        r'\bforge\b',
        r'\bsjcl\b',
        r'\bnacl\b',
        r'\bopenpgp\b'
    ]

    crypto_locations = []
    for pattern in crypto_patterns:
        for match in re.finditer(pattern, content, re.I):
            findings["real_crypto_detected"] = True
            crypto_locations.append(match.start())
            findings["crypto_flows"].append(match.group())
            ctx = content[max(0, match.start() - 200):match.start() + 200]
            findings["crypto_contexts"].append(ctx)

    crypto_api_patterns = [
        r'\bcrypto\.subtle\b',
        r'\bcreateCipheriv\b',
        r'\bcreateDecipheriv\b',
        r'\bCryptoJS\b',
        r'\bforge\b',
        r'\bsjcl\b',
        r'\bnacl\b',
        r'\bopenpgp\b'
    ]
    for p in crypto_api_patterns:
        for match in re.findall(p, content, re.I):
            if match not in findings["crypto_apis"]:
                findings["crypto_apis"].append(match)

    candidates = re.findall(r'[\'\"][A-Za-z0-9+/=_\-]{12,}[\'\"]', content)
    for c in candidates:
        pos = content.find(c)
        if any(abs(pos - loc) < 400 for loc in crypto_locations) or "EncryptionKey" in content or re.search(r'(?i)(key|iv|nonce|vector|secret)\s*[:=]', content):
            if is_valid_key(c):
                findings["keys"].append(c)

    key_var_patterns = [
        r'(?i)(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["\'][^"\']{12,}["\']',
        r'(?i)(?:key|secret|password|token|encryptionKey|privateKey)\s*[:=]\s*([A-Za-z_][A-Za-z0-9_]*)'
    ]
    for pattern in key_var_patterns:
        for match in re.findall(pattern, content):
            if isinstance(match, tuple):
                match = match[0]
            if match not in findings["key_vars"]:
                findings["key_vars"].append(match)

    iv_patterns = [
        r'iv\s*[:=]\s*[\'\"][^\'\"]{8,}[\'\"]',
        r'EncryptionIV\s*[:=]\s*[\'\"][^\'\"]+[\'\"]',
        r'(?i)(?:iv|nonce|vector)\s*[:=]\s*[\'\"][^\'\"]+[\'\"]',
        r'Utf8\.parse\([^)]*iv[^)]*\)'
    ]
    for p in iv_patterns:
        findings["ivs"].extend(re.findall(p, content, re.I))

    env = re.findall(
        r'((EncryptionKey|EncryptionIV|key|iv|secret|token|nonce|vector)\s*[:=]\s*["\'][^"\']+["\'])',
        content,
        re.I
    )
    findings["env_vars"] = [e[0] for e in env]

    for e in findings["env_vars"]:
        val_match = re.search(r'["\']([^"\']+)["\']', e)
        if val_match:
            val = val_match.group(1)
            if is_valid_key(val):
                findings["keys"].append(f'"{val}"')

    priority_keys = []
    for k in findings["keys"]:
        val = k.strip('"').strip("'")
        if "EncryptionKey" in content or "key" in val.lower() or "secret" in val.lower():
            priority_keys.insert(0, k)
        elif len(set(val)) > 10 and len(val) > 16:
            priority_keys.insert(len(priority_keys) // 2, k)
        else:
            priority_keys.append(k)
    findings["keys"] = list(dict.fromkeys(priority_keys))[:10]

    if findings["real_crypto_detected"] and not findings["keys"]:
        fallback = re.findall(r'[\'\"][A-Za-z0-9+/=_\-]{16,}[\'\"]', content)
        for f in fallback:
            if is_valid_key(f):
                findings["keys"].append(f)

    mode_patterns = [r'\b(CBC|GCM|CTR|ECB|OFB|CFB|CCM)\b', r'\b(HmacSHA|SHA1|SHA256|SHA512)\b']
    for p in mode_patterns:
        for match in re.findall(p, content, re.I):
            if match not in findings["crypto_modes"]:
                findings["crypto_modes"].append(match)

    for k in findings["keys"]:
        try:
            val = k.strip('"').strip("'")
            decoded = base64.b64decode(val).decode(errors="ignore")
            if len(decoded) > 6:
                findings["base64_decoded"].append(decoded)
        except Exception:
            pass

    if "AES" in content and ("CBC" in content or "GCM" in content):
        findings["aes_cbc_detected"] = True

    snippets = []
    for ctx in findings["crypto_contexts"]:
        for line in ctx.split("\n"):
            if any(k in line.lower() for k in ["encrypt", "decrypt", "aes", "crypto", "cipher", "decipher"]):
                if len(line.strip()) < 250:
                    snippets.append(line.strip())
    findings["logic_snippets"] = list(dict.fromkeys(snippets))[:20]

    funcs = []
    for match in re.finditer(r'\w+\(.*?\)\s*{', content):
        snip = content[match.start():match.start() + 400]
        if any(k in snip.lower() for k in ["encrypt", "decrypt", "cipher", "crypto", "aes"]):
            funcs.append(snip)
    findings["function_defs"] = list(dict.fromkeys(funcs))[:5]

    deep = []
    for f in findings["function_defs"]:
        for line in f.split("\n"):
            if any(k in line.lower() for k in ["key", "iv", "nonce", "vector", "aes", "utf8", "parse", "crypto", "cipher"]):
                deep.append(line.strip())
    findings["deep_crypto"] = list(dict.fromkeys(deep))[:20]

    import_map = {}
    import_lines = re.findall(
        r'import\s*\{[^}]+\}\s*from\s*["\'][^"\']+["\']',
        content
    )
    for line in import_lines:
        path_match = re.search(r'from\s*["\']([^"\']+)["\']', line)
        if not path_match:
            continue
        path = path_match.group(1)
        block_match = re.search(r'\{([^}]+)\}', line)
        if not block_match:
            continue
        block = block_match.group(1)
        for part in block.split(","):
            part = part.strip()
            if " as " in part:
                original, alias = part.split(" as ")
                import_map[alias.strip()] = path
                import_map[original.strip()] = path
            else:
                import_map[part.strip()] = path

    crypto_calls = re.findall(
        r'(\w+)\.(encryptData|decryptedData|decryptData|encrypt|decrypt)',
        content
    )
    services = set([c[0] for c in crypto_calls])
    for service in services:
        assigns = re.findall(rf'(?:this\.)?{service}\s*=\s*(\w+)', content)
        for var in assigns:
            if var in import_map:
                path = import_map[var]
                match = re.search(r'(chunk-[A-Za-z0-9]+\.js)', path)
                if match:
                    findings["target_imports"].append(match.group(1))

    chunk_scores = {}
    for path in import_map.values():
        if "chunk-" not in path:
            continue
        match = re.search(r'(chunk-[A-Za-z0-9]+\.js)', path)
        if match:
            chunk_scores[match.group(1)] = 1
    ranked = sorted(chunk_scores.items(), key=lambda x: x[1], reverse=True)
    findings["target_imports"] += [c[0] for c in ranked[:3]]

    for ctx in findings["crypto_contexts"]:
        lower = ctx.lower()
        if any(term in lower for term in ["encrypt", "decrypt", "cipher"]):
            if any(term in lower for term in ["fetch", "axios", "xmlhttprequest", "/api/"]):
                findings["flow_map"].append("encrypt/decrypt flow linked to API request")
            if any(term in lower for term in ["localstorage", "sessionstorage", "cookie"]):
                findings["flow_map"].append("encrypt/decrypt flow linked to storage")

    secret_patterns = [
        r'client[_-]?secret\s*[:=]\s*["\'][^"\']+["\']',
        r'token\s*[:=]\s*["\'][^"\']+["\']',
        r'Bearer\s+[A-Za-z0-9\-\._=]+',
        r'(?i)(?:api|access|refresh|client|private|public)[_-]?(?:key|secret|token)\s*[:=]\s*["\'][^"\']+["\']'
    ]
    secrets = []
    for p in secret_patterns:
        secrets.extend(re.findall(p, content, re.I))
    findings["secrets"] = list(dict.fromkeys(secrets))[:20]

    decoded = []
    for s in findings["secrets"]:
        try:
            clean = re.sub(r'[^A-Za-z0-9+/=]', '', s)
            val = base64.b64decode(clean).decode(errors="ignore")
            if ":" in val or len(val) > 10:
                decoded.append(val)
        except Exception:
            pass
    findings["decoded_secrets"] = decoded

    score = 0
    if findings["real_crypto_detected"]:
        score += 2
    if findings["keys"]:
        score += 3
    if findings["ivs"]:
        score += 3
    if findings["decoded_secrets"]:
        score += 2
    if findings["crypto_apis"]:
        score += 1
    if findings["flow_map"]:
        score += 1

    findings["confidence"] = (
        "HIGH" if score >= 7 else
        "MEDIUM" if score >= 4 else
        "LOW"
    )

    return findings
'''

reporter_code = r'''import html


def is_real_crypto_key(k):
    val = k.strip('"').strip("'")

    if len(set(val)) < 8:
        return False

    junk = [
        "aria", "router", "component", "label", "data-", "index", "name",
        "button", "form", "icon", "style", "class"
    ]
    if any(j in val.lower() for j in junk):
        return False

    return (
        "EncryptionKey" in k
        or any(c in val for c in ["~", "<", ">", "$", "%", "&", "+", ";", "_"])
        or (len(val) > 14 and not val.isalpha())
    )


def clean_html(val):
    """Decode HTML entities safely for report output."""
    if not val:
        return ""
    return html.unescape(str(val))


def score_risk(data):
    score = 0
    findings = []

    if data.get("secrets"):
        score += 3
        findings.append("HIGH: Hardcoded secret/token material detected")
    if data.get("keys") and data.get("ivs"):
        score += 4
        findings.append("CRITICAL: Hardcoded key/IV pair detected")
    if data.get("storage"):
        score += 3
        findings.append("HIGH: Sensitive storage usage detected")
    if data.get("api_calls"):
        score += 1
        findings.append("MEDIUM: API request flow detected")
    if data.get("real_crypto_detected"):
        score += 2
        findings.append("MEDIUM: Crypto implementation detected")
    if data.get("decoded_strings"):
        score += 1
        findings.append("LOW: Decoded/obfuscated values detected")

    if score >= 7:
        label = "CRITICAL"
    elif score >= 4:
        label = "HIGH"
    elif score >= 2:
        label = "MEDIUM"
    else:
        label = "LOW"

    return score, label, findings


def generate_report(results):
    report = []
    all_keys = []
    all_ivs = []
    env_keys = []
    global_crypto = False

    report.append("\n========== DETAILED ANALYSIS ==========")

    for file, data in results.items():
        report.append(f"\n==== {file} ====")

        if data.get("real_crypto_detected"):
            global_crypto = True
            report.append("[🔥 REAL CRYPTO IMPLEMENTATION DETECTED]")
            for flow in sorted(set(data.get("crypto_flows", []))):
                report.append(f"  - {flow}")

        if data.get("confidence"):
            report.append(f"\n[📊 Confidence Level: {data['confidence']}]")

        if data.get("env_vars"):
            report.append("\n[🔑 Environment Variables:]")
            for ev in list(set(data["env_vars"]))[:8]:
                report.append(f"  - {ev}")
                if "EncryptionKey" in ev:
                    val = ev.split(":")[-1].strip().strip('"').strip("'")
                    env_keys.append(clean_html(val))

        if data.get("keys"):
            unique_keys = list(set(data["keys"]))
            all_keys.extend(unique_keys)
            report.append("\n[🔐 Crypto Keys:]")
            for k in unique_keys[:5]:
                report.append(f"  - {k}")

        if data.get("ivs"):
            unique_ivs = list(set(data["ivs"]))
            all_ivs.extend(unique_ivs)
            report.append("\n[🧪 IVs:]")
            for i in unique_ivs[:5]:
                report.append(f"  - {i}")

        if data.get("secrets"):
            report.append("\n[🔐 Secrets Found:]")
            for s in list(set(data["secrets"]))[:5]:
                report.append(f"  - {s}")

        if data.get("hardcoded_configs"):
            report.append("\n[🧩 Hardcoded Configs:]")
            for cfg in data["hardcoded_configs"][:5]:
                report.append(f"  - {cfg}")

        if data.get("storage"):
            report.append("\n[💾 Storage Usage:]")
            for item in list(set(data["storage"]))[:5]:
                report.append(f"  - {item}")

        if data.get("api_calls"):
            report.append("\n[🌐 API Calls:]")
            for item in list(set(data["api_calls"]))[:8]:
                report.append(f"  - {item}")

        if data.get("decoded_strings"):
            report.append("\n[🧪 Decoded Strings:]")
            for item in data["decoded_strings"][:5]:
                report.append(f"  - {item}")

        if data.get("logic_snippets"):
            report.append("\n[🧠 Crypto Logic:]")
            for line in data["logic_snippets"][:5]:
                report.append(f"  - {line}")

        if data.get("function_defs"):
            report.append("\n[🔍 Crypto Functions:]")
            for f in data["function_defs"][:2]:
                report.append(f"  - {f[:200]}")

        risk_score, risk_label, risk_findings = score_risk(data)
        report.append(f"\n[⚠️ Risk Level: {risk_label} ({risk_score})]")
        for finding in risk_findings:
            report.append(f"  - {finding}")

    report.append("\n\n========== FINAL GLOBAL SUMMARY ==========")

    all_keys = list(set(all_keys))
    all_ivs = list(set(all_ivs))
    env_keys = list(set(env_keys))

    if global_crypto:
        report.append("[🔥 CRYPTOGRAPHY DETECTED ACROSS APPLICATION]\n")

    report.append("[🔑 Extracted Keys]")
    if env_keys:
        report.append(f"  - {env_keys[0]}")
    else:
        real_keys = [k for k in all_keys if is_real_crypto_key(k)]
        if real_keys:
            for k in real_keys[:3]:
                report.append(f"  - {k}")
        else:
            for k in all_keys[:3]:
                report.append(f"  - {k}")

    if all_ivs:
        report.append("\n[🧪 Extracted IVs]")
        clean_ivs = []
        for iv in all_ivs:
            iv_clean = clean_html(iv)
            if "parse(" in iv_clean.lower():
                continue
            val = iv_clean.split(":")[-1].strip().strip('"').strip("'")
            if len(val) >= 8:
                clean_ivs.append(val)
        for i in sorted(set(clean_ivs))[:3]:
            report.append(f"  - {i}")

    overall_score = 0
    overall_findings = []
    for data in results.values():
        score, label, findings = score_risk(data)
        overall_score += score
        overall_findings.extend(findings)

    if overall_score >= 10 or (all_keys and all_ivs):
        report.append("\n[🔥🔥 CRITICAL VULNERABILITY]")
        report.append("  - Hardcoded cryptographic material and sensitive data are exposed")
    elif overall_score >= 5 or global_crypto:
        report.append("\n[⚠️ MODERATE RISK]")
        report.append("  - Sensitive data and/or crypto flows were identified")
    else:
        report.append("\n[✅ LOW RISK]")
        report.append("  - No significant exposure detected")

    report.append("\n[📌 Structured Findings]")
    for item in list(dict.fromkeys(overall_findings))[:8]:
        report.append(f"  - {item}")

    if all_keys:
        report.append("\n[🧠 Attack Insight]")
        report.append("  - Extracted keys can be used to replicate encryption")
        report.append("  - API requests can be forged externally")
        report.append("  - Tampering and replay attacks possible")

    return "\n".join(report)
'''

Path('core/crypto.py').write_text(crypto_code)
Path('core/reporter.py').write_text(reporter_code)
print('rewritten core/crypto.py and core/reporter.py')
