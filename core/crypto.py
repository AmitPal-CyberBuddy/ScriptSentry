import re
import base64
import os


# =========================================
# 🧠 SMART FILTER (BALANCED VERSION ✅)
# =========================================
def is_valid_key(value):
    val = value.strip('"').strip("'")

    if len(val) < 12 or len(val) > 64:
        return False

    lower = val.lower()

    # ❌ Reject obvious false positives and UI/config labels
    blacklist = [
        "arrow", "enter", "ctrl", "shift",
        "draw", "render", "chart", "axis",
        "tooltip", "legend", "monaco",
        "encrypted", "header", "http-equiv",
        "unidentified", "spinner-bar-", "statekey",
        "datakey", "content-type", "responseurl",

        # UI / Angular / CSS junk filters
        "mat", "mdc", "ng", "p-", "btn",
        "form", "label", "component", "icon",
        "style", "class"
    ]

    if any(b in lower for b in blacklist):
        return False

    # Reject plain words / generic labels that are not crypto-like
    if re.fullmatch(r'[a-z][a-z0-9_-]{3,}', lower):
        return False

    # Reject low entropy junk
    if len(set(val)) < 5:
        return False

    # Require either special crypto-like characters or high entropy
    if not any(ch in val for ch in ['~', '<', '>', '$', '%', '&', '+', ';', '_', '/', '=', '?', '@', '#']):
        if not re.fullmatch(r'[A-Za-z0-9+/]{16,}={0,2}', val) and len(set(val)) < 10:
            return False

    return True


def is_valid_iv(value):
    val = value.strip('"').strip("'")

    if len(val) < 8 or len(val) > 64:
        return False

    lower = val.lower()

    if any(b in lower for b in ["http-equiv", "unidentified", "spinner-bar-", "content-type", "statekey", "datakey"]):
        return False

    if re.fullmatch(r'[a-z][a-z0-9_-]{3,}', lower):
        return False

    if len(set(val)) < 5:
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
        "confidence": "LOW"
    }

    # =========================================
    # 🔥 CRYPTO DETECTION
    # =========================================
    crypto_patterns = [
        r'\w*encrypt\w*\(',
        r'\w*decrypt\w*\(',
        r'CryptoJS',
        r'\bAES\b'
    ]

    crypto_locations = []

    for pattern in crypto_patterns:
        for match in re.finditer(pattern, content):
            findings["real_crypto_detected"] = True
            crypto_locations.append(match.start())
            findings["crypto_flows"].append(match.group())

            ctx = content[max(0, match.start()-200):match.start()+200]
            findings["crypto_contexts"].append(ctx)

    # =========================================
    # 🔑 KEY DETECTION (HYBRID ✅)
    # =========================================
    candidates = re.findall(r'[\'"][A-Za-z0-9+/=_\-]{12,}[\'"]', content)

    for c in candidates:
        pos = content.find(c)

        if (
            any(abs(pos - loc) < 400 for loc in crypto_locations)
            or "EncryptionKey" in content
        ):
            if is_valid_key(c):
                findings["keys"].append(c)

    # =========================================
    # 🧪 IV DETECTION (EXPANDED ✅)
    # =========================================
    iv_patterns = [
        r'EncryptionIV\s*[:=]\s*[\'\"][^\'\"]+[\'\"]',
        r'initialVector\s*[:=]\s*[\'\"][^\'\"]+[\'\"]',
        r'nonce\s*[:=]\s*[\'\"][^\'\"]+[\'\"]',
        r'Utf8\.parse\([^)]*iv[^)]*\)'
    ]

    for p in iv_patterns:
        findings["ivs"].extend(re.findall(p, content, re.I))

    # Filter out generic config labels such as "http-equiv"
    findings["ivs"] = [iv for iv in findings["ivs"] if is_valid_iv(iv)]

    # =========================================
    # 🔑 ENV VARS (VERY IMPORTANT ✅)
    # =========================================
    env = re.findall(
        r'((EncryptionKey|EncryptionIV|secretKey|privateKey|publicKey|apiKey|accessKey|tokenKey|sessionKey)\s*[:=]\s*["\'][^"\']+["\'])',
        content,
        re.I
    )
    findings["env_vars"] = [e[0] for e in env]

    # ✅ STRICT BOOST: Extract actual values only for real crypto fields
    for e in findings["env_vars"]:
        val_match = re.search(r'["\']([^"\']+)["\']', e)
        if val_match:
            val = val_match.group(1)
            if is_valid_key(val):
                findings["keys"].append(f'"{val}"')

    # =========================================
    # ✅ NEW: PRIORITY KEY SORTING (CRITICAL FIX)
    # =========================================
    priority_keys = []

    for k in findings["keys"]:

        val = k.strip('"').strip("'")

        # ✅ highest priority
        if "EncryptionKey" in content or "key" in val.lower():
            priority_keys.insert(0, k)

        # ✅ medium priority (high entropy)
        elif len(set(val)) > 10 and len(val) > 16:
            priority_keys.insert(len(priority_keys)//2, k)

        # ✅ low priority
        else:
            priority_keys.append(k)

    # ✅ deduplicate and trim
    findings["keys"] = list(dict.fromkeys(priority_keys))[:10]

    # =========================================
    # ✅ NEW: FALLBACK (cross-file key issue fix)
    # =========================================
    if findings["real_crypto_detected"] and not findings["keys"]:

        fallback = re.findall(r'[\'"][A-Za-z0-9+/=_\-]{16,}[\'"]', content)

        for f in fallback:
            if is_valid_key(f):
                findings["keys"].append(f)

    # =========================================
    # 🔄 BASE64 DECODE
    # =========================================
    for k in findings["keys"]:
        try:
            val = k.strip('"').strip("'")
            decoded = base64.b64decode(val).decode(errors="ignore")

            if len(decoded) > 6:
                findings["base64_decoded"].append(decoded)
        except:
            pass

    # =========================================
    # 🔐 AES CHECK
    # =========================================
    if "AES" in content and "CBC" in content:
        findings["aes_cbc_detected"] = True

    # =========================================
    # 🧠 LOGIC SNIPPETS
    # =========================================
    snippets = []

    for ctx in findings["crypto_contexts"]:
        for line in ctx.split("\n"):
            if any(k in line.lower() for k in ["encrypt", "decrypt", "aes"]):
                if len(line.strip()) < 200:
                    snippets.append(line.strip())

    findings["logic_snippets"] = list(set(snippets))[:20]

    # =========================================
    # 🔍 FUNCTION DEFINITIONS
    # =========================================
    funcs = []

    for match in re.finditer(r'\w+\(.*?\)\s*{', content):
        snip = content[match.start():match.start()+400]

        if any(k in snip.lower() for k in ["encrypt", "decrypt"]):
            funcs.append(snip)

    findings["function_defs"] = list(set(funcs))[:5]

    # =========================================
    # 🧬 DEEP CRYPTO
    # =========================================
    deep = []

    for f in findings["function_defs"]:
        for line in f.split("\n"):
            if any(k in line.lower() for k in ["key", "iv", "aes", "utf8", "parse"]):
                deep.append(line.strip())

    findings["deep_crypto"] = list(set(deep))[:20]

    # =========================================
    # 🔗 IMPORT MAP (UNCHANGED ✅)
    # =========================================
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

    # =========================================
    # 🔥 SERVICE TRACE
    # =========================================
    crypto_calls = re.findall(
        r'(\w+)\.(encryptData|decryptedData|decryptData)',
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

    # =========================================
    # 🔥 SMART CHUNK SCORING (UNCHANGED ✅)
    # =========================================
    chunk_scores = {}

    for path in import_map.values():

        if "chunk-" not in path:
            continue

        match = re.search(r'(chunk-[A-Za-z0-9]+\.js)', path)
        if not match:
            continue

        chunk = match.group(1)
        chunk_scores[chunk] = 1

    ranked = sorted(chunk_scores.items(), key=lambda x: x[1], reverse=True)
    findings["target_imports"] += [c[0] for c in ranked[:3]]

    # =========================================
    # 🔐 SECRET DETECTION (UNCHANGED ✅)
    # =========================================
    secret_patterns = [
        r'client[_-]?secret\s*[:=]\s*["\'][^"\']+["\']',
        r'token\s*[:=]\s*["\'][^"\']+["\']',
        r'Bearer\s+[A-Za-z0-9\-\._=]+'
    ]

    secrets = []
    for p in secret_patterns:
        secrets.extend(re.findall(p, content, re.I))

    findings["secrets"] = list(set(secrets))[:15]

    # =========================================
    # 🔄 SECRET DECODE
    # =========================================
    decoded = []

    for s in findings["secrets"]:
        try:
            clean = re.sub(r'[^A-Za-z0-9+/=]', '', s)
            val = base64.b64decode(clean).decode(errors="ignore")

            if ":" in val or len(val) > 10:
                decoded.append(val)
        except:
            pass

    findings["decoded_secrets"] = decoded

    # =========================================
    # 📊 CONFIDENCE
    # =========================================
    score = 0

    if findings["real_crypto_detected"]:
        score += 2
    if findings["keys"]:
        score += 3
    if findings["ivs"]:
        score += 3
    if findings["decoded_secrets"]:
        score += 2

    findings["confidence"] = (
        "HIGH" if score >= 7 else
        "MEDIUM" if score >= 4 else
        "LOW"
    )

    return findings
