import re
import base64
import os
from urllib.parse import urlparse


# =========================================
# 🧠 SMART FILTER (BALANCED VERSION ✅)
# =========================================
def is_valid_key(value):
    val = value.strip('"').strip("'")

    if len(val) < 12 or len(val) > 128:
        return False
    if re.search(r'\s', val):
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

    if any(b in lower for b in blacklist if len(b) >= 4):
        return False
    if re.search(r'\b(?:mat|mdc|ng|btn|p-)\b', lower):
        return False

    # Reject URLs, paths, endpoints, and static asset references
    if re.search(r'(^|\W)(https?|wss|ws|ftp)://', lower):
        return False
    if re.search(r'(^|/)(api|v[0-9]+|auth|login|logout|graphql|assets|static|js|css|chunk)', lower):
        return False
    if lower.startswith(("/", "./", "../", "www.", "localhost", "127.")):
        return False
    if re.search(r'\.(js|mjs|css|png|jpg|jpeg|gif|svg|ico|json|html|map)(\b|$)', lower):
        return False
    if lower.count("/") >= 1 and (lower.startswith("/") or "/api/" in lower):
        return False

    # Reject generic English-ish labels that are not crypto-like
    generic_labels = {
        "defaultvalue", "placeholder", "originaldata", "encrypteddata",
        "decodedvalue", "data", "example", "sample", "username",
        "password123", "network", "browser", "element", "children",
        "document", "window", "global", "response", "request",
    }
    if lower in generic_labels:
        return False
    if re.fullmatch(r'[a-z]{3,}', lower) and len(set(val)) < 8 and len(val) < 24:
        return False

    # Reject low entropy junk
    if len(set(val)) < 5:
        return False

    # Require either special crypto-like characters or high entropy
    if not any(ch in val for ch in ['~', '<', '>', '$', '%', '&', '+', ';', '_', '/', '=', '?', '@', '#']):
        if not re.fullmatch(r'[A-Za-z0-9+/]{16,}={0,2}', val) and len(set(val)) < 10:
            return False

    return True


def looks_like_url_or_path(value):
    """Public filter used to drop endpoint/asset spam from secret-like findings."""
    text = str(value).strip().strip('"').strip("'").lower()
    if not text:
        return True
    if re.search(r'https?://|wss?://', text):
        return True
    if text.startswith(("./", "../", "/", "//", "www.", "localhost", "127.")):
        return True
    if re.search(r'\.(?:js|mjs|css|png|jpg|jpeg|gif|svg|ico|json|html|map)\b', text):
        return True
    if re.match(r'^(?:api|v[0-9]+|auth|login|logout|graphql|assets|static|js|css)/', text):
        return True
    return False


def is_valid_iv(value):
    val = value.strip('"').strip("'")

    if len(val) < 8 or len(val) > 64:
        return False

    lower = val.lower()

    if any(b in lower for b in ["http-equiv", "unidentified", "spinner-bar-", "content-type", "statekey", "datakey"]):
        return False

    if lower in {"assigned", "content", "example", "sample", "default", "placeholder"}:
        return False
    if re.fullmatch(r'[a-z]{3,}', lower) and len(set(val)) < 6 and len(val) < 20:
        return False

    if len(set(val)) < 5:
        return False

    return True


# =========================================
# 🔐 CRYPTO EXTRACTION ENGINE
# =========================================
def extract_crypto_material(content, filename="inline.js"):

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
        (r'\b(?:CryptoJS|forge|sjcl|openPGP|node-forge)\b', "library"),
        (r'\b(?:encrypt|decrypt|cipher|decipher|createCipheriv|createDecipheriv|createCipher|createDecipher|subtask)\w*\(', "operation"),
        (r'\b(?:AES|DES|RC4|ChaCha20|Rabbit|TripleDES)\b', "algorithm"),
        (r'\b(?:CBC|ECB|GCM|CTR|CFB|OFB|HMAC|SHA-?1|SHA-?256|SHA-?512|PBKDF2|scrypt|bcrypt)\b', "mode"),
        (r'\b(?:generateKey|deriveKey|importKey|encryptData|decryptData|encryptString|decryptString)\s*\(', "webcrypto"),
    ]

    crypto_locations = []
    seen_flows = set()

    for pattern, category in crypto_patterns:
        for match in re.finditer(pattern, content, re.I):
            flow = match.group()
            flow_key = (flow.lower(), category)
            if flow_key in seen_flows:
                continue
            seen_flows.add(flow_key)
            findings["real_crypto_detected"] = True
            crypto_locations.append(match.start())
            findings["crypto_flows"].append({"signal": flow, "category": category, "filename": filename})

            ctx = content[max(0, match.start()-220):match.start()+220]
            findings["crypto_contexts"].append(ctx)

    # =========================================
    # 🔑 KEY DETECTION (HYBRID ✅)
    # =========================================
    candidates = re.findall(r'[\'"]([^"\'\\]{12,})[\'"]', content)

    for c in candidates:
        pos = content.find(c)
        val = c.strip('"').strip("'")
        if looks_like_url_or_path(val):
            continue

        if (
            any(abs(pos - loc) < 400 for loc in crypto_locations)
            or "EncryptionKey" in content
        ):
            if is_valid_key(val):
                findings["keys"].append({"value": val, "context": "crypto", "source": filename})

    # =========================================
    # 🧪 IV DETECTION (EXPANDED ✅)
    # =========================================
    iv_patterns = [
        (r'(?:EncryptionIV|initialVector|iv)\s*[:=]\s*[\'"]([^\'"]+)[\'"]', "assignment"),
        (r'Utf8\.parse\(\s*[\'"]([^\'"]+)[\'"]\s*\)', "parse"),
        (r'iv\s*:\s*[\'"]([^\'"]+)[\'"]', "object"),
    ]

    iv_seen = set()
    for p, iv_kind in iv_patterns:
        for match in re.finditer(p, content, re.I):
            val = match.group(1)
            if not val or looks_like_url_or_path(val) or not is_valid_iv(val):
                continue
            if val in iv_seen:
                continue
            iv_seen.add(val)
            findings["ivs"].append({"value": val, "kind": iv_kind, "source": filename})

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
        field_name = e.split(":")[0].split("=")[0].strip().lower()
        val_match = re.search(r'["\']([^"\']+)["\']', e)
        if val_match:
            val = val_match.group(1)
            if "iv" in field_name and is_valid_iv(val) and not looks_like_url_or_path(val):
                if val not in {x.get("value") for x in findings["ivs"]}:
                    findings["ivs"].append({"value": val, "kind": "env", "source": filename})
            elif is_valid_key(val) and not looks_like_url_or_path(val):
                findings["keys"].append({"value": val, "context": "env", "source": filename})

    # =========================================
    # ✅ NEW: PRIORITY KEY SORTING (CRITICAL FIX)
    # =========================================
    priority_keys = []
    seen_keys = set()

    keys = [k["value"] if isinstance(k, dict) else k for k in findings["keys"]]
    for k in keys:
        val = k.strip('"').strip("'")
        if val in seen_keys:
            continue
        seen_keys.add(val)

        # ✅ highest priority
        if "EncryptionKey" in content or "key" in val.lower():
            priority_keys.insert(0, {"value": val, "context": "crypto", "source": filename})

        # ✅ medium priority (high entropy)
        elif len(set(val)) > 10 and len(val) > 16:
            priority_keys.insert(len(priority_keys)//2, {"value": val, "context": "crypto", "source": filename})

        # ✅ low priority
        else:
            priority_keys.append({"value": val, "context": "crypto", "source": filename})

    # ✅ deduplicate and trim
    findings["keys"] = priority_keys[:12]

    # =========================================
    # ✅ NEW: FALLBACK (cross-file key issue fix)
    # =========================================
    if findings["real_crypto_detected"] and not findings["keys"]:

        fallback = re.findall(r'[\'"]([^"\'\\]{16,})[\'"]', content)

        for f in fallback:
            val = f.strip('"').strip("'")
            if is_valid_key(val) and not looks_like_url_or_path(val):
                findings["keys"].append({"value": val, "context": "fallback", "source": filename})

    # =========================================
    # 🔄 BASE64 DECODE
    # =========================================
    for k in findings["keys"]:
        try:
            val = k["value"] if isinstance(k, dict) else k.strip('"').strip("'")
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
