import importlib
import re
import tempfile
import os

from config import CRYPTO_KEYWORDS, SECRET_REGEX
from core.ast_analyzer import analyze_ast
from core.crypto import looks_like_url_or_path
from core.decoder import decode_candidate_strings, extract_hidden_values


def _run_additional_analyzers(content, results):
    analyzers = [
        ("secret_analyzer", "secret_analysis"),
        ("crypto_analyzer", "crypto_analysis"),
        ("api_analyzer", "api_inventory"),
        ("auth_analyzer", "auth_summary"),
        ("storage_analyzer", "storage_analysis"),
        ("config_analyzer", "config_summary"),
        ("dependency_analyzer", "technology_stack"),
        ("dom_analyzer", "dom_risks"),
        ("obfuscation_analyzer", "obfuscation_analysis"),
        ("flow_analyzer", "data_flow_summary"),
    ]

    for module_name, result_key in analyzers:
        try:
            module = importlib.import_module(f"analyzers.{module_name}")
            payload = module.analyze(content, previous=results)
            if result_key == "obfuscation_analysis":
                results[result_key] = payload or {}
            elif result_key == "data_flow_summary":
                results[result_key] = payload or []
            else:
                results[result_key] = payload or []
        except Exception:
            results[result_key] = [] if result_key != "obfuscation_analysis" else {}


def scan_file(file_path, content=None):
    results = {
        "secrets": [],
        "crypto": [],
        "endpoints": [],
        "headers": [],
        "secret_context": [],
        "hardcoded_configs": [],
        "decoded_strings": [],
        "storage": [],
        "api_calls": [],
        "dataflow": [],
        "suspicious_calls": [],
        "secret_analysis": [],
        "crypto_analysis": [],
        "api_inventory": [],
        "auth_summary": [],
        "storage_analysis": [],
        "config_summary": [],
        "technology_stack": [],
        "dom_risks": [],
        "obfuscation_analysis": {},
        "data_flow_summary": [],
        "notable_features": [],
        "ast_analysis": {},
        "dependency_scan": [],
        "risk_signals": [],
        "score": 0,
    }

    if content is None:
        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return results

    content = content or ""
    results["file_size"] = len(content)
    results["line_count"] = content.count("\n") + 1
    results["loc_id"] = os.path.basename(file_path) if file_path else "inline.js"

    # =========================================
    # 🔐 SECRET DETECTION (EXTENDED ✅)
    # =========================================
    secret_patterns = list(SECRET_REGEX) + [
        r'(?i)(?:api|access|refresh|client|private|public)[_-]?(?:key|token|secret)\s*[:=]\s*["\'][^"\']+["\']',
        r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']+["\']',
        r'(?i)(?:username|user|email)\s*[:=]\s*["\'][^"\']+["\']',
        r'(?i)(?:authorization|bearer|token)\s*[:=]\s*["\'][^"\']+["\']',
        r'(?i)(?:secret|token|key|password)\s*[:=]\s*[^,;\n]{6,}',
        r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
        r'(?i)(?:aws|github|slack|firebase|google)[^\s"\']{10,}',
    ]

    secrets = []
    for pattern in secret_patterns:
        secrets.extend(re.findall(pattern, content, re.I))

    secrets = list(dict.fromkeys(secrets))
    # Drop endpoint/asset noise while retaining credential-looking strings
    cleaned = []
    for s in secrets:
        text = str(s)
        matched = re.search(r'["\']([^"\']{6,})["\']', text)
        value = matched.group(1) if matched else text
        if looks_like_url_or_path(value) and not re.search(r'(token|key|secret|password|bearer|authorization|api)', text, re.I):
            continue
        cleaned.append(text.strip())
    results["secrets"] = cleaned[:25]

    for s in secrets[:8]:
        try:
            idx = content.find(s)
            context = content[max(0, idx - 120):idx + 180]
            if context.strip():
                results["secret_context"].append(context.strip())
        except Exception:
            pass

    # =========================================
    # 🔐 HARD-CODED CONFIG OBJECTS
    # =========================================
    config_patterns = [
        r'(?i)(?:const|let|var)\s+\w+\s*=\s*\{[^\}]{0,800}(?:api|url|host|endpoint|token|secret|key|password|user|baseUrl)[^\}]{0,300}\}',
        r'(?i)(?:api|endpoint|baseUrl|host|url|token|secret|key|password|username)\s*[:=]\s*["\'][^"\']{4,}["\']'
    ]
    for pattern in config_patterns:
        for match in re.findall(pattern, content, re.I):
            if match not in results["hardcoded_configs"]:
                results["hardcoded_configs"].append(match.strip())

    # =========================================
    # 🔐 DEOBFUSCATION / DECODED VALUES
    # =========================================
    results["decoded_strings"] = decode_candidate_strings(content)
    results["decoded_strings"] += extract_hidden_values(content)
    results["decoded_strings"] = list(dict.fromkeys(results["decoded_strings"]))[:30]

    # =========================================
    # 🔐 CRYPTO KEYWORDS
    # =========================================
    for keyword in CRYPTO_KEYWORDS:
        if keyword.lower() in content.lower():
            results["crypto"].append(keyword)
    results["crypto"] = list(dict.fromkeys(results["crypto"]))

    # =========================================
    # 🌐 ENDPOINT EXTRACTION (EXTENDED)
    # =========================================
    endpoint_patterns = [
        r'/api/[a-zA-Z0-9/_\-]+',
        r'https?://[a-zA-Z0-9\.\-]+/[a-zA-Z0-9/_\-]*',
        r'/(auth|v1|v2|graphql|oauth|login|logout)/[a-zA-Z0-9/_\-]*',
        r'(?:fetch|axios|XMLHttpRequest)\s*\(\s*["\']([^"\']+)["\']',
        r'(?:fetch|axios)\s*\(\s*[^\n]*?["\']([^"\']+)["\']'
    ]
    endpoints = []
    for pattern in endpoint_patterns:
        endpoints.extend(re.findall(pattern, content))
    results["endpoints"] = list(dict.fromkeys(endpoints))[:30]

    # =========================================
    # 🌐 API CALL / REQUEST STRUCTURE
    # =========================================
    api_patterns = [
        r'\b(fetch|axios|XMLHttpRequest)\s*\(',
        r'\b(?:post|get|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
        r'\b(?:url|endpoint|baseURL)\s*[:=]\s*["\']([^"\']+)["\']'
    ]
    for pattern in api_patterns:
        for match in re.findall(pattern, content):
            if isinstance(match, tuple):
                data = match[0] if match else ''
            else:
                data = match
            if data and data not in results["api_calls"]:
                results["api_calls"].append(data)

    # =========================================
    # 🗂️ CLIENT STORAGE ANALYSIS
    # =========================================
    storage_patterns = [
        r'\b(localStorage|sessionStorage)\.(getItem|setItem|removeItem)\s*\(',
        r'\bdocument\.cookie\b',
        r'\bCookies?\.(get|set|remove)\b'
    ]
    for pattern in storage_patterns:
        for match in re.findall(pattern, content, re.I):
            if isinstance(match, tuple):
                text = '.'.join(part for part in match if part)
            else:
                text = match
            if text not in results["storage"]:
                results["storage"].append(text)

    # =========================================
    # 🔄 DATA FLOW CLUES
    # =========================================
    flow_patterns = [
        r'(?:encrypt|decrypt|cipher|decipher)\s*\([^\)]*\)',
        r'(?:localStorage|sessionStorage|document\.cookie|Cookies?)\.(?:setItem|getItem|set|remove)\s*\(',
        r'(?:fetch|axios|XMLHttpRequest)\s*\('
    ]
    for pattern in flow_patterns:
        for match in re.findall(pattern, content):
            if match not in results["dataflow"]:
                results["dataflow"].append(match)

    # =========================================
    # ⚠️ SUSPICIOUS RUNTIME / OBFUSCATION PATTERNS
    # =========================================
    suspicious_patterns = [
        r'\b(?:eval|new\s+Function)\s*\(',
        r'\b(?:atob|btoa|decodeURIComponent|encodeURIComponent)\s*\(',
        r'\b(?:innerHTML|outerHTML|document\.write)\s*=',
        r'\bsetTimeout\s*\(\s*["\']'
    ]
    for pattern in suspicious_patterns:
        for match in re.findall(pattern, content):
            if match not in results["suspicious_calls"]:
                results["suspicious_calls"].append(match.strip())

    # =========================================
    # 🔐 HEADER DETECTION
    # =========================================
    header_patterns = [
        r'Authorization\s*[:=]\s*["\'][^"\']+["\']',
        r'Bearer\s+[A-Za-z0-9\-\._=]+',
        r'X-[A-Za-z0-9\-]+\s*[:=]\s*["\'][^"\']+["\']',
        r'api[-_]?key\s*[:=]\s*["\'][^"\']+["\']',
        r'(?i)(?:cookie|token|auth)\s*[:=]\s*["\'][^"\']+["\']'
    ]
    headers = []
    for pattern in header_patterns:
        headers.extend(re.findall(pattern, content, re.I))
    results["headers"] = list(dict.fromkeys(headers))[:15]

    # =========================================
    # 🌐 HTTP METHOD + TRANSPORT PROFILE
    # =========================================
    transport = []
    if re.search(r'\bfetch\s*\(', content):
        transport.append("fetch")
    if re.search(r'\baxios\b', content):
        transport.append("axios")
    if re.search(r'\bXMLHttpRequest\b', content):
        transport.append("XMLHttpRequest")
    if re.search(r'\bnew\s+WebSocket\b', content):
        transport.append("WebSocket")
    if re.search(r'\bEventSource\s*\(', content):
        transport.append("EventSource")
    if re.search(r'\bserviceWorker\b|navigator\.serviceWorker', content):
        transport.append("ServiceWorker")
    results["transport"] = list(dict.fromkeys(transport))

    methods = []
    for pattern in [
        r'\bfetch\s*\([^)]*?\bmethod\s*:\s*["\'](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["\']',
        r'\baxios\.(get|post|put|patch|delete|head)\s*\(',
        r'\$\s*\.\s*(get|post|put|delete|ajax)\s*\(',
        r'(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+["\'](?:/|[a-zA-Z])',
    ]:
        for match in re.findall(pattern, content, re.I):
            if isinstance(match, tuple):
                match = match[0]
            methods.append(match.upper())
    results["request_methods"] = list(dict.fromkeys(methods))[:20]

    # =========================================
    # 🧠 AST INTELLIGENCE
    # =========================================
    try:
        results["ast_analysis"] = analyze_ast(content, filename=results.get("loc_id", "inline.js"))
    except Exception:
        results["ast_analysis"] = {"available": False, "parse_error": "ast_analyzer_failed"}

    # =========================================
    # 📦 DEPENDENCY / ECOSYSTEM SCAN
    # =========================================
    dependency_scan = []
    dep_entity = {
        "react": {"name": "React", "kind": "framework"},
        "react-dom": {"name": "ReactDOM", "kind": "framework"},
        "angular": {"name": "Angular", "kind": "framework"},
        "vue": {"name": "Vue", "kind": "framework"},
        "next": {"name": "Next.js", "kind": "framework"},
        "nuxt": {"name": "Nuxt", "kind": "framework"},
        "svelte": {"name": "Svelte", "kind": "framework"},
        "ember": {"name": "Ember", "kind": "framework"},
        "jquery": {"name": "jQuery", "kind": "library"},
        "lodash": {"name": "Lodash", "kind": "library"},
        "moment": {"name": "Moment.js", "kind": "library"},
        "dayjs": {"name": "Day.js", "kind": "library"},
        "crypto-js": {"name": "CryptoJS", "kind": "crypto"},
        "forge": {"name": "node-forge", "kind": "crypto"},
        "openpgp": {"name": "OpenPGP", "kind": "crypto"},
        "axios": {"name": "Axios", "kind": "http"},
        "graphql": {"name": "GraphQL", "kind": "api"},
        "firebase": {"name": "Firebase", "kind": "backend"},
        "aws-amplify": {"name": "AWS Amplify", "kind": "backend"},
        "stripe": {"name": "Stripe", "kind": "payments"},
        "razorpay": {"name": "Razorpay", "kind": "payments"},
        "socket.io": {"name": "Socket.IO", "kind": "realtime"},
        "three": {"name": "Three.js", "kind": "media"},
        "monaco": {"name": "Monaco", "kind": "editor"},
    }
    seen_deps = set()
    for source in (results.get("ast_analysis", {}).get("dependencies", []) or []):
        source = (source or "").split("/")[0]
        entity = dep_entity.get(source)
        if entity and source not in seen_deps:
            seen_deps.add(source)
            dependency_scan.append({**entity, "source": source, "evidence": f"import {source}"})
    # Regex fallbacks for common libraries that live in the bundle itself.
    for marker, entity in dep_entity.items():
        if entity["kind"].lower() in ("framework", "library") and marker in content.lower():
            if marker not in seen_deps:
                seen_deps.add(marker)
                dependency_scan.append({**entity, "source": marker, "evidence": "bundle marker"})
    results["dependency_scan"] = dependency_scan[:40]

    _run_additional_analyzers(content, results)

    # =========================================
    # 📊 SCORING SYSTEM (EXTENDED)
    # =========================================
    score = 0
    if results["secrets"]:
        score += 3
    if results["headers"]:
        score += 2
    if results["crypto"]:
        score += 2
    if results["endpoints"]:
        score += 1
    if results["storage"]:
        score += 2
    if results["hardcoded_configs"]:
        score += 1
    if results["decoded_strings"]:
        score += 1
    if results["suspicious_calls"]:
        score += 1

    # =========================================
    # 📌 NOTABLE FEATURES
    # =========================================
    features = []
    if re.search(r'\b(?:localStorage|sessionStorage|document\.cookie)\b', content):
        features.append("client_storage")
    if re.search(r'\bfetch\s*\(|\baxios\b|\bXMLHttpRequest\b', content):
        features.append("http_client")
    if re.search(r'\bnew\s+WebSocket\b', content):
        features.append("websocket")
    if re.search(r'\bEventSource\b', content):
        features.append("server_events")
    if re.search(r'\bindexedDB\b', content):
        features.append("indexeddb")
    if re.search(r'\b(?:serviceWorker|navigator\.serviceWorker)\b', content):
        features.append("service_worker")
    if re.search(r'\bimport\(\s*["\']|require\(\s*["\']', content):
        features.append("dynamic_imports")
    if re.search(r'\b(?:sourceMappingURL|//# sourceMappingURL)\b', content):
        features.append("source_map")
    if re.search(r'\b(?:Chrome|Firefox|Safari|iOS|Android)\b', content):
        features.append("browser_detection")
    if re.search(r'\bpostMessage\s*\(|\bmessage\s*:\s*\w+', content):
        features.append("post_message")
    if re.search(r'__proto__|constructor\s*\.\s*prototype|Object\.assign', content):
        features.append("prototype_touch")
    if re.search(r'\badobe\b|\bair\b|\bactivex\b|\.evaluate\s*\(', content):
        features.append("legacy_plugins")
    results["notable_features"] = features

    # =========================================
    # ⚠️ NORMALIZED RISK SIGNALS
    # =========================================
    risk_signals = []
    if results["secrets"]:
        risk_signals.append({"id": "hardcoded_secret", "severity": "HIGH", "title": "Hardcoded secret material", "evidence": results["secrets"][:3]})
    if results.get("keys") and results.get("ivs"):
        risk_signals.append({"id": "exposed_key_iv_pair", "severity": "CRITICAL", "title": "Static crypto key/IV pair exposed", "evidence": [results["keys"][:2], results["ivs"][:2]]})
    elif results.get("keys"):
        risk_signals.append({"id": "static_crypto_key", "severity": "HIGH", "title": "Static crypto key material", "evidence": results["keys"][:2]})
    if results.get("ivs"):
        risk_signals.append({"id": "static_iv", "severity": "MEDIUM", "title": "Static IV/nonce material", "evidence": results["ivs"][:2]})
    if results.get("real_crypto_detected") or results.get("crypto"):
        crypto_names = list(dict.fromkeys(results.get("crypto", []) + [f.get("signal" if isinstance(f, dict) else "") for f in results.get("crypto_flows", [])]))[:3]
        risk_signals.append({
            "id": "client_side_crypto", "severity": "MEDIUM",
            "title": "Client-side cryptographic flow detected",
            "evidence": crypto_names or ["crypto library/operation present"],
        })
    if results.get("storage"):
        storage_text = " ".join(map(str, results["storage"])).lower()
        sensitive = any(t in storage_text for t in ("token", "auth", "secret", "password", "session"))
        risk_signals.append({
            "id": "sensitive_storage", "severity": "HIGH" if sensitive else "MEDIUM",
            "title": "Client storage used" + (" for sensitive data" if sensitive else ""),
            "evidence": results["storage"][:3],
        })
    if results.get("dom_risks"):
        risk_signals.append({"id": "dom_injection", "severity": "HIGH", "title": "DOM injection & XSS patterns", "evidence": results["dom_risks"][:3]})
    if results.get("suspicious_calls"):
        risk_signals.append({"id": "unsafe_runtime", "severity": "MEDIUM", "title": "Unsafe runtime execution", "evidence": results["suspicious_calls"][:3]})
    if results.get("endpoints") or results.get("api_calls"):
        risk_signals.append({"id": "api_surface", "severity": "LOW", "title": "API surface mapped", "evidence": (results.get("endpoints") or results.get("api_calls"))[:3]})
    if results.get("obfuscation_analysis", {}).get("evidence"):
        risk_signals.append({"id": "obfuscation", "severity": "LOW", "title": "Obfuscation signals", "evidence": results["obfuscation_analysis"].get("evidence", [])[:3]})
    results["risk_signals"] = risk_signals

    results["score"] = score
    return results


def scan_content(content, filename="inline.js"):
    """Analyze JavaScript that did not necessarily come from a file on disk."""
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="ignore")
    if not content or not content.strip():
        return {
            "secrets": [], "crypto": [], "endpoints": [], "headers": [],
            "secret_context": [], "hardcoded_configs": [], "decoded_strings": [],
            "storage": [], "api_calls": [], "dataflow": [], "suspicious_calls": [],
            "secret_analysis": [], "crypto_analysis": [], "api_inventory": [],
            "auth_summary": [], "storage_analysis": [], "config_summary": [],
            "technology_stack": [], "dom_risks": [], "obfuscation_analysis": {},
            "data_flow_summary": [], "notable_features": [], "ast_analysis": {},
            "dependency_scan": [], "risk_signals": [], "score": 0,
        }

    fd, tmp_path = tempfile.mkstemp(suffix=".js", prefix="scriptsentry_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        return scan_file(tmp_path)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass