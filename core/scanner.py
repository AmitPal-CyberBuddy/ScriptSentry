import importlib
import re
import tempfile
import os

from config import CRYPTO_KEYWORDS, SECRET_REGEX
from core.analysis_model import correlate_findings
from core.ast_analyzer import analyze_ast
from core.attack_surface import extract_attack_surface
from core.crypto import looks_like_url_or_path
from core.decoder import decode_candidate_strings, extract_hidden_values
from core.framework_rules import analyze_framework
from core.taint import analyze_taint
from core.source_maps import source_map_reference


def _credible_secret(candidate):
    """Filter obvious fixtures/labels before raising a secret risk signal."""
    text = str(candidate or "")
    lower = text.lower()
    if any(marker in lower for marker in (
        "example", "sample", "placeholder", "changeme", "dummy", "test123",
        "your_", "_here", "xxx", "todo", "fixme", "redact", "lorem",
        "api_token", "token_here", "<your", "replace_", "00000000",
    )):
        return False
    # Template placeholders like ${TOKEN}, <token>, [key] are not secrets.
    if re.search(r"[\$%]?\{[^}]*\}|<[^>]+>|\[\w+\]", text):
        return False
    if "-----begin " in lower or re.search(r"eyj[\w-]+\.[\w-]+\.[\w-]+", text, re.I):
        return True
    match = re.search(r"[\"']([^\"']+)[\"']", text)
    value = match.group(1) if match else text
    if len(value) < 10 or value.lower() in {"password", "secret", "token", "abc123", "abc"}:
        return False
    # Real credentials generally have both character classes or high entropy;
    # natural-language strings should not become high-severity findings.
    classes = sum(bool(re.search(pattern, value)) for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    return len(value) >= 16 and classes >= 2


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
        except Exception as exc:
            results.setdefault("analyzer_errors", []).append({"analyzer": module_name, "error": str(exc)[:240]})
            results[result_key] = [] if result_key != "obfuscation_analysis" else {}


def scan_file(file_path, content=None):
    results = {
        "secrets": [],
        "credible_secrets": [],
        "crypto": [],
        "endpoints": [],
        "headers": [],
        "secret_context": [],
        "hardcoded_configs": [],
        "decoded_strings": [],
        "storage": [],
        "sensitive_storage": False,
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
        "dataflows": [],
        "attack_surface": {},
        "framework_findings": [],
        "findings": [],
        "finding_statuses": {},
        "score": 0,
        "source_map": {"present": False, "url": ""},
        "analysis_warnings": [],
        "analyzer_errors": [],
    }

    if content is None:
        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return results

    content = content or ""
    source_map = source_map_reference(content)
    if source_map:
        results["source_map"] = {"present": True, "url": source_map, "sources": [], "available": False}
        results["notable_features"].append("source_map")
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
    results["credible_secrets"] = [item for item in results["secrets"] if _credible_secret(item)][:25]

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
    results["sensitive_storage"] = bool(re.search(
        r"(?:localStorage|sessionStorage)\s*\.\s*(?:getItem|setItem)\s*\(\s*['\"](?:token|auth|secret|password|session|credential|jwt)[^'\"]*['\"]",
        content, re.I,
    ) or re.search(r"document\.cookie\b", content, re.I))

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
        r'\bsetTimeout\s*\(\s*["\']',
        r'\bsetInterval\s*\(\s*["\']'
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
    if re.search(r'\b(?:navigator\s*\.\s*)?sendBeacon\s*\(', content):
        transport.append("sendBeacon")
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
    except Exception as exc:
        results["ast_analysis"] = {"available": False, "parse_error": "ast_analyzer_failed"}
        results["analyzer_errors"].append({"analyzer": "ast", "error": str(exc)[:240]})
    if results.get("ast_analysis", {}).get("parse_error"):
        results["analysis_warnings"].append("AST parser could not fully parse this dialect; conservative regex fallbacks were used.")

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

    # Explicit `import ... from 'pkg'`, `require('pkg')`, and dynamic `import('pkg')`.
    import_sources = set()
    for pattern in (
        r"""\b(?:from\s+|import\s*\()\s*['"]([a-zA-Z0-9_.@/-]+)['"]""",
        r"""\brequire\s*\(\s*['"]([a-zA-Z0-9_.@/-]+)['"]""",
        r"""\bimport\s+['"]([a-zA-Z0-9_.@/-]+)['"]""",
    ):
        for source in re.findall(pattern, content):
            source = (source or "").split("/")[0]
            if source and source not in seen_deps:
                seen_deps.add(source)
                entity = dep_entity.get(source)
                dependency_scan.append({
                    **({"name": entity["name"], "kind": entity["kind"]} if entity else {"name": source, "kind": "node/npm"}),
                    "source": source,
                    "evidence": f"import/require {source}",
                })
            import_sources.add(source)

    # Regex fallbacks for common libraries that live in the bundle itself.
    for marker, entity in dep_entity.items():
        if entity["kind"].lower() in ("framework", "library", "crypto") and marker in content.lower():
            if marker not in seen_deps:
                seen_deps.add(marker)
                dependency_scan.append({**entity, "source": marker, "evidence": "bundle marker"})
    # Bundle aliases / framework conventions that don't carry the package name in code.
    alias_hints = {
        "react": ("React", ["dangerouslysetinnerhtml", "react.createelement"], "framework"),
        "angular": ("Angular", ["bypasssecuritytrust"], "framework"),
        "vue": ("Vue", ["v-html", "vue.createapp"], "framework"),
        "jquery": ("jQuery", ["jquery(", "$.ajax", "$.get", "$.post", "$(select).html"], "library"),
        "crypto-js": ("CryptoJS", ["cryptojs", "crypto-js"], "crypto"),
        "firebase": ("Firebase", ["firebase.initializeapp", "firebase/app"], "backend"),
    }
    for marker, (name, hints, kind) in alias_hints.items():
        if marker in seen_deps:
            continue
        if any(h in content.lower() for h in hints) or (marker == "jquery" and re.search(r"\$\s*\([^)]*\)\s*\.(html|append|ajax|get|post|on)", content)):
            seen_deps.add(marker)
            dependency_scan.append({"name": name, "kind": kind, "source": marker, "evidence": "bundle alias"})
    results["dependency_scan"] = dependency_scan[:40]

    _run_additional_analyzers(content, results)

    # =========================================
    # 📊 SCORING SYSTEM (EXTENDED)
    # =========================================
    score = 0
    if results.get("credible_secrets"):
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
    if re.search(r'\b(?:navigator\s*\.\s*)?sendBeacon\s*\(', content):
        features.append("beacon")
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
    # Risk signals are coarse, static (or static-heuristic) observations. They
    # never reach the "confirmed" triage state on their own; a finding requires
    # a source-to-sink flow or runtime evidence. Low-impact signals are tagged
    # as observations so the dashboard can present "interesting behavior"
    # separately from "actionable findings".
    risk_signals = []
    def _signal(sig_id, severity, title, evidence, confidence="medium", observation=None):
        sev = str(severity).upper()
        if observation is None:
            observation = sev not in ("CRITICAL", "HIGH")
        risk_signals.append({
            "id": sig_id,
            "severity": sev,
            "title": title,
            "evidence": evidence,
            "confidence": confidence,
            "evidence_type": "static_pattern",
            "observation": bool(observation),
        })

    if results.get("credible_secrets"):
        _signal("hardcoded_secret", "HIGH", "Hardcoded secret candidate", results["credible_secrets"][:3], confidence="medium", observation=False)
    if results.get("keys") and results.get("ivs"):
        _signal("exposed_key_iv_pair", "CRITICAL", "Static crypto key/IV pair exposed", [results["keys"][:2], results["ivs"][:2]], confidence="medium", observation=False)
    elif results.get("keys"):
        _signal("static_crypto_key", "HIGH", "Static crypto key material", results["keys"][:2], confidence="medium", observation=False)
    if results.get("ivs"):
        _signal("static_iv", "MEDIUM", "Static IV/nonce material", results["ivs"][:2], confidence="medium", observation=False)
    if results.get("real_crypto_detected") or results.get("crypto"):
        crypto_names = list(dict.fromkeys(results.get("crypto", []) + [f.get("signal" if isinstance(f, dict) else "") for f in results.get("crypto_flows", [])]))[:3]
        _signal("client_side_crypto", "MEDIUM", "Client-side cryptographic flow detected", crypto_names or ["crypto library/operation present"])
    if results.get("storage"):
        storage_text = " ".join(map(str, results["storage"])).lower()
        sensitive = bool(results.get("sensitive_storage")) or any(t in storage_text for t in ("token", "auth", "secret", "password", "session"))
        _signal(
            "sensitive_storage", "HIGH" if sensitive else "MEDIUM",
            "Client storage used" + (" for sensitive data" if sensitive else ""),
            results["storage"][:3],
        )
    if results.get("dom_risks"):
        # This is a capability observation.  A vulnerability requires a
        # source-to-sink path (added below by the taint pass).
        _signal("dom_injection", "MEDIUM", "DOM/dynamic sink observed", results["dom_risks"][:3], confidence="low", observation=True)
    if results.get("suspicious_calls"):
        _signal("unsafe_runtime", "MEDIUM", "Unsafe runtime execution pattern", results["suspicious_calls"][:3], confidence="low", observation=True)
    if results.get("endpoints") or results.get("api_calls"):
        _signal("api_surface", "LOW", "API surface mapped", (results.get("endpoints") or results.get("api_calls"))[:3], confidence="low", observation=True)
    if results.get("obfuscation_analysis", {}).get("evidence"):
        _signal("obfuscation", "LOW", "Obfuscation signals", results["obfuscation_analysis"].get("evidence", [])[:3], confidence="low", observation=True)
    results["risk_signals"] = risk_signals

    # =========================================
    # 🔁 SOURCE→SINK DATA FLOWS & FRAMEWORK RULES
    # =========================================
    filename = results.get("loc_id", "inline.js")
    try:
        results["dataflows"] = analyze_taint(content, filename=filename)
    except Exception:
        results["dataflows"] = []
    try:
        results["framework_findings"] = analyze_framework(content, filename=filename)
    except Exception:
        results["framework_findings"] = []

    # =========================================
    # 🎯 ATTACK SURFACE
    # =========================================
    try:
        results["attack_surface"] = extract_attack_surface(content, filename=filename)
    except Exception:
        results["attack_surface"] = {}

    # Unify findings (taint > framework > coarse risk signals) for UI/reports.
    # Correlation is centralised in core.analysis_model so every consumer receives
    # the same evidence-based, de-duplicated view.
    results["findings"] = correlate_findings(
        results["dataflows"],
        results["framework_findings"],
        results["risk_signals"],
        filename=filename,
    )[:80]
    results["finding_statuses"] = {}

    results["score"] = score
    return results


def scan_content(content, filename="inline.js"):
    """Analyze JavaScript that did not necessarily come from a file on disk."""
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="ignore")
    if not content or not content.strip():
        return {
            "secrets": [], "credible_secrets": [], "crypto": [], "endpoints": [], "headers": [],
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