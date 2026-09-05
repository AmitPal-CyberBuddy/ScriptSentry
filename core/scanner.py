import importlib
import math
import re
import tempfile
import os

from config import SECRET_REGEX
from core.analysis_model import correlate_findings
from core.ast_analyzer import analyze_ast
from core.attack_surface import extract_attack_surface
from core.crypto import looks_like_url_or_path
from core.js_patterns import crypto_markers_in
from core.decoder import decode_candidate_strings, extract_hidden_values
from core.framework_rules import analyze_framework
from core.taint import analyze_taint
from core.source_maps import source_map_reference


class ScanCancelled(Exception):
    """Raised inside an analysis pass when the user cancels the scan.

    A single 2 MB minified bundle can take many seconds to analyze, so the
    cancel flag is checked *between* analysis passes as well as between files.
    Without that, the cancel button appears dead while one worker chews through
    one big file.
    """


# Below this size a document analyzes in well under a second on any plausible
# machine; heartbeat events would only add noise to the activity log. Large
# production bundles are the ones that can occupy a worker for minutes without
# finishing, and those are exactly the ones that must keep reporting.
HEARTBEAT_MIN_CHARS = 150_000


def _raise_if_cancelled(cancel_check):
    if cancel_check and cancel_check():
        raise ScanCancelled("Scan cancelled by user")


# Keys that are *designed* to ship inside a browser bundle.  They identify a
# project rather than authenticate it (they are restricted by referrer/domain),
# so reporting them as HIGH hardcoded secrets is a guaranteed false positive.
# Endpoints where the URL itself is the secret (anyone holding it can post).
CREDENTIAL_URL_RE = re.compile(
    r"hooks\.slack\.com|discord(?:app)?\.com/api/webhooks|hooks\.zapier\.com"
    r"|maker\.ifttt\.com|oauth/token|/webhooks?/",
    re.I,
)

PUBLIC_CLIENT_KEY_RE = re.compile(
    r"(?:AIza[0-9A-Za-z_\-]{35}"          # Google / Firebase browser API key
    r"|(?:pk|rk)_(?:live|test)_[0-9A-Za-z]{8,}"   # Stripe publishable key
    r"|GOCSPX-[0-9A-Za-z_\-]+"             # Google OAuth client secret (public)
    r"|1\/[0-9A-Za-z_\-]{20,})"           # legacy Google client id
)


def _secret_value(text):
    """Return the assigned value from a matched secret expression.

    A match like ``apiKey: "AIza..."`` yields ``AIza...`` so overlapping
    patterns can be deduplicated on what was actually assigned rather than on
    the exact slice of text each regex captured.
    """
    match = re.search(r"""['"]([^'"]{4,})['"]""", str(text or ""))
    return match.group(1) if match else str(text or "").strip()


def _shannon_entropy(value):
    """Bits of entropy per character -- catches short but random API keys."""
    text = str(value or "")
    if not text:
        return 0.0
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    length = float(len(text))
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _secret_context(content, secret, before=120, after=180):
    """Code surrounding ``secret``, or "" when it is not literally present.

    The previous version sliced with the raw result of ``content.find(s)``.
    When the value had been normalized, reconstructed or deduplicated the
    lookup returned -1 and the slice became ``content[0:180]`` -- the top of
    the file, quoted back as the "context" of the secret.
    """
    if not secret:
        return ""
    candidates = [secret]
    # Entries look like `apiKey = "abc"`; the quoted value survives
    # minification and whitespace differences that the full match does not.
    for value in re.findall(r"""['"]([^'"]{4,})['"]""", secret):
        candidates.append(value)
    for candidate in candidates:
        idx = content.find(candidate)
        if idx >= 0:
            return content[max(0, idx - before):idx + after].strip()
    return ""


def _credible_secret(candidate):
    """Filter obvious fixtures/labels before raising a secret risk signal."""
    text = str(candidate or "")
    lower = text.lower()

    # Public-by-design client identifiers are inventory, not credentials.
    if PUBLIC_CLIENT_KEY_RE.search(_secret_value(text)):
        return False
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
    # Real credentials generally have mixed character classes or high entropy;
    # natural-language strings should not become high-severity findings.  The
    # old rule required >= 16 characters, which silently dropped perfectly real
    # 12-character API keys.
    classes = sum(bool(re.search(pattern, value)) for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    # A webhook URL *is* the credential, so keep those while still discarding
    # ordinary endpoints and asset paths.
    if (looks_like_url_or_path(value)
            and not CREDENTIAL_URL_RE.search(value)
            and not re.search(r"(token|key|secret|password|bearer|sig|signature)", value, re.I)):
        return False
    if len(value) >= 20 and classes >= 2:
        return True
    if len(value) >= 12 and classes >= 3:
        return True
    return len(value) >= 10 and _shannon_entropy(value) >= 3.2 and classes >= 2


def _run_additional_analyzers(content, results, cancel_check=None, progress_heartbeat=None):
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

    for index, (module_name, result_key) in enumerate(analyzers, start=1):
        _raise_if_cancelled(cancel_check)
        if progress_heartbeat is not None:
            progress_heartbeat(f"analyzer {index}/{len(analyzers)} ({module_name})")
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


def scan_file(file_path, content=None, cancel_check=None, progress_heartbeat=None):
    """Run every analysis pass over one document.

    ``progress_heartbeat``, when given, is called with a short pass name at
    each heavy checkpoint *for large documents only* (see
    ``HEARTBEAT_MIN_CHARS``). A 2 MB minified bundle can hold one worker for
    minutes; without these in-flight events the dashboard cannot tell
    "working on a big bundle" from "gone".
    """
    results = {
        "secrets": [],
        "credible_secrets": [],
        "public_client_keys": [],
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

    _raise_if_cancelled(cancel_check)
    content = content or ""

    def _beat(detail):
        if progress_heartbeat is not None and len(content) >= HEARTBEAT_MIN_CHARS:
            try:
                progress_heartbeat(detail)
            except Exception:
                pass

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
        r'(?i)(?:authorization|bearer|token)\s*[:=]\s*["\'][^"\']+["\']',
        r'(?i)(?:secret|token|key|password)\s*[:=]\s*[^,;\n]{6,}',
        r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
        # Provider-scoped credentials only.  The previous rule matched any long
        # word merely *containing* a vendor name, so `githubOrgName = "acme-…"`
        # and `googleAnalyticsLoaded` were reported as secrets.
        r'(?i)\b(?:aws|amazon|github|gitlab|slack|firebase|google|gcp|azure|stripe|twilio|sendgrid|mailgun)[_-]?'
        r'(?:secret|access[_-]?key|api[_-]?key|token|webhook|key)\b\s*[:=]\s*["\']([^"\']{8,})["\']',
        # Credentials recognised by *value shape*, so a badly named variable
        # (`const sk = "sk_live_..."`) is still caught.
        r'(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}',
        r'\bgh[pousr]_[A-Za-z0-9]{20,}',
        r'\bxox[baprs]-[A-Za-z0-9-]{10,}',
        r'\bAKIA[0-9A-Z]{16}\b',
        r'https://hooks\.slack\.com/services/[A-Za-z0-9/_]+',
        r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+',
    ]

    _beat("secret patterns")
    raw_secrets = []
    for pattern in secret_patterns:
        # A regex over a 2 MB minified bundle is fast, but a dozen of them in
        # a row is not free; check the flag every pass so cancel interrupts a
        # single huge file, not only the gaps between files.
        _raise_if_cancelled(cancel_check)
        raw_secrets.extend(re.findall(pattern, content, re.I))

    # Deduplicate on the *assigned value* rather than the matched text: three
    # overlapping patterns can match different slices of one assignment
    # (`apiKey: "x`, `apiKey: "x"`, `Key: "x"`), which used to inflate the
    # secrets panel, the per-file score and the overall risk score.
    by_value = {}
    for candidate in raw_secrets:
        text = str(candidate).strip()
        if not text:
            continue
        value = _secret_value(text)
        # Two patterns capture the same value with and without its closing
        # quote, so key on the longest credential-shaped token inside it.
        tokens = re.findall(r"[A-Za-z0-9+/=_\-]{8,}", value)
        key = re.sub(r"\s+", "", (max(tokens, key=len) if tokens else value).lower())
        if not key:
            continue
        previous = by_value.get(key)
        if previous is None or len(text) > len(previous):
            by_value[key] = text
    secrets = list(by_value.values())

    # Drop endpoint/asset noise while retaining credential-looking strings, and
    # split out keys that are meant to be public.
    cleaned = []
    public_keys = []
    for s in secrets:
        text = str(s)
        value = _secret_value(text)
        if PUBLIC_CLIENT_KEY_RE.search(value):
            public_keys.append(text.strip())
            continue
        if looks_like_url_or_path(value) and not re.search(r'(token|key|secret|password|bearer|authorization|api|webhook|hooks\.)', text, re.I):
            continue
        cleaned.append(text.strip())
    results["secrets"] = cleaned[:25]
    results["credible_secrets"] = [item for item in results["secrets"] if _credible_secret(item)][:25]
    results["public_client_keys"] = list(dict.fromkeys(public_keys))[:10]

    for s in secrets[:8]:
        context = _secret_context(content, s)
        if context:
            results["secret_context"].append(context)

    _beat("hardcoded config scan")

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
    _raise_if_cancelled(cancel_check)
    _beat("decoder pass")
    results["decoded_strings"] = decode_candidate_strings(content)
    results["decoded_strings"] += extract_hidden_values(content)
    results["decoded_strings"] = list(dict.fromkeys(results["decoded_strings"]))[:30]

    # =========================================
    # 🔐 CRYPTO KEYWORDS
    # =========================================
    # Word-bounded, shared catalogue (core.js_patterns).  The old loop was a
    # plain substring test over config.CRYPTO_KEYWORDS, so "DES" matched
    # "desktop", "Hex" matched "hexagon" and every design token or
    # desktop-theme helper became a crypto finding.
    _beat("crypto markers")
    for marker in crypto_markers_in(content):
        if marker["name"] not in results["crypto"]:
            results["crypto"].append(marker["name"])
    results["crypto"] = list(dict.fromkeys(results["crypto"]))

    # =========================================
    # 🌐 ENDPOINT EXTRACTION (EXTENDED)
    # =========================================
    _beat("endpoint extraction")
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
    # "Sensitive" used to mean "mentions document.cookie anywhere" (or, via the
    # check below, "uses sessionStorage" -- 'session' is a substring of it).
    # Both flagged ordinary analytics helpers as HIGH.  Sensitivity now
    # requires a sensitive *key name* or a sensitive value written to a cookie.
    results["sensitive_storage"] = bool(
        re.search(
            r"(?:localStorage|sessionStorage)\s*\.\s*(?:getItem|setItem)\s*\(\s*['\"]"
            r"(?:token|auth|secret|password|session|credential|jwt)[^'\"]*['\"]",
            content, re.I,
        )
        or re.search(
            r"document\s*\.\s*cookie\s*(?:\+?=(?!=))[^;]{0,160}"
            r"(?:token|auth|secret|password|session|credential|jwt)",
            content, re.I,
        )
    )

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
    _raise_if_cancelled(cancel_check)
    _beat("AST parse")
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
    _beat("dependency scan")
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

    _raise_if_cancelled(cancel_check)
    _run_additional_analyzers(content, results, cancel_check=cancel_check,
                              progress_heartbeat=_beat)

    # =========================================
    # 📊 SCORING SYSTEM (EXTENDED)
    # =========================================
    _raise_if_cancelled(cancel_check)
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
        # storage_text holds API names only ("localStorage.setItem"), so
        # substring tests against it were meaningless -- "session" matched
        # "sessionStorage" and marked every cached UI state as sensitive.
        sensitive = bool(results.get("sensitive_storage"))
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
    _raise_if_cancelled(cancel_check)
    filename = results.get("loc_id", "inline.js")
    _beat("taint flows")
    try:
        results["dataflows"] = analyze_taint(content, filename=filename)
    except Exception:
        results["dataflows"] = []
    _beat("framework rules")
    try:
        results["framework_findings"] = analyze_framework(content, filename=filename)
    except Exception:
        results["framework_findings"] = []

    # =========================================
    # 🎯 ATTACK SURFACE
    # =========================================
    _raise_if_cancelled(cancel_check)
    _beat("attack surface")
    try:
        results["attack_surface"] = extract_attack_surface(content, filename=filename)
    except Exception:
        results["attack_surface"] = {}

    # Unify findings (taint > framework > coarse risk signals) for UI/reports.
    # Correlation is centralised in core.analysis_model so every consumer receives
    # the same evidence-based, de-duplicated view.
    _raise_if_cancelled(cancel_check)
    _beat("correlating findings")
    results["findings"] = correlate_findings(
        results["dataflows"],
        results["framework_findings"],
        results["risk_signals"],
        filename=filename,
    )[:80]
    results["finding_statuses"] = {}

    results["score"] = score
    return results


def scan_content(content, filename="inline.js", cancel_check=None):
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
        return scan_file(tmp_path, cancel_check=cancel_check)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass