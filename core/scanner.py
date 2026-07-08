import importlib
import re

from config import CRYPTO_KEYWORDS, SECRET_REGEX
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


def scan_file(file_path):
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
        "score": 0,
    }

    try:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()
    except Exception:
        return results

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
    results["secrets"] = secrets[:25]

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

    results["score"] = score
    return results