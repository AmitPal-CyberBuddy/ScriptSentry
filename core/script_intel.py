"""Script-level intelligence: inventory, behavior profiles and risk scoring.

ScriptSentry's job is not only to find vulnerabilities --- it should answer:

* What scripts are running?
* Are they first-party, third-party, inline or dynamically loaded?
* What capabilities / sensitive browser APIs do they use?
* What data can they read, and where can that data go?

This module turns the existing static per-file analysis plus the optional
runtime evidence block into a consistent script inventory and behavior profile.
It deliberately stays script-focused: it does not replace per-finding severity,
it adds a script-centric view for triage and prioritization.
"""
import hashlib
import json
import os
import re
from urllib.parse import urlparse


def _host(url):
    try:
        return (urlparse(str(url or "")).hostname or "").lower()
    except Exception:
        return ""


def _is_url(value):
    try:
        return bool(urlparse(str(value or "")).scheme)
    except Exception:
        return False


def _basename(url):
    try:
        path = urlparse(str(url or "")).path
        return os.path.basename(path.rstrip("/")) or ""
    except Exception:
        return os.path.basename(str(url or ""))


def _canonical(url):
    return str(url or "").split("#", 1)[0].split("?", 1)[0].rstrip("/")


def _read_hash(path):
    if not path:
        return ""
    try:
        if os.path.isfile(path):
            digest = hashlib.sha256()
            with open(path, "rb", buffering=1 << 20) as handle:
                for chunk in iter(lambda: handle.read(1 << 20), b""):
                    digest.update(chunk)
            return digest.hexdigest()
        return ""
    except Exception:
        return ""


def _party(url, page_url):
    """Classify a script as first-party / third-party / inline / unknown."""
    if not url:
        return "inline"
    if str(url).startswith("file://"):
        return "file"
    script_host = _host(url)
    page_host = _host(page_url)
    if not script_host:
        return "inline"
    if not page_host:
        return "third_party" if _is_url(url) else "unknown"
    if script_host == page_host or script_host.endswith("." + page_host):
        return "first_party"
    return "third_party"


def _load_method(name, url, data):
    if str(name).startswith(("runtime://", "url://")):
        return "runtime_dynamic"
    if not name or url:
        return "external"
    if str(name) in ("inline.js", "inline"):
        return "inline"
    if "chunk-" in str(name):
        return "dynamic_import"
    if str(name).startswith(("http://", "https://")):
        return "external"
    if "://" in str(name):
        return "external"
    if os.path.isfile(str(name)):
        return "external"
    return "inline"


def _blob(data):
    try:
        return json.dumps(data, default=str).lower()
    except Exception:
        return str(data or "").lower()


def _contains_any(text, patterns):
    return any(p in text for p in patterns)


def browser_api_map(data):
    """Return a compact privacy/security API capability map for a script."""
    blob = _blob(data)
    features = " ".join(str(x) for x in (data.get("notable_features", []) or []))
    blob = f"{blob} {features.lower()}"

    def found(*patterns):
        return _contains_any(blob, [p.lower() for p in patterns])

    return [
        {"key": "camera_microphone", "label": "Camera / Microphone", "enabled": found("getusermedia", "mediaDevices")},
        {"key": "geolocation", "label": "Geolocation", "enabled": found("geolocation", "navigator.geolocation")},
        {"key": "clipboard", "label": "Clipboard", "enabled": found("clipboard", "nav.clipboard", "execcommand('copy')")},
        {"key": "notifications", "label": "Notifications", "enabled": found("notification.requestpermission", "new notification")},
        {"key": "storage", "label": "Browser Storage", "enabled": found("localstorage", "sessionstorage", "document.cookie", ".cookie")},
        {"key": "indexeddb", "label": "IndexedDB", "enabled": found("indexeddb")},
        {"key": "service_worker", "label": "Service Worker", "enabled": found("serviceworker", "service_worker")},
        {"key": "websocket", "label": "WebSocket", "enabled": found("websocket", "new websocket")},
        {"key": "post_message", "label": "postMessage", "enabled": found("postmessage", "post_message")},
        {"key": "dynamic_code", "label": "Dynamic Code", "enabled": found("eval(", "new function", "settimeout(\"", "setinterval(\"")},
        {"key": "dom_access", "label": "DOM Modification", "enabled": found("innerhtml", "insertadjacenthtml", "outerhtml", "document.write", "dom_risks")},
        {"key": "network", "label": "Network Access", "enabled": found("fetch(", "axios", "xmlhttprequest", "sendbeacon", "websocket")},
    ]


def sensitive_sources(data):
    """List sensitive data classes the script can read/collect."""
    blob = _blob(data)
    sources = []
    if _contains_any(blob, ["document.cookie", "cookies", "cookie"]):
        sources.append("cookies")
    if data.get("storage") or data.get("storage_analysis") or _contains_any(blob, ["localstorage", "sessionstorage"]):
        sources.append("browser_storage")
    if _contains_any(blob, ["location.search", "urlsearchparams", "url query", "query string", "location.hash"]):
        sources.append("url_parameters")
    if data.get("attack_surface", {}).get("parameters") or data.get("dom_risks") and _contains_any(blob, ["form", "input", "value"]):
        sources.append("form_fields")
    if data.get("credible_secrets", data.get("secrets")) or data.get("keys") or data.get("headers"):
        sources.append("secrets_tokens")
    return list(dict.fromkeys(sources))


def network_destinations(data):
    """Return normalized HTTP/WS destinations inferred from static analysis."""
    destinations = []
    seen = set()
    raw = []
    for item in data.get("endpoints", []) or []:
        raw.append(str(item))
    for item in data.get("api_calls", []) or []:
        raw.append(str(item))
    surface = data.get("attack_surface", {}) or {}
    for item in surface.get("endpoints", []) or []:
        if isinstance(item, dict):
            if item.get("url"):
                raw.append(str(item.get("url")))
            else:
                raw.append(f"{item.get('method', 'GET')} {item.get('url', '')}")
    for item in surface.get("websockets", []) or []:
        if isinstance(item, dict) and item.get("url"):
            raw.append(str(item.get("url")))
    for item in surface.get("sse", []) or []:
        if isinstance(item, dict) and item.get("url"):
            raw.append(str(item.get("url")))

    for value in raw:
        host = _host(value)
        if host and (host, value) not in seen:
            seen.add((host, value))
            destinations.append({
                "url": value[:240],
                "domain": host,
                "scheme": (urlparse(value).scheme if _is_url(value) else "relative"),
            })
    return destinations[:30]


def capability_profile(data, page_url=""):
    """Build the behavioral profile: what the script reads, writes and sends."""
    blob = _blob(data)
    sources = sensitive_sources(data)
    destinations = network_destinations(data)
    surface = data.get("attack_surface", {}) or {}
    external = [d for d in destinations if d.get("domain") and d["domain"] != _host(page_url)]

    writes = []
    if data.get("dom_risks") or _contains_any(blob, ["innerhtml", "insertadjacenthtml", "outerhtml", "document.write"]):
        writes.append("DOM")
    if data.get("storage") or _contains_any(blob, ["localstorage", "sessionstorage"]):
        writes.append("Browser Storage")
    if data.get("post_message") or _contains_any(blob, ["postmessage"]):
        writes.append("postMessage")
    if data.get("suspicious_calls") or _contains_any(blob, ["eval(", "new function"]):
        writes.append("Dynamic Execution")

    return {
        "reads": sources,
        "writes": list(dict.fromkeys(writes)),
        "network_destinations": destinations,
        "external_destinations": external,
        "websockets": [w.get("url", "") for w in surface.get("websockets", []) if isinstance(w, dict)][:12],
        "dynamic_imports": [x for x in (data.get("dependency_scan", []) or []) if isinstance(x, dict) and "import" in str(x.get("evidence", "")).lower()][:12],
    }


def script_risk_score(data, page_url="", runtime_evidence=None, party=""):
    """Return a 0-100 script risk score plus human-readable factors."""
    profile = capability_profile(data, page_url)
    factors = []
    score = 0

    party = party or _party(data.get("url", ""), page_url)
    if party == "third_party":
        score += 25
        factors.append("Third-party origin")
    if party == "first_party":
        score += 5
        factors.append("First-party execution context")

    caps = " ".join(profile["reads"] + profile["writes"])
    if "Dynamic Execution" in profile["writes"]:
        score += 20
        factors.append("Dynamic code execution")
    if "DOM" in profile["writes"]:
        score += 15
        factors.append("DOM modification")
    if profile["reads"]:
        score += 15
        factors.append("Sensitive data sources: " + ", ".join(profile["reads"][:4]))
    if profile["external_destinations"]:
        score += 15
        factors.append("External network destinations: " + ", ".join(sorted({d["domain"] for d in profile["external_destinations"]})[:4]))
    elif profile["network_destinations"]:
        score += 8
        factors.append("Network communication")
    if profile["websockets"]:
        score += 10
        factors.append("WebSocket channel")
    if "postMessage" in profile["writes"]:
        score += 8
        factors.append("postMessage communication")
    if profile["dynamic_imports"]:
        score += 8
        factors.append("Dynamically imports more scripts")
    if _contains_any(_blob(data), ["navigator.geolocation", "getusermedia", "notification", "clipboard"]):
        score += 10
        factors.append("Sensitive browser API usage")

    if runtime_evidence and runtime_evidence.get("captured"):
        if len(runtime_evidence.get("requests", []) or []) > 10:
            score += 5
            factors.append("High runtime network activity")
        if runtime_evidence.get("eval_calls"):
            score += 10
            factors.append("Runtime eval observed")

    return {
        "score": min(100, max(0, score)),
        "factors": list(dict.fromkeys(factors)),
    }


def _intel_for_file(name, data, page_url="", runtime_evidence=None, runtime_url="", loaded_by=None, pages_present=None):
    url = str(data.get("url") or runtime_url or name)
    host = _host(url)
    if not _is_url(url) and page_url and not str(name).startswith("inline"):
        # A discovered/downloaded script from the same scan is almost always the
        # page's first-party bundle even when its absolute URL is not known.
        party = "first_party"
    else:
        party = _party(url, page_url)
    load_method = _load_method(name, url, data)
    profile = capability_profile(data, page_url)
    api_map = browser_api_map(data)
    risk = script_risk_score(data, page_url, runtime_evidence, party=party)
    hash_value = str(data.get("content_sha256") or _read_hash(name) or "")
    findings = data.get("findings", []) or []
    runtime_requests = []
    url_candidates = {_canonical(url), _canonical(name), _basename(url)}
    for request in runtime_evidence.get("requests", []) or []:
        if not isinstance(request, dict):
            continue
        initiators = request.get("initiated_by", []) or []
        if any(_canonical(value) in url_candidates or _basename(value) in url_candidates for value in initiators):
            runtime_requests.append({
                "method": request.get("method", "GET"),
                "url": str(request.get("url", ""))[:240],
                "status": request.get("status"),
            })
    return {
        "name": _basename(name) or str(name),
        "path": str(name),
        "url": url if _is_url(url) else "",
        "domain": host,
        "party": party,
        "load_method": load_method,
        "loaded_by": list(dict.fromkeys(loaded_by or []))[:12],
        "pages_present": list(dict.fromkeys(pages_present or ([page_url] if page_url else [])))[:12],
        "size": data.get("file_size", 0),
        "lines": data.get("line_count", 0),
        "hash": hash_value,
        "capabilities": profile,
        "browser_apis": api_map,
        "risk": risk,
        "finding_count": len(findings),
        "dataflow_count": len(data.get("dataflows", []) or []),
        "dependencies": [d.get("name") for d in (data.get("dependency_scan", []) or []) if isinstance(d, dict)][:12],
        "runtime_requests": runtime_requests[:20],
        "scanned": bool(host or data.get("file_size")),
    }


def build_script_intel(results, runtime_evidence=None, page_url=""):
    """Build the full script inventory/behavior list for one scan result dict."""
    runtime_evidence = runtime_evidence or {}
    page_url = page_url or runtime_evidence.get("url") or ""
    runtime_scripts = runtime_evidence.get("scripts", []) or []
    runtime_url_by_base = {_basename(url): url for url in runtime_scripts if _basename(url)}
    scan_summary = (results or {}).get("__scan_summary__") or {}
    script_edges = scan_summary.get("script_edges", []) or []
    page_list = [page_url] if page_url else []
    page_list.extend(runtime_evidence.get("frame_urls", []) or [])
    page_list = list(dict.fromkeys(str(value) for value in page_list if value))[:12]

    def canonical(value):
        return str(value or "").split("#", 1)[0].split("?", 1)[0].rstrip("/")

    def loaders_for(url, name):
        target = canonical(url)
        loaders = []
        for edge in script_edges:
            if not isinstance(edge, dict):
                continue
            if canonical(edge.get("to")) == target or _basename(edge.get("to")) == _basename(name):
                if edge.get("from"):
                    loaders.append(str(edge["from"]))
        # Entry scripts are loaded by the scanned page; a runtime-only script
        # may be loaded by a page/frame when CDP initiator data is unavailable.
        if not loaders and page_url and (target or name):
            loaders.append(page_url)
        return list(dict.fromkeys(loaders))[:12]

    out = []
    seen = set()

    for name, data in (results or {}).items():
        if str(name).startswith("__"):
            continue
        runtime_url = runtime_url_by_base.get(_basename(name), "")
        entry = _intel_for_file(
            name,
            data,
            page_url=page_url,
            runtime_evidence=runtime_evidence,
            runtime_url=runtime_url,
            loaded_by=loaders_for(entry_url := (data.get("url") or runtime_url or name), name),
            pages_present=page_list,
        )
        seen.add(entry["name"])
        out.append(entry)

    # Add dynamically-loaded runtime scripts that static discovery could not see.
    for url in runtime_scripts:
        key = _basename(url)
        if not key or key in seen:
            continue
        seen.add(key)
        out.append({
            "name": key,
            "path": url,
            "url": url,
            "domain": _host(url),
            "party": _party(url, page_url),
            "load_method": "runtime_dynamic",
            "loaded_by": [page_url] if page_url else [],
            "pages_present": page_list,
            "size": 0,
            "lines": 0,
            "hash": "",
            "capabilities": {"reads": [], "writes": ["Dynamic Load"], "network_destinations": [], "external_destinations": [], "websockets": [], "dynamic_imports": []},
            "browser_apis": [],
            "risk": {"score": 20, "factors": ["Runtime-loaded script"]},
            "finding_count": 0,
            "dataflow_count": 0,
            "dependencies": [],
            "scanned": False,
        })

    return out


def data_exfiltration_candidates(results, runtime_evidence=None, page_url=""):
    """Correlate sensitive sources with external network destinations."""
    runtime_evidence = runtime_evidence or {}
    page_url = page_url or runtime_evidence.get("url") or ""
    candidates = []
    for name, data in (results or {}).items():
        if str(name).startswith("__"):
            continue
        profile = capability_profile(data, page_url)
        if not profile["reads"] or not profile["external_destinations"]:
            continue
        external_domains = sorted({d["domain"] for d in profile["external_destinations"]})
        candidates.append({
            "id": "data_exfiltration_candidate",
            "type": "Sensitive data flow to external destination",
            "severity": "HIGH",
            "confidence": "medium",
            "status": "needs_review",
            "file": name,
            "line": 0,
            "source": " + ".join(profile["reads"][:4]),
            "sink": "external network: " + ", ".join(external_domains[:6]),
            "flow": ["+".join(profile["reads"][:4]), "->".join(external_domains[:4])],
            "evidence": [f"sources: {', '.join(profile['reads'][:4])}", f"external domains: {', '.join(external_domains[:6])}"],
            "sanitization_detected": False,
            "framework": "Script behavior correlation",
            "evidence_type": "behavioral_correlation",
        })
    return candidates
