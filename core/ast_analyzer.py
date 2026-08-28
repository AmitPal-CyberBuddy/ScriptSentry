"""AST-driven JavaScript intelligence.

This module answers "what is this JS code structure really doing?" It is a clean
complement to the regex scanner: imports/exports, functions/classes, call graph
signals, object/config structure, and syntax profile.
"""
import re
from collections import Counter

from core.js_parser import extract_exports, extract_imports, parse_ast


def _is_import_like(path):
    return bool(path and path.startswith((".", "/", "http", "https", "//", "@")))


def _short_source(source):
    if source and len(source) > 42:
        return source[:18] + "…" + source[-18:]
    return source


def _call_signals():
    return {
        "window.fetch": "HTTP client",
        "fetch": "HTTP client",
        "fetch(": "HTTP client",
        "axios": "HTTP client",
        "XMLHttpRequest": "HTTP client",
        "WebSocket": "WebSocket",
        "EventSource": "Server-Sent Events",
        "postMessage": "Cross-window messaging",
        "eval": "Dynamic code execution",
        "Function": "Dynamic function construction",
        "localStorage": "localStorage",
        "sessionStorage": "sessionStorage",
        "document.cookie": "cookie access",
        "indexedDB": "IndexedDB",
        "serviceWorker": "Service Worker",
        "CryptoJS": "Crypto library",
        "subtle": "WebCrypto",
        "encrypt": "Cryptographic operation",
        "decrypt": "Cryptographic operation",
        "atob": "Base64 decode",
        "btoa": "Base64 encode",
        "JSON.parse": "JSON parsing",
        "JSON.stringify": "JSON serialization",
        "console.log": "Debug logging",
        "console.debug": "Debug logging",
        "window.open": "Navigation",
        "location": "Navigation",
        "Object.assign": "Object mutation",
        "__proto__": "Prototype mutation",
        "innerHTML": "DOM injection",
        "insertAdjacentHTML": "DOM injection",
        "document.write": "DOM injection",
        "setTimeout": "Timed execution",
        "requestAnimationFrame": "Animation frame",
    }


def _call_category(name):
    name = name.lower()
    if name in ("fetch", "axios", "xmlhttprequest") or ".fetch" in name or ".post(" in name or ".get(" in name:
        return "http"
    if "websocket" in name:
        return "realtime"
    if "eventsource" in name or "sse" in name:
        return "realtime"
    if "indexeddb" in name:
        return "storage"
    if "localstorage" in name or "sessionstorage" in name or "cookie" in name:
        return "storage"
    if name in ("eval", "new function", "function") or "function(" in name:
        return "dynamic"
    if "cryptojs" in name or "subtle" in name or name in ("encrypt", "decrypt"):
        return "crypto"
    if "atob" in name or "btoa" in name or "decodeuri" in name or "encodeuri" in name:
        return "encoding"
    if "innerhtml" in name or "outerhtml" in name or ".write(" in name or "adjehtml" in name:
        return "dom"
    if "postmessage" in name or "post_message" in name:
        return "postMessage"
    return "other"


def analyze_ast(content, filename="inline.js"):
    """Return a structured AST intelligence dict for a JS document."""
    ast = parse_ast(content) if content else {}
    imports = ast.get("imports", []) or []
    exports = ast.get("exports", []) or []
    if not imports:
        imports = [
            {"source": item.get("source"), "specifiers": item.get("specifiers", []), "raw": item.get("raw", "")}
            for item in extract_imports(content)
        ]
    if not exports:
        exports = extract_exports(content)

    calls = ast.get("calls", []) or []
    literal_values = [item.get("value") for item in ast.get("literals", []) or [] if item.get("value") is not None]
    properties = [item.get("key") for item in ast.get("properties", []) or [] if item.get("key")]

    call_names = [c.get("callee", "") for c in calls if c.get("callee")]
    if not call_names:
        # Fallback when the JSX / dialect parser cannot build a full AST.
        call_names = re.findall(r'\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(', content)
    signals_seen = set()
    notable = []
    for name in dict.fromkeys(call_names):
        matched_label = None
        for needle, label in _call_signals().items():
            if needle.lower() in name.lower():
                matched_label = label
                break
        if matched_label and (name, matched_label) not in signals_seen:
            signals_seen.add((name, matched_label))
            notable.append({"name": name, "kind": matched_label, "category": _call_category(name)})

    modules = {
        "es6_imports": int(bool(imports)),
        "es6_exports": int(bool(exports)),
        "commonjs_require": int(bool(re.search(r"\brequire\s*\(", content))),
        "dynamic_import": int(bool(re.search(r"\bimport\s*\(", content))),
        "worker_or_service": int(bool(re.search(r"\b(?:Worker|ServiceWorker|SharedWorker)\b", content))),
    }

    # Module system snapshots.
    module_system = "ES modules" if modules["es6_imports"] or modules["es6_exports"] else ("CommonJS" if modules["commonjs_require"] else ("none detected" if not content else "unknown"))

    # Estimate complexity from AST and raw heuristics.
    decl_count = len(ast.get("declarations", []) or [])
    function_count = len(ast.get("functions", []) or [])
    class_count = len(ast.get("classes", []) or [])
    prop_count = len(properties)
    token_count = ast.get("token_count", 0)
    comment_count = ast.get("comment_count", 0)
    line_count = content.count("\n") + 1 if content else 0
    char_count = len(content) if content else 0
    referenced_names = len({c.get("callee", "").split(".")[0] for c in calls}) if call_names else 0
    complexity = min(100, (decl_count * 2 + function_count * 3 + class_count * 2 + prop_count + referenced_names) * 2)

    return {
        "available": bool(ast.get("available", False)),
        "parse_error": ast.get("parse_error"),
        "token_count": token_count,
        "comment_count": comment_count,
        "node_count": ast.get("node_count", 0),
        "line_count": line_count,
        "char_count": char_count,
        "module_system": module_system,
        "modules": modules,
        "imports": [
            {
                "source": _short_source(i.get("source", "")),
                "specifiers": i.get("specifiers", [])[:20],
                "line": i.get("line", 0),
            }
            for i in imports[:40]
        ],
        "exports": [{"kind": e.get("kind", "named"), "name": e.get("name", "")} for e in exports[:30]],
        "functions": [
            {"name": f.get("name", "(anonymous)"), "kind": f.get("kind", "function"), "line": f.get("line", 0)}
            for f in ast.get("functions", [])[:20]
        ],
        "classes": [
            {"name": c.get("name", "(anonymous)"), "line": c.get("line", 0)}
            for c in ast.get("classes", [])[:20]
        ],
        "declarations": [
            {"name": d.get("name", ""), "kind": d.get("kind", "var")}
            for d in ast.get("declarations", [])[:30]
        ],
        "calls": [{"callee": c.get("callee", ""), "args": c.get("args", 0)} for c in calls[:80]],
        "notable_calls": notable[:30],
        "literals": [
            {"value": v, "type": type(v).__name__, "line": 0}
            for v in literal_values[:30]
        ],
        "keys": [{"key": k, "count": 1} for k in dict.fromkeys(properties) if k][:60],
        "key_count": len(set(properties)),
        "complexity": complexity,
        "syntax": {
            "has_jsx": bool(re.search(r"<\s*[A-Z][\w.]*\s+[^>]*[\s/]>", content)),
            "has_typescript_interface": bool(re.search(r"\binterface\s+\w+", content)),
            "has_typescript_types": bool(re.search(r":\s*(?:string|number|boolean|any|unknown|never|void)\b", content)),
            "has_async": bool(re.search(r"\basync\b", content)),
            "has_generator": bool(re.search(r"\bfunction\s*\*|yield\b", content)),
            "has_class": bool(re.search(r"\bclass\b", content)),
            "has_optional_chaining": bool(re.search(r"\?\.", content)),
            "has_nullish": bool(re.search(r"\?\?", content)),
            "has_decorators": bool(re.search(r"@\w+", content)),
        },
        "dependencies": list(dict.fromkeys([i.get("source") for i in imports if i.get("source")]))[:40],
        "config_keys": list(dict.fromkeys(properties))[:40],
    }
