"""Context-aware attack-surface extraction: endpoints, params, headers,
GraphQL operations, WebSocket/SSE connections, auth hints and hidden routes.
"""
import re
from urllib.parse import urlparse

from core.js_parser import parse_raw

INTERNAL_HINTS = ("admin", "internal", "debug", "dev", "staging", "stage", "test",
                  "private", "config", "env", "health", "metrics", "local", "localhost",
                  "127.0.0.1", "10.", "192.168", "internal-api", "backoffice", "console")

HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

GRAPHQL_PATTERNS = (
    r"\bgraphql\b",
    r"/graphql",
    r"\bquery\s+\w*\s*(\(|\{)",
    r"\bmutation\s+\w*\s*(\(|\{)",
)


def _line(node):
    if not isinstance(node, dict):
        return 0
    return (node.get("loc") or {}).get("start", {}).get("line", 0)


def _literal_value(node):
    if not isinstance(node, dict):
        return None
    t = node.get("type")
    if t == "Literal":
        return node.get("value")
    if t == "TemplateLiteral":
        parts = []
        quasis = node.get("quasis", []) or []
        exprs = node.get("expressions", []) or []
        idx = 0
        for quasi in quasis:
            parts.append((quasi.get("value") or {}).get("cooked", "") or "")
            if idx < len(exprs):
                parts.append("${...}")
                idx += 1
        return "".join(parts)
    if t == "BinaryExpression":
        left = _literal_value(node.get("left"))
        right = _literal_value(node.get("right"))
        if left is None or right is None:
            return None
        return f"{left}{right}"
    return None


def _key_name(key_node):
    if not isinstance(key_node, dict):
        return None
    t = key_node.get("type")
    if t in ("Identifier",):
        return key_node.get("name")
    if t == "Literal":
        return key_node.get("value")
    return None


def _find_properties(obj_node, wanted=None):
    props = {}
    if not isinstance(obj_node, dict) or obj_node.get("type") != "ObjectExpression":
        return props
    for prop in obj_node.get("properties", []) or []:
        if not isinstance(prop, dict) or prop.get("type") != "Property":
            continue
        key = _key_name(prop.get("key"))
        if key is None:
            continue
        props[key] = prop.get("value")
    return props


def _query_params(url):
    parsed = urlparse(url if url.startswith(("http", "/")) else f"http://x{url}")
    params = {}
    for part in (parsed.query or "").split("&"):
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        params.setdefault(k, set()).add(v)
    return {k: sorted(vs) for k, vs in params.items()}


def _body_fields(value_node):
    """Extract object keys from a body/options expression, incl. JSON.stringify({...})."""
    if not isinstance(value_node, dict):
        return []
    # JSON.stringify({...}) or JSON.parse({...})
    if value_node.get("type") in ("CallExpression",):
        args = value_node.get("arguments", []) or []
        if args and args[0].get("type") == "ObjectExpression":
            return list(_find_properties(args[0]).keys())
        return []
    if value_node.get("type") == "ObjectExpression":
        return list(_find_properties(value_node).keys())
    return []


def _is_internal(url):
    low = url.lower()
    parsed = urlparse(url if url.startswith(("http", "/", "ws")) else f"http://x{url}")
    path = parsed.path or str(url)
    return any(h in path.lower() for h in INTERNAL_HINTS) or parsed.hostname in ("localhost", "127.0.0.1", "0.0.0.0")


def _extract_from_call(node, filename):
    """Inspect a CallExpression that is likely a network request."""
    callee = None
    obj = node.get("callee") or {}
    if isinstance(obj, dict):
        callee = (
            (obj.get("object") or {}).get("name") if obj.get("type") == "MemberExpression" else obj.get("name")
        )
        if obj.get("type") == "MemberExpression":
            prop = obj.get("property") or {}
            if isinstance(prop, dict):
                callee = f"{(obj.get('object') or {}).get('name', '')}.{prop.get('name', '')}"
    callee_low = (callee or "").lower()
    if not any(k in callee_low for k in ("fetch", "axios", "xmlhttprequest", "websocket", "eventsource", "sendbeacon")):
        return None

    args = node.get("arguments", []) or []
    if not args:
        return None

    # WebSocket / SSE
    if "websocket" in callee_low or "eventsource" in callee_low:
        url_lit = _literal_value(args[0])
        if not url_lit:
            return {"kind": "realtime", "url": url_lit, "line": _line(node), "internal": False}
        return {
            "kind": "websocket" if "websocket" in callee_low else "sse",
            "url": _literal_value(args[0]),
            "protocols": [_literal_value(a) for a in args[1:3] if _literal_value(a)],
            "line": _line(node),
            "internal": _is_internal(url_lit),
        }

    # navigator.sendBeacon(url, data) is a POST-style beacon.
    if "sendbeacon" in callee_low:
        url_lit = _literal_value(args[0]) or ""
        body_fields = _body_fields(args[1]) if len(args) > 1 else []
        params = _query_params(url_lit) if url_lit else {}
        return {
            "kind": "endpoint", "url": url_lit, "method": "POST", "params": params,
            "headers": {}, "body_fields": body_fields, "auth": None,
            "line": _line(node), "internal": _is_internal(url_lit) if url_lit else False,
        }

    # fetch(url, options) / axios.method(url, config) / XHR(url)
    url_lit = _literal_value(args[0])
    method = "GET"
    headers = {}
    body_fields = []
    params = _query_params(url_lit) if url_lit else {}
    auth = None

    if "axios" in callee_low:
        method = "GET"
        # axios.get/post/... -> second arg is config
        prop = obj.get("property") or {}
        if isinstance(prop, dict) and prop.get("name", "").lower() in {m.lower() for m in HTTP_METHODS}:
            method = prop.get("name", "GET").upper()
        cfg = args[1] if len(args) > 1 else (args[0] if len(args) == 1 and _node_is_config(args[0]) else None)
        if isinstance(cfg, dict):
            cfg_props = _find_properties(cfg)
            hdr = cfg_props.get("headers")
            hdr_props = _find_properties(hdr) if isinstance(hdr, dict) else {}
            headers = {k: _literal_value(v) for k, v in hdr_props.items() if _literal_value(v) is not None}
            data = cfg_props.get("data") or cfg_props.get("body")
            body_fields = _body_fields(data)
            url_lit = _literal_value(cfg_props.get("url")) or url_lit
            params = _query_params(url_lit) if url_lit else {}
    elif "fetch" in callee_low:
        # HTTP method lives in options, not callee
        opts = args[1] if len(args) > 1 else None
        if isinstance(opts, dict):
            opts_props = _find_properties(opts)
            m = _literal_value(opts_props.get("method"))
            if m:
                method = str(m).upper()
            hdr = opts_props.get("headers")
            hdr_props = _find_properties(hdr) if isinstance(hdr, dict) else {}
            headers = {k: _literal_value(v) for k, v in hdr_props.items() if _literal_value(v) is not None}
            data = opts_props.get("body")
            body_fields = _body_fields(data)
    elif "xmlhttprequest" in callee_low:
        # .open(method, url) appears earlier; handled by heuristic pass instead.
        return None

    if not url_lit:
        return {"kind": "endpoint", "url": url_lit, "method": method, "params": params,
                "headers": headers, "body_fields": body_fields, "line": _line(node), "internal": False, "auth": None}

    # Authentication hints
    auth_present = any(h.lower() in {"authorization", "auth", "x-api-key", "api-key", "token", "x-auth-token"} for h in headers)
    url_auth = bool(re.search(r"(?:token|api[_-]?key|access[_-]?token|auth|jwt)=[^&]+", url_lit, re.I))
    auth = ("authorization header" if auth_present else "url token" if url_auth else None)

    return {
        "kind": "endpoint",
        "url": url_lit,
        "method": method,
        "params": params,
        "headers": headers,
        "body_fields": body_fields,
        "auth": auth,
        "line": _line(node),
        "internal": _is_internal(url_lit),
    }


def _node_is_config(node):
    return isinstance(node, dict) and node.get("type") == "ObjectExpression"


def _regex_sweep(content, filename):
    findings = []
    # Fetch/axios/XHR method calls where AST may not apply.
    for match in re.finditer(r"\baxios\.(get|post|put|patch|delete|head)\s*\(\s*[\"'][^\"']+[\"']", content, re.I):
        method = match.group(1).upper()
        m = re.search(r"[\"']([^\"']+)[\"']", match.group(0))
        url = m.group(1) if m else None
        findings.append({"kind": "endpoint", "url": url, "method": method, "params": _query_params(url),
                         "headers": {}, "body_fields": [], "auth": None, "line": content[:match.start()].count("\n") + 1,
                         "internal": _is_internal(url) if url else False})
    for match in re.finditer(r"\bnew\s+WebSocket\s*\(\s*[\"']([^\"']+)[\"']", content, re.I):
        url = match.group(1)
        findings.append({"kind": "websocket", "url": url, "protocols": [], "line": content[:match.start()].count("\n") + 1,
                         "internal": _is_internal(url)})
    for match in re.finditer(r"\bnew\s+EventSource\s*\(\s*[\"']([^\"']+)[\"']", content, re.I):
        url = match.group(1)
        findings.append({"kind": "sse", "url": url, "protocols": [], "line": content[:match.start()].count("\n") + 1,
                         "internal": _is_internal(url)})
    for match in re.finditer(r"(?:xhr|request)\.open\s*\(\s*[\"'](GET|POST|PUT|PATCH|DELETE)[\"']\s*,\s*[\"']([^\"']+)[\"']", content, re.I):
        method, url = match.group(1).upper(), match.group(2)
        findings.append({"kind": "endpoint", "url": url, "method": method, "params": _query_params(url),
                         "headers": {}, "body_fields": [], "auth": None, "line": content[:match.start()].count("\n") + 1,
                         "internal": _is_internal(url)})
    for match in re.finditer(r"(?:navigator\s*\.\s*)?sendBeacon\s*\(\s*[\"']([^\"']+)[\"']", content, re.I):
        url = match.group(1)
        findings.append({"kind": "endpoint", "url": url, "method": "POST", "params": _query_params(url),
                         "headers": {}, "body_fields": [], "auth": None, "line": content[:match.start()].count("\n") + 1,
                         "internal": _is_internal(url)})
    return findings


def _graphql_sweep(content, filename):
    ops = []
    for pattern in [r"\bquery\s+(\w*)\s*(\(|\{)", r"\bmutation\s+(\w*)\s*(\(|\{)"]:
        for match in re.finditer(pattern, content, re.I):
            ops.append({"operation": match.group(1) or "(anonymous)", "line": content[:match.start()].count("\n") + 1})
    urls = re.findall(r"/[a-zA-Z0-9/_.-]*graphql[a-zA-Z0-9/_.-]*", content, re.I)
    return {"urls": list(dict.fromkeys(urls)), "operations": ops[:40]}


def extract_attack_surface(content, filename="inline.js"):
    """Return a structured attack-surface object for a JS document."""
    endpoints = []
    websockets = []
    sse = []
    params = {}
    domains = set()
    headers = set()
    body_fields = set()
    auth_hints = []
    internal = []
    graphql_urls = set()
    graphql_ops = []

    tree = parse_raw(content)
    if tree is not None:
        seen_keys = set()

        def walk(node):
            if isinstance(node, list):
                for child in node:
                    walk(child)
                return
            if not isinstance(node, dict):
                return
            ntype = node.get("type")
            if ntype in ("CallExpression", "NewExpression"):
                item = _extract_from_call(node, filename)
                if item:
                    key = (item.get("kind"), item.get("url"), item.get("method"), item.get("line") or 0)
                    if key not in seen_keys:
                        seen_keys.add(key)
                        if item["kind"] == "websocket":
                            websockets.append(item)
                        elif item["kind"] == "sse":
                            sse.append(item)
                        else:
                            endpoints.append(item)
            # Recurse
            for value in node.values():
                if isinstance(value, (list, dict)):
                    walk(value)

        for body in tree.get("body", []):
            walk(body)

    # merge regex sweep where AST didn't find things
    for item in _regex_sweep(content, filename):
        key = (item.get("kind"), item.get("url"), item.get("method"), item.get("line") or 0)
        if key not in {(e.get("kind"), e.get("url"), e.get("method"), e.get("line") or 0) for e in endpoints + websockets + sse if isinstance(e, dict)}:
            if item["kind"] == "websocket":
                websockets.append(item)
            elif item["kind"] == "sse":
                sse.append(item)
            else:
                endpoints.append(item)

    # GraphQL
    gq = _graphql_sweep(content, filename)
    graphql_urls.update(gq["urls"])
    graphql_ops.extend(gq["operations"])

    # Unconditional endpoint extraction from URL literals, incl. hidden routes.
    # Require an actual URL/path shape so header/object keys like "Authorization"
    # do not become fake endpoints.
    url_re = re.compile(
        r"[\"']((?:(?:https?|wss?):)?//[A-Za-z0-9/_.?=&%{}\-]+"
        r"|/[A-Za-z0-9/_.?=&%{}\-]+"
        r"|(?:api|v[0-9]+|auth|login|logout|admin|internal|dev|staging|graphql|ws|wss)/[A-Za-z0-9/_.?=&%{}\-]+)[\"']",
        re.I,
    )
    for m in url_re.finditer(content):
        url = m.group(1)
        line = content[:m.start()].count("\n") + 1
        lower_url = url.lower()
        if any(e.get("url") == url for e in endpoints):
            continue
        # Realtime channels are already captured separately; don't duplicate as HTTP GET.
        if lower_url.startswith(("ws://", "wss://")) or any(rt.get("url") == url for rt in websockets + sse):
            continue
        endpoints.append({
            "kind": "endpoint", "url": url, "method": "GET", "params": _query_params(url),
            "headers": {}, "body_fields": [], "auth": None, "line": line, "internal": _is_internal(url),
        })

    all_urls = [e["url"] for e in endpoints if e.get("url")] + [w["url"] for w in websockets if w.get("url")] + [s["url"] for s in sse if s.get("url")] + list(graphql_urls)
    for url in all_urls:
        if not url:
            continue
        parsed = urlparse(url if url.startswith(("http", "/", "ws")) else f"http://x{url}")
        if parsed.hostname:
            domains.add(parsed.hostname)
        params.update(_query_params(url))

    for e in endpoints + websockets + sse:
        if e.get("headers"):
            headers.update(e["headers"].keys())
        if e.get("body_fields"):
            body_fields.update(e["body_fields"])
        if e.get("auth"):
            auth_hints.append({"type": e["auth"], "evidence": e.get("url") or ""})
        if e.get("internal"):
            internal.append(e)

    # Header / credential patterns across whole document (headers in fetch options etc.)
    # Require a quoted value (`token: "x"` / `token='x'`) so URL query strings like
    # `?token=abc` stay in parameter/auth signals instead of polluting the header list.
    for m in re.finditer(r"[\"']?(?:authorization|bearer|token|api[_-]?key|client[_-]?secret|access[_-]?token)[\"']?\s*[:=]\s*[\"']", content, re.I):
        header_name = re.split(r"[:=]", m.group(0), maxsplit=1)[0].strip().lower()
        headers.add(header_name)
        auth_hints.append({
            "type": "credential/header usage",
            "evidence": content[max(0, m.start() - 40):m.start() + 120].strip(),
            "line": content[:m.start()].count("\n") + 1,
        })

    return {
        "endpoints": endpoints[:80],
        "websockets": websockets[:30],
        "sse": sse[:20],
        "graphql": {"urls": sorted(graphql_urls)[:30], "operations": graphql_ops[:40]},
        "parameters": sorted(set(_flatten_params(params)))[:80],
        "domains": sorted(domains)[:60],
        "headers": sorted(headers)[:40],
        "body_fields": sorted(body_fields)[:40],
        "auth_hints": auth_hints[:20],
        "internal_endpoints": internal[:20],
        "endpoint_count": len(endpoints),
    }


def _flatten_params(params):
    """Return parameter *names* (not values) for the compact attack-surface summary."""
    return list(params.keys())
