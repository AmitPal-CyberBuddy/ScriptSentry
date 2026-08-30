"""Optional JavaScript AST parsing helpers.

Uses the pure-Python ``esprima`` package when available. Everything is wrapped
so the analyzer still works (with regex fallbacks) when the parser is absent or
the source uses syntax the parser cannot handle.
"""
import re

try:
    import esprima
except ImportError:
    esprima = None


PARSER_NAME = "esprima"


def parser_available():
    """True when the optional JavaScript parser is installed.

    Everything keeps working without it, but taint analysis degrades to the
    line-based fallback, so callers should surface this to the analyst instead
    of silently producing weaker results.
    """
    return esprima is not None


def parser_status():
    return {
        "name": PARSER_NAME,
        "available": esprima is not None,
        "mode": "ast" if esprima is not None else "regex_fallback",
        "install_hint": f"pip install {PARSER_NAME}",
    }


def _node_key(node, key="name"):
    """Return the normalized name for an ESTree-style identifier node."""
    if node is None:
        return None
    if isinstance(node, str):
        return node
    if isinstance(node, dict):
        return node.get("name") or node.get("value") or node.get("raw") or (node.get("id") or {}).get("name")
    if hasattr(node, "name"):
        return node.name
    if hasattr(node, "value"):
        return node.value
    if hasattr(node, "raw"):
        return node.raw
    return None


def _is_node(obj, kind):
    return isinstance(obj, dict) and obj.get("type") == kind


def _walk(node, callback):
    if node is None:
        return
    if isinstance(node, list):
        for child in node:
            _walk(child, callback)
        return
    if not isinstance(node, dict):
        return
    callback(node)
    for value in node.values():
        if isinstance(value, (list, dict)):
            _walk(value, callback)


def _line(node):
    loc = None
    if isinstance(node, dict):
        loc = node.get("loc") or {}
    return (loc.get("start") or {}).get("line", 0) if loc else 0


def _format_node(node):
    if node is None:
        return ""
    if isinstance(node, dict):
        return _node_key(node) or node.get("type", "")
    return str(node)


def _callee_name(callee):
    if callee is None:
        return ""
    if isinstance(callee, dict):
        callee_type = callee.get("type")
        if callee_type == "Identifier":
            return callee.get("name", "")
        if callee_type == "MemberExpression":
            obj = _callee_name(callee.get("object"))
            prop = _callee_name(callee.get("property"))
            return f"{obj}.{prop}" if obj and prop else prop or obj or ""
        if callee_type == "ChainExpression":
            return _callee_name(callee.get("expression"))
    return _format_node(callee)


def _specifier_info(specifier):
    if specifier is None or not isinstance(specifier, dict):
        return None
    local = _node_key(specifier.get("local"), "local")
    kind = specifier.get("type", "ImportSpecifier")
    if kind == "ImportSpecifier":
        imported = _node_key(specifier.get("imported"), "imported")
        return {"kind": "named", "imported": imported, "local": local}
    if kind == "ImportDefaultSpecifier":
        return {"kind": "default", "imported": "default", "local": local}
    if kind == "ImportNamespaceSpecifier":
        return {"kind": "namespace", "imported": "*", "local": local}
    if kind == "ExportSpecifier":
        local = _node_key(specifier.get("local"), "local")
        exported = _node_key(specifier.get("exported", local), "exported")
        return {"kind": "named", "local": local, "exported": exported}
    return None


def _sanitize_modern_syntax(content):
    """Make modern syntax parser-friendly without dropping detection signals."""
    if not content:
        return content
    out = re.sub(r"\?\.", ".", content)
    out = re.sub(r"\?\?", "||", out)
    out = re.sub(r"&&\s*=|=\s*&&", "=", out)
    out = re.sub(r"\|\|\s*=|=\s*\|\|", "=", out)
    out = re.sub(r"\?\?=", "=", out)
    out = re.sub(r"#\s*([A-Za-z_$][\w$]*)", "_\\1", out)
    out = re.sub(r"\bawait\s+(?!\()", "", out)
    return out


def _parse(content):
    if esprima is None:
        return None, "esprima-not-installed"
    if not content or not content.strip():
        return None, "empty"
    attempts = []
    candidates = [content, _sanitize_modern_syntax(content)]
    seen = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        for method in ("parseModule", "parseScript"):
            try:
                fn = getattr(esprima, method)
                return fn(candidate, {"loc": True, "range": True, "comment": True, "tokens": True}), None
            except Exception as exc:  # noqa: BLE001 - parser supports many syntax dialects
                attempts.append(f"{method}: {exc}")
    if attempts:
        return None, attempts[0].split(":", 1)[-1].strip()
    return None, "parse-failed"


def parse_ast(content):
    """Parse JavaScript and return a compact, report-friendly AST summary."""
    result = {
        "available": bool(esprima is not None),
        "parse_error": None,
        "imports": [],
        "exports": [],
        "declarations": [],
        "functions": [],
        "classes": [],
        "calls": [],
        "literals": [],
        "properties": [],
        "assignments": [],
        "token_count": 0,
        "comment_count": 0,
        "node_count": 0,
    }

    if esprima is None:
        return result

    tree, error = _parse(content)
    if tree is None:
        result["parse_error"] = error
        return result

    # esprima returns typed AST objects; normalize to a plain dict.
    if not isinstance(tree, dict):
        try:
            tree = esprima.toDict(tree)
        except Exception:  # noqa: BLE001
            return result

    if not isinstance(tree, dict):
        return result

    result["token_count"] = len(tree.get("tokens", []) or [])
    result["comment_count"] = len(tree.get("comments", []) or [])

    def collect(node):
        node_type = node.get("type")
        if node_type == "ImportDeclaration":
            specifiers = [
                info for info in (_specifier_info(s) for s in node.get("specifiers", []) or []) if info
            ]
            result["imports"].append({
                "source": (node.get("source") or {}).get("value", ""),
                "specifiers": specifiers,
                "line": _line(node),
            })
        elif node_type in ("ExportNamedDeclaration", "ExportDefaultDeclaration", "ExportAllDeclaration"):
            export_type = "default" if node_type == "ExportDefaultDeclaration" else node["type"].replace("Export", "").replace("Declaration", "").lower()
            if node.get("declaration") is not None:
                decl = node["declaration"]
                name = _node_key(decl.get("id") or decl.get("name")) or decl.get("type", "")
                result["exports"].append({
                    "kind": export_type or "named",
                    "name": name,
                    "line": _line(node),
                })
            for spec in node.get("specifiers", []) or []:
                info = _specifier_info(spec)
                if info:
                    result["exports"].append({
                        "kind": info.get("kind", "named"),
                        "name": info.get("exported") or info.get("local") or "",
                        "line": _line(spec),
                    })
            if node.get("source") is not None:
                result["exports"].append({
                    "kind": "re-export",
                    "name": (node["source"] or {}).get("value", ""),
                    "line": _line(node),
                })
        elif node_type in ("VariableDeclaration",):
            for decl in node.get("declarations", []) or []:
                result["declarations"].append({
                    "name": _node_key(decl.get("id")),
                    "kind": node.get("kind", "var"),
                    "line": _line(decl),
                })
        elif node_type in ("FunctionDeclaration", "FunctionExpression"):
            result["functions"].append({
                "name": _node_key(node.get("id")) or "(anonymous)",
                "kind": "function",
                "line": _line(node),
            })
        elif node_type == "ArrowFunctionExpression":
            result["functions"].append({
                "name": "(arrow)",
                "kind": "arrow",
                "line": _line(node),
            })
        elif node_type in ("ClassDeclaration", "ClassExpression"):
            result["classes"].append({
                "name": _node_key(node.get("id")) or "(anonymous)",
                "line": _line(node),
            })
        elif node_type == "CallExpression":
            result["calls"].append({
                "callee": _callee_name(node.get("callee")),
                "args": len(node.get("arguments", []) or []),
                "line": _line(node),
            })
        elif node_type == "NewExpression":
            result["calls"].append({
                "callee": _callee_name(node.get("callee")),
                "args": len(node.get("arguments", []) or []),
                "line": _line(node),
            })
        elif node_type == "Literal":
            lp = {k: v for k, v in node.items() if k in ("value", "regex", "line")}
            result["literals"].append({
                "value": node.get("value"),
                "raw": node.get("raw", ""),
                "line": _line(node),
            })
        elif node_type == "Property":
            props = {
                "key": _node_key(node.get("key")),
                "computed": bool(node.get("computed")),
                "kind": node.get("kind", "init"),
                "line": _line(node),
            }
            val = node.get("value")
            if val and val.get("type") == "Literal":
                props["value"] = val.get("value")
            result["properties"].append(props)
        elif node_type == "AssignmentExpression":
            result["assignments"].append({
                "operator": node.get("operator", "="),
                "left": _format_node(node.get("left")),
                "line": _line(node),
            })

    for node in tree.get("body", []):
        _walk(node, collect)

    result["node_count"] = result.get("node_count", 0)
    # Node count is approximated by the recursive walk above; keep it meaningful.
    result["node_count"] = len(result["declarations"]) + len(result["functions"]) + len(result["classes"]) + len(result["calls"]) + len(result["literals"]) + len(result["properties"]) + len(result["imports"]) + len(result["exports"])
    return result


def parse_raw(content):
    """Return the raw parsed AST as a plain dict, or None.

    Used by downstream analyzers that need the full ESTree shape (e.g.
    source/sink data-flow analysis) rather than the summarized report dict.
    """
    if esprima is None:
        return None
    tree, error = _parse(content)
    if tree is None:
        return None
    if not isinstance(tree, dict):
        try:
            tree = esprima.toDict(tree)
        except Exception:  # noqa: BLE001
            return None
    return tree if isinstance(tree, dict) else None


def extract_imports(content):
    """Fallback regex import extraction when the parser is unavailable."""
    imports = []
    patterns = [
        r"import\s+[\"']([^\"']+)[\"']",
        r"import\s+([^;]+?)\s+from\s+[\"']([^\"']+)[\"']",
        r"import\s*\(\s*[\"']([^\"']+)[\"']",
        r"require\s*\(\s*[\"']([^\"']+)[\"']",
    ]
    for pattern in patterns:
        for match in re.findall(pattern, content):
            if len(match) > 1 and isinstance(match, tuple):
                spec, source = match[0], match[1]
            elif isinstance(match, tuple):
                spec, source = "", match[0]
            else:
                spec, source = "", match
            imports.append({"source": source, "specifiers": [], "raw": (spec + source).strip()})
    return imports


def extract_exports(content):
    exports = []
    patterns = [
        (r"export\s+default\s+(\w+)", "default"),
        (r"export\s+(?:const|let|var|function|class)\s+(\w+)", "named"),
        (r"export\s*\{\s*([^}]+)\s*\}", "named"),
    ]
    for pattern, kind in patterns:
        for match in re.findall(pattern, content):
            exports.append({"kind": kind, "name": match.strip()})
    return exports
