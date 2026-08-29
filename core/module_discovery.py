"""Layered JavaScript module/script reference discovery.

The old discovery relied on a growing set of regular expressions
(``import(...)``, ``require(...)``, ``chunk-...``, ``/static/js/`` ...).  Those
patterns eventually miss bundler-specific loaders.  This module implements the
layered approach recommended in the accuracy review:

  * **Layer 1 — AST/module understanding.** When the source parses, extract
    ``ImportDeclaration`` sources, dynamic ``ImportExpression`` / ``import()``
    arguments and ``require(...)`` literals directly from the syntax tree.
    This is exact and does not depend on file-name conventions.

  * **Layer 2 — Bundler adapters.** Lightweight signatures for the common
    bundlers (Webpack chunk maps, Vite/Rollup preloads, Next.js, Parcel,
    generic ``chunk-*``/hashed asset names) cover assets referenced through
    loader objects rather than import statements.

  * **Layer 3 — Runtime.** Dynamically injected/lazy scripts are discovered by
    the Playwright runtime pass (see ``core.runtime_evidence``); that remains
    the source of truth for scripts only reachable after execution.

Only *script-like* references are returned.  Arbitrary ``fetch('/api/...')``
strings and JSON/CSS/font imports are filtered out by the same policy the
regex layer used.
"""
import os
import re
from typing import List, Set

from core.js_parser import parse_raw

# ---------------------------------------------------------------------------
# Layer 2 — bundler signatures
# ---------------------------------------------------------------------------
_BUNDLER_ASSET_PATTERNS = [
    # Webpack runtime chunk maps: e.g. {123:"chunk-name", ...} + ".js"
    r"""['"]([^'"]*chunk-?[A-Za-z0-9_.-]*\.[a-f0-9]{6,}\.js)['"]""",
    r"""['"]([^'"]*chunk-[A-Za-z0-9_.-]+\.js)['"]""",
    # Vite / Rollup / generic hashed assets under assets/ or /static/js/.
    r"""['"]([^'"]*(?:/?assets/|/static/js/|/_next/static/chunks/|static/chunks/|/dist/js/)[^'"]*\.js)['"]""",
    # Next.js chunk references.
    r"""['"]([^'"]*(?:_next/static/chunks|static/chunks)/[^'"]+\.js)['"]""",
    # Absolute/root-relative .js/.mjs URLs.
    r"""(?:https?:)?//[^\s'"<>()\\]+\.m?js(?:[?#][^\s'"<>()\\]*)?""",
    r"""['"](/?[A-Za-z0-9_./-]+\.mjs)['"]""",
]

_NON_SCRIPT_EXT = (".json", ".css", ".scss", ".less", ".map", ".wasm",
                   ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2",
                   ".ttf", ".eot", ".mp4", ".webp", ".ico")

_BUNDLER_HINTS = ("chunk-", "/static/js/", "/assets/", "_next/", "static/chunks", ".chunk.")


def _is_script_ref(ref: str) -> bool:
    """True only for script/module-like references (never arbitrary API paths)."""
    ref = str(ref or "").strip().strip("'\"")
    if not ref:
        return False
    no_query = ref.split("?")[0].split("#")[0]
    low = no_query.lower()
    if low.endswith(_NON_SCRIPT_EXT):
        return False
    if re.search(r"\.(?:js|mjs|cjs)$", low):
        return True
    # Explicit relative ES-module imports (./foo, ../foo/bar) may be
    # extensionless. Root-relative "/api/..." paths are NOT modules: they are
    # server endpoints, so require an explicit "./" or "../" prefix here.
    if ref.startswith(("./", "../")) and "." not in os.path.basename(no_query):
        return True
    if any(hint in ref for hint in _BUNDLER_HINTS):
        return True
    return False


def _ast_module_refs(content: str) -> List[str]:
    """Layer 1: exact import/require sources from the AST."""
    refs: Set[str] = set()
    tree = parse_raw(content)
    if tree is None:
        return []

    def visit(node):
        if isinstance(node, list):
            for child in node:
                visit(child)
            return
        if not isinstance(node, dict):
            return
        ntype = node.get("type")
        if ntype == "ImportDeclaration" or ntype == "ExportAllDeclaration":
            src = (node.get("source") or {})
            if isinstance(src, dict) and src.get("value"):
                refs.add(str(src["value"]))
        elif ntype == "ExportNamedDeclaration":
            src = node.get("source")
            if isinstance(src, dict) and src.get("value"):
                refs.add(str(src["value"]))
        elif ntype == "ImportExpression":
            # dynamic import("x")
            src = node.get("source")
            if isinstance(src, dict) and src.get("type") == "Literal" and src.get("value"):
                refs.add(str(src["value"]))
        elif ntype == "CallExpression":
            callee = node.get("callee") or {}
            is_require = callee.get("type") == "Identifier" and callee.get("name") == "require"
            is_import = callee.get("type") == "Import"
            if is_require or is_import:
                args = node.get("arguments", []) or []
                if args and isinstance(args[0], dict):
                    arg = args[0]
                    # String literal argument; template/variable loads are left
                    # to the bundler layer.
                    if arg.get("type") == "Literal" and arg.get("value"):
                        refs.add(str(arg["value"]))
        for value in node.values():
            if isinstance(value, (list, dict)):
                visit(value)

    visit(tree)
    return [r for r in refs if _is_script_ref(r)]


def _bundler_refs(content: str) -> List[str]:
    """Layer 2: bundler-specific asset references the AST cannot express."""
    refs: Set[str] = set()
    for pattern in _BUNDLER_ASSET_PATTERNS:
        for match in re.findall(pattern, content):
            ref = str(match).strip().strip("'\"")
            if ref:
                refs.add(ref)
    return [r for r in refs if _is_script_ref(r)]


def discover_module_refs(content: str) -> List[str]:
    """Return script-like module references using AST first, bundlers second.

    The result is de-duplicated and sorted for stable ordering.  Non-script
    references (API paths, JSON/CSS/font imports) are filtered out.
    """
    content = content or ""
    refs: Set[str] = set()
    refs.update(_ast_module_refs(content))
    # Layer 2 always runs as well: Webpack chunk maps and runtime loaders refer
    # to assets through object literals, not import statements.
    refs.update(_bundler_refs(content))
    return sorted(r.split("#")[0] for r in refs if r)
