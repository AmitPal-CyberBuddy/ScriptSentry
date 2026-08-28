"""Source-to-sink taint analysis for client-side JavaScript.

This is deliberately pragmatic: it uses the AST when available (fast, precise)
and a line-based regex fallback for highly minified or syntax-heavy bundles.

Design goals from the review, applied with care:
  * Distinguish a *dangerous coding pattern* from an *actual data flow*.
  * Report source(s), sink, transformation/sanitization, and status.
  * Prefer low false positives: taint only propagates from explicit sources
    (URL, fragment, postMessage, storage, cookies, user/input fields) and
    through variable assignments and concatenation.
  * Track common sanitizers so we can mark a flow as sanitized/informational
    instead of adding a false "confirmed" finding.
"""
import re
from dataclasses import dataclass, field

from core.js_parser import parse_raw

# ---------------------------------------------------------------------------
# Source / sink catalog
# ---------------------------------------------------------------------------
SOURCE_PATTERNS = {
    "location.search": "URL query string",
    "url.search": "URL query string",
    "searchParams": "URL search params",
    "location.hash": "URL fragment",
    "url.hash": "URL fragment",
    "location.href": "full URL",
    "window.location": "full URL",
    "document.referrer": "referrer",
    "event.data": "postMessage/window message data",
    "e.data": "postMessage/window message data",
    "message.data": "postMessage/window message data",
    "localStorage": "localStorage",
    "sessionStorage": "sessionStorage",
    "document.cookie": "document.cookie",
    "window.name": "window.name",
    "location": "location object",
    "innerText": "DOM text content",
    "value": "form/input value",
}

DANGEROUS_SINK_ASSIGN = {
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "srcdoc",
    "href",
    "src",
}

DANGEROUS_SINK_CALL_KEYWORDS = {
    "eval",
    "Function",
    "setTimeout",
    "setInterval",
    "document.write",
    "document.writeln",
    "insertAdjacentHTML",
    "replace",
    "assign",
    "open",
    "postMessage",
    "html",
    "append",
    "dangerouslySetInnerHTML",
}

SANITIZER_HINTS = (
    "sanitize", "_sanitize", "escapehtml", "escape_html", "htmlencode",
    "encodeuricomponent", "encodeuri", "textcontent", "createtextnode",
    "dopurify", "stringreplace", "xss", "deburr", "striptags",
)


def _node_kind_str(node):
    return node.get("type") if isinstance(node, dict) else None


def _name(node):
    if not isinstance(node, dict):
        return None
    return node.get("name") or node.get("value") or node.get("raw")


def _is_identifier(node, name=None):
    if not isinstance(node, dict) or node.get("type") != "Identifier":
        return False
    return name is None or node.get("name") == name


def _is_literal(node):
    if not isinstance(node, dict):
        return False
    return node.get("type") in ("Literal", "StringLiteral", "TemplateLiteral")


def _is_sanitizer_call(name):
    if not name:
        return False
    lower = name.lower()
    return any(hint in lower for hint in SANITIZER_HINTS)


def _sanitize_transform(label):
    return label


@dataclass
class _Taint:
    sources: list = field(default_factory=list)
    sanitized: bool = False
    path: list = field(default_factory=list)
    confidence: str = "medium"

    def copy(self):
        return _Taint(list(self.sources), self.sanitized, list(self.path), self.confidence)

    def merge(self, other):
        for source in other.sources:
            if source not in self.sources:
                self.sources.append(source)
        if other.sanitized:
            self.sanitized = True
        for step in other.path:
            if step not in self.path:
                self.path.append(step)
        self.confidence = _max_confidence(self.confidence, other.confidence)


def _max_confidence(a, b):
    order = {"low": 0, "medium": 1, "high": 2}
    return a if order.get(a, 0) >= order.get(b, 0) else b


def _line(node):
    if not isinstance(node, dict):
        return 0
    return (node.get("loc") or {}).get("start", {}).get("line", 0)


def _node_text(node, content):
    if not node or not isinstance(node, dict):
        return ""
    rng = node.get("range")
    if rng and len(rng) == 2:
        return content[rng[0]:rng[1]]
    return _name(node) or node.get("type", "")


class TaintAnalyzer:
    def __init__(self, content, filename="inline.js"):
        self.content = content
        self.filename = filename
        self.vars = {}
        self.urlsearch_vars = set()
        self.findings = []
        self._seen = set()

    # ---------------- source extraction ----------------
    def _strip_calls(self, expr):
        """Return a compact text representation used for source classification."""
        expr = expr or {}
        ntype = _node_kind_str(expr)

        if ntype == "Identifier":
            return expr.get("name", "")
        if ntype in ("MemberExpression", "ChainExpression", "OptionalMemberExpression"):
            if ntype == "ChainExpression":
                return self._strip_calls(expr.get("expression", {}))
            obj = expr.get("object")
            prop = expr.get("property")
            obj_txt = self._strip_calls(obj) if isinstance(obj, dict) else str(obj)
            if prop is None:
                return obj_txt
            if isinstance(prop, dict):
                prop_type = _node_kind_str(prop)
                if prop_type == "Identifier":
                    prop_txt = prop.get("name", "")
                else:
                    # computed: look for a literal key
                    prop_txt = _name(prop) or self._node_simple_text(prop)
            else:
                prop_txt = str(prop)
            return f"{obj_txt}.{prop_txt}"
        if ntype == "CallExpression":
            callee = self._strip_calls(expr.get("callee", {}))
            args = expr.get("arguments", []) or []
            arg_texts = [self._node_simple_text(a) for a in args[:2]]
            return f"{callee}({','.join(a for a in arg_texts if a)})"
        if ntype == "Literal":
            return str(expr.get("value", ""))
        if ntype == "BinaryExpression":
            left = self._strip_calls(expr.get("left", {}))
            right = self._strip_calls(expr.get("right", {}))
            return f"{left}+{right}"
        if ntype == "TemplateLiteral":
            return "".join(
                self._node_simple_text(part) for part in expr.get("expressions", []) or []
            ) or "template"
        return _name(expr) or _node_kind_str(expr) or ""

    def _node_simple_text(self, node):
        if not isinstance(node, dict):
            return ""
        if _node_kind_str(node) == "Identifier":
            return node.get("name", "")
        if _node_kind_str(node) == "Literal":
            return str(node.get("value", ""))
        return self._strip_calls(node)

    # ---------------- expression taint ----------------
    def _taint_of_expr(self, node, depth=0):
        """Return _Taint describing data entering ``node``, or None."""
        if depth > 24 or node is None or not isinstance(node, dict):
            return None
        ntype = _node_kind_str(node)

        # Identifier -> look up tracked vars
        if ntype == "Identifier":
            name = node.get("name")
            if name in self.vars:
                return self.vars[name].copy()
            # Conservative source: common input-ish identifiers.
            if name and re.fullmatch(r"(userInput|user_input|input|data|payload|param|query|value|userData|msg|message|payloadData)", name, re.I):
                return _Taint([f"identifier:{name}"], False, [f"read {name}"], "medium")
            if name == "URLSearchParams":
                return None
            return None

        # String/number literals are not tainted unless combined with taint.
        if _node_kind_str(node) in ("Literal", "StringLiteral"):
            return None

        # Template literal -> combine parts
        if ntype == "TemplateLiteral":
            combined = _Taint()
            for expr in node.get("expressions", []) or []:
                t = self._taint_of_expr(expr, depth + 1)
                if t:
                    combined.merge(t)
            return combined if combined.sources else None

        # Binary expression (typically + concatenation)
        if ntype == "BinaryExpression":
            left = self._taint_of_expr(node.get("left"), depth + 1)
            right = self._taint_of_expr(node.get("right"), depth + 1)
            if left and right:
                combined = left.copy()
                combined.merge(right)
                return combined
            return left or right

        # Member expression sources (location/search, storage, cookie, value...)
        if ntype in ("MemberExpression", "ChainExpression"):
            callee_txt = self._strip_calls(node).lower()
            for marker, source_label in SOURCE_PATTERNS.items():
                if marker in callee_txt:
                    return _Taint([f"source:{source_label}"], False, [f"read {callee_txt}"], "high")
            # A member access on a tracked object should propagate taint.
            obj = node.get("object") if ntype == "MemberExpression" else (node.get("expression") or {}).get("object")
            if isinstance(obj, dict):
                obj_taint = self._taint_of_expr(obj, depth + 1)
                if obj_taint:
                    return obj_taint
            return None

        # New URLSearchParams(...) -> URL source object
        if ntype == "NewExpression":
            callee = node.get("callee", {})
            callee_name = _name(callee)
            if callee_name == "URLSearchParams":
                return _Taint(["source:URL search params"], False, [f"new URLSearchParams"], "high")
            return None

        # Call expressions -> detect source getters / sanitizers / sinks
        if ntype in ("CallExpression", "OptionalCallExpression"):
            callee_txt = self._strip_calls(node.get("callee", {}))
            lower = callee_txt.lower()

            # source getters
            if any(marker in lower for marker in ("searchparams.get", "searchparams.getall", "getitem", "cookie", "referrer", ".get", ".getall")):
                source_label = {
                    "searchparams": "URL search params",
                    "getitem": "browser storage",
                    "cookie": "document.cookie",
                    "referrer": "document.referrer",
                }
                label = next((v for k, v in source_label.items() if k in lower), "URL search params")
                return _Taint([f"source:{label}"], False, [f"read {callee_txt}"], "high")

            # URLSearchParams object getters (u.get('next'), params.get('x'))
            obj_name = callee_txt.split(".")[0] if "." in callee_txt else callee_txt
            if lower.endswith(".get") or lower.endswith(".getall"):
                if obj_name in self.urlsearch_vars or lower.startswith("urlsearchparams"):
                    return _Taint(["source:URL search params"], False, [f"read {callee_txt}"], "high")
                obj_taint = self.vars.get(obj_name)
                if obj_taint:
                    return obj_taint.copy()
            if "postmessage" in lower or lower.endswith(".data"):
                return _Taint(["source:postMessage data"], False, [f"read {callee_txt}"], "high")
            if _is_sanitizer_call(callee_txt):
                args = node.get("arguments", []) or []
                inner = self._taint_of_expr(args[0] if args else node, depth + 1)
                if inner:
                    result = inner.copy()
                    result.sanitized = True
                    result.path.append(f"sanitize {callee_txt}")
                    result.confidence = "low"
                    return result
            # Propagate taint from function arguments? Only for known pass-through
            # helpers is safe; avoid broad propagation to reduce false positives.
            return None

        # CallExpression-like member flows (already handled above)
        return None

    # ---------------- sink checks ----------------
    def _record(self, finding):
        key = (
            finding.get("id"),
            finding.get("source", ""),
            finding.get("sink", ""),
            finding.get("line", 0),
        )
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(finding)

    def _record_sink(self, sink_type, node, taint, extra=None):
        if not taint or not taint.sources:
            return
        sanitized = bool(taint.sanitized)
        if sanitized:
            severity = "LOW"
            confidence = "low"
            status = "informational"
        else:
            severity = extra.get("severity", "HIGH") if extra else "HIGH"
            confidence = taint.confidence or "medium"
            status = "confirmed" if confidence == "high" else "potential"
        sources = [s.replace("source:", "") for s in taint.sources]
        self._record({
            "id": extra.get("id", sink_type) if extra else sink_type,
            "type": extra.get("type", sink_type) if extra else sink_type,
            "severity": severity,
            "confidence": confidence,
            "status": status,
            "file": self.filename,
            "line": _line(node),
            "source": " → ".join(sources),
            "sink": _node_text(node, self.content)[:160] or sink_type,
            "flow": list(dict.fromkeys(taint.path))[:12],
            "sanitization_detected": sanitized,
            "evidence": _node_text(node, self.content)[:240],
        })

    def _check_call_sink(self, node):
        ntype = _node_kind_str(node)
        if ntype not in ("CallExpression", "OptionalCallExpression", "NewExpression"):
            return
        if ntype == "NewExpression":
            callee = node.get("callee", {})
            name = _name(callee) or ""
            if name.lower() == "function":
                args = node.get("arguments", []) or []
                taint = self._taint_of_expr(args[0]) if args else None
                if taint:
                    self._record_sink("dangerous_dynamic_code", node, taint, {
                        "id": "dangerous_dynamic_code",
                        "type": "Dangerous dynamic code execution",
                        "severity": "HIGH",
                    })
            return
        callee = self._strip_calls(node.get("callee", {}))
        lower = callee.lower()

        # postMessage target-origin
        if "postmessage" in lower:
            args = node.get("arguments", []) or []
            target = self._node_simple_text(args[1]) if len(args) > 1 else ""
            taint = self._taint_of_expr(args[0] if args else {})
            target_origin = str(target).strip("'\"")
            if target_origin in ("*", ""):
                # Wildcard targetOrigin is risky even before we know what the payload is.
                self._record_sink("insecure_postmessage", node, taint or _Taint(["postMessage data"], False, [], "medium"), {
                    "id": "insecure_postmessage",
                    "type": "Insecure postMessage",
                    "severity": "MEDIUM",
                    "extra_text": f"targetOrigin='{target_origin}'",
                })
            elif taint:
                self._record_sink("postmessage_with_origin", node, taint, {
                    "id": "postmessage_with_origin",
                    "type": "postMessage cross-origin",
                    "severity": "LOW",
                })
            return

        # String-based dynamic execution / DOM sinks.
        # Keep this source-to-sink: a bare `eval("...")` is still a risky pattern
        # (the scanner's `unsafe_runtime` risk signal covers it), but a data flow
        # should only be claimed when tainted input reaches the sink (or a template
        # literal interpolation does).
        if lower in ("eval", "function") or any(k in lower for k in ("eval(", "new function", "function(", "settimeout(", "setinterval(")):
            args = node.get("arguments", []) or []
            if args:
                arg = args[0]
                taint = self._taint_of_expr(arg)
                dynamic_code = bool(arg and _node_kind_str(arg) == "TemplateLiteral" and arg.get("expressions"))
                if taint or dynamic_code:
                    self._record_sink("dangerous_dynamic_code", node, taint or _Taint(["source:template${{}}"], False, [], "low"), {
                        "id": "dangerous_dynamic_code",
                        "type": "Dangerous dynamic code execution",
                        "severity": "HIGH",
                    })
            return

        if "document.write" in lower or "document.writeln" in lower:
            args = node.get("arguments", []) or []
            self._record_sink("dom_injection_document_write", node, self._taint_of_expr(args[0]) if args else None, {
                "id": "dom_injection",
                "type": "DOM injection",
                "severity": "HIGH",
            })
            return

        if "insertadjacenthtml" in lower or ".html(" in lower or ".append(" in lower:
            args = node.get("arguments", []) or []
            taint = self._taint_of_expr(args[-1] if args else {})
            self._record_sink("dom_injection", node, taint, {
                "id": "dom_injection",
                "type": "DOM injection",
                "severity": "HIGH",
            })
            return

        # location assign/replace/open -> open redirect
        if lower.endswith(".assign(") or lower.endswith(".replace(") or lower.endswith(".open("):
            args = node.get("arguments", []) or []
            taint = self._taint_of_expr(args[0] if args else {})
            if taint:
                self._record_sink("open_redirect", node, taint, {
                    "id": "open_redirect",
                    "type": "Client-side open redirect",
                    "severity": "HIGH",
                })
            return

    def _check_assignment_sink(self, node):
        if _node_kind_str(node) != "AssignmentExpression":
            return
        left = node.get("left", {})
        right = node.get("right", {})
        left_txt = self._strip_calls(left).lower()
        prop = left.get("property") if isinstance(left, dict) else None
        prop_name = _name(prop) if isinstance(prop, dict) else None

        if any(k in left_txt for k in ("innerhtml", "outerhtml", "srcdoc", "document.write", "location.href", "location", "window.location", "document.domain", "dangerouslysetinnerhtml")):
            # open redirect assignment
            if "location" in left_txt and ("href" in left_txt or left_txt.endswith("location")):
                self._record_sink("open_redirect", node, self._taint_of_expr(right), {
                    "id": "open_redirect",
                    "type": "Client-side open redirect",
                    "severity": "HIGH",
                })
                return
            self._record_sink("dom_injection", node, self._taint_of_expr(right), {
                "id": "dom_injection",
                "type": "DOM injection",
                "severity": "HIGH",
            })
            return

        # prototype pollution
        if "__proto__" in left_txt or "constructor.prototype" in left_txt or ("object.assign" in left_txt and re.search(r"__proto__|prototype", content_low)):
            self._record_sink("prototype_pollution", node, self._taint_of_expr(right) or _Taint(["source:dynamic"], False, [], "low"), {
                "id": "prototype_pollution",
                "type": "Prototype pollution",
                "severity": "MEDIUM",
            })
            return

    # ---------------- scope / statements ----------------
    def _handle_variable_declaration(self, node):
        for decl in node.get("declarations", []) or []:
            init = decl.get("init")
            if not init:
                continue
            name = _name(decl.get("id"))
            if not name:
                continue
            taint = self._taint_of_expr(init)
            if taint:
                taint = taint.copy()
                taint.path.append(f"var {name} = {self._node_simple_text(init)[:60]}")
                self.vars[name] = taint
            if _node_kind_str(init) == "NewExpression" and _name(init.get("callee")) == "URLSearchParams":
                self.urlsearch_vars.add(name)

    def _handle_assignment(self, node):
        left = node.get("left", {})
        right = node.get("right", {})
        if _node_kind_str(left) != "Identifier":
            # sink checks first, then object-member assignments that are not sinks
            self._check_assignment_sink(node)
            return
        name = left.get("name")
        taint = self._taint_of_expr(right)
        if taint:
            taint = taint.copy()
            taint.path.append(f"{name} = {self._node_simple_text(right)[:60]}")
            self.vars[name] = taint

    def analyze(self):
        tree = parse_raw(self.content)
        if tree is None:
            self._regex_analyze()
            return self.findings

        # Two passes: first assignments so reads later see taint, then sink checks.
        statements = tree.get("body", []) or []
        for stmt in statements:
            self._walk(stmt, self._handle_variable_declaration)
        for stmt in statements:
            self._walk(stmt, self._handle_assignment)
        for stmt in statements:
            self._walk(stmt, self._check_call_sink)
            self._walk(stmt, self._check_assignment_sink)

        # If AST parsed but found no flows, only run the regex fallback when the code
        # actually has a taint source. A bare `eval("...")` is a pattern the scanner's
        # `unsafe_runtime` risk signal already covers, not a source-to-sink flow.
        if not self.findings and self._has_obvious_dangerous_patterns() and self._has_source_like_pattern():
            self._regex_analyze()
        return self.findings

    def _walk(self, node, callback):
        if node is None:
            return
        if isinstance(node, list):
            for child in node:
                self._walk(child, callback)
            return
        if not isinstance(node, dict):
            return
        callback(node)
        for value in node.values():
            if isinstance(value, (list, dict)):
                self._walk(value, callback)

    # ---------------- fallback / heuristics ----------------
    def _has_obvious_dangerous_patterns(self):
        return bool(re.search(r"\b(innerHTML\s*=|\beval\s*\(|new\s+Function|location\.(href|assign|replace)|postMessage\s*\([^)]*,\s*['\"]\*['\"]|\.html\s*\(|v-html|dangerouslySetInnerHTML)", self.content, re.I))

    def _has_source_like_pattern(self):
        markers = [k.lower() for k in SOURCE_PATTERNS if k.lower() not in ("value", "innertext")]
        source_re = "|".join(re.escape(m) for m in markers)
        return bool(re.search(source_re, self.content, re.I)) or bool(
            re.search(r"\b(?:userInput|user_input|input|data|payload|param|query|userData|msg|message)\b", self.content, re.I)
        )

    def _regex_analyze(self):
        lines = self.content.splitlines()
        # Track tainted vars from source reads.
        tainted = set()
        for i, line in enumerate(lines, 1):
            for source_re, label in [
                (r"\b(?:location\.search|url\.search|location\.hash|location\.href|document\.referrer|window\.location)\b", "URL"),
                (r"new\s+URLSearchParams\(|\.searchParams\.get\s*\(", "URL params"),
                (r"(?:event|e|msg)\.data\b", "postMessage"),
                (r"localStorage\.getItem\(|sessionStorage\.getItem\(|document\.cookie", "storage"),
                (r"\.value\b", "user input"),
            ]:
                if re.search(source_re, line, re.I):
                    # capture assignment target
                    m = re.search(r"(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*.*" + source_re, line)
                    if m:
                        tainted.add(m.group(1))
                    elif re.search(r"\b(?:return|\(|[,=])", line):
                        m2 = re.search(r"\b([A-Za-z_$][\w$]*)\s*=", line)
                        if m2:
                            tainted.add(m2.group(1))

        for i, line in enumerate(lines, 1):
            low = line.lower()
            # assignment sinks
            m_sink = None
            if re.search(r"\binnerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|insertAdjacentHTML\s*\(|eval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*['\"]|setInterval\s*\(\s*['\"]", line, re.I):
                srcs = [v for v in tainted if v in line]
                dynamic = bool(re.search(r"\b(?:innerHTML|eval|Function|document\.write|insertAdjacentHTML)\b", line, re.I))
                self._record({
                    "id": "dangerous_pattern", "type": "Dangerous DOM/dynamic pattern", "severity": "HIGH" if dynamic else "MEDIUM",
                    "confidence": "medium", "status": "confirmed" if srcs else "potential", "file": self.filename, "line": i,
                    "source": " → ".join(srcs) or "unknown", "sink": line.strip()[:120], "flow": srcs[:6],
                    "sanitization_detected": any(h in low for h in SANITIZER_HINTS),
                    "evidence": line.strip()[:240],
                })
            # open redirect
            if re.search(r"\blocation\.(?:href|assign|replace)\s*(?:=|\()", line, re.I):
                srcs = [v for v in tainted if v in line]
                self._record({
                    "id": "open_redirect", "type": "Client-side open redirect", "severity": "HIGH",
                    "confidence": "high" if srcs else "medium", "status": "confirmed" if srcs else "potential",
                    "file": self.filename, "line": i, "source": " → ".join(srcs) or "unknown",
                    "sink": line.strip()[:120], "flow": srcs[:6], "sanitization_detected": any(h in low for h in SANITIZER_HINTS),
                    "evidence": line.strip()[:240],
                })
            # postMessage '*'
            m = re.match(r"\s*([^#]+?)\s*postMessage\s*\(", line, re.I)
            if re.search(r"postMessage\s*\([^)]*,\s*['\"]\*['\"]", line, re.I):
                self._record({
                    "id": "insecure_postmessage", "type": "Insecure postMessage", "severity": "MEDIUM", "confidence": "medium",
                    "status": "potential", "file": self.filename, "line": i, "source": "message data", "sink": line.strip()[:120],
                    "flow": [], "sanitization_detected": False, "evidence": line.strip()[:240],
                })
            # prototype pollution
            if re.search(r"(?:__proto__|constructor\.prototype|Object\.assign\s*\([^)]*(?:__proto__|prototype))", line, re.I):
                self._record({
                    "id": "prototype_pollution", "type": "Prototype pollution", "severity": "MEDIUM", "confidence": "medium",
                    "status": "potential", "file": self.filename, "line": i, "source": "dynamic input", "sink": line.strip()[:120],
                    "flow": [], "sanitization_detected": False, "evidence": line.strip()[:240],
                })


content_low = ""


def analyze_taint(content, filename="inline.js"):
    """Public entrypoint: return source-to-sink data-flow findings."""
    global content_low
    content_low = content or ""
    analyzer = TaintAnalyzer(content or "", filename=filename)
    return analyzer.analyze()
