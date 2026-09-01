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

# The source/sink catalogue lives in core.js_patterns so that the taint engine
# and the analyzers can never disagree about what counts as a sink.  The names
# are re-exported here because callers import them from core.taint.
from core.js_patterns import (  # noqa: F401  (re-exported)
    DANGEROUS_SINK_ASSIGN,
    DANGEROUS_SINK_CALL_KEYWORDS,
    DOM_SINK_PATTERNS,
    SANITIZER_HINTS,
    SENSITIVE_READ_RE,
    SOURCE_PATTERNS,
)

# ---------------------------------------------------------------------------
# Source / sink catalog
# ---------------------------------------------------------------------------

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


def _is_static_value(node):
    """True when ``node`` is a value the engine can prove is constant.

    Literals, constant template literals (no interpolation), and literal
    arrays/objects are static.  A variable with a static value must not be
    treated as user input by the by-name identifier heuristic.
    """
    if not isinstance(node, dict):
        return False
    ntype = node.get("type")
    if ntype in ("Literal", "StringLiteral", "NumericLiteral", "BooleanLiteral", "NullLiteral"):
        return True
    if ntype == "TemplateLiteral":
        return not (node.get("expressions") or [])
    if ntype in ("ArrayExpression", "ObjectExpression"):
        values = node.get("elements", []) if ntype == "ArrayExpression" else [
            prop.get("value") for prop in (node.get("properties") or [])
            if isinstance(prop, dict) and prop.get("type") == "Property"
        ]
        return all(_is_static_value(v) for v in values if v is not None)
    if ntype == "UnaryExpression":
        return _is_static_value(node.get("argument"))
    return False


def _is_sanitizer_call(name):
    if not name:
        return False
    lower = name.lower()
    return any(hint in lower for hint in SANITIZER_HINTS)


# A `.value` read is only attacker-reachable when it comes off a real
# form/DOM element: querySelector(...).value, getElementById(...).value,
# form.elements.x.value, this.value in an event handler.  Any other `.value`
# (config.value, state.value, props.value) is application data, not input.
_FORM_VALUE_OBJECT_RE = re.compile(
    r"(?:^|\.)(?:form|input|textarea|select|option|elements|target|currenttarget)\b",
    re.I,
)


def _is_form_value_read(callee_txt: str) -> bool:
    if not callee_txt.endswith(".value"):
        return False
    if callee_txt == "this.value":
        # Inline event handlers read this.value off the form element; this is
        # ambiguous outside that context, so keep it but at the caller's
        # standard (medium/high) confidence.
        return True
    head = callee_txt[:-6]  # strip the trailing ".value"
    return bool(
        re.search(r"queryselector|getelementbyid|getelementsby(?:class|tag)name", head)
        or _FORM_VALUE_OBJECT_RE.search(head)
    )


# Property reads that always yield numbers.  A number cannot become markup,
# executable code or a navigation payload, so taint stops at these reads
# (`q.length` of a tainted string is not a DOM-injection primitive).
_NUMERIC_PROPS = frozenset({
    "length", "size", "count", "index", "selectedindex",
    "offsetwidth", "offsetheight", "clientwidth", "clientheight",
    "scrollwidth", "scrollheight", "duration", "currenttime", "timestamp",
})


# Data that is worth stealing.  Exfiltration findings are gated on this: a
# URL/query/fragment source reflected into a request is normal client
# behaviour (search, pagination, sharing), while cookies, storage, tokens
# and credentials leaving the page is always worth a HIGH finding.
SENSITIVE_SOURCE_RE = re.compile(
    r"cookie|storage|token|credential|password|secret|session|useragent",
    re.I,
)


def _sanitize_transform(label):
    return label


@dataclass
class _Taint:
    sources: list = field(default_factory=list)
    sanitized: bool = False
    path: list = field(default_factory=list)
    confidence: str = "medium"
    limitations: list = field(default_factory=list)

    def copy(self):
        return _Taint(list(self.sources), self.sanitized, list(self.path), self.confidence, list(self.limitations))

    def merge(self, other):
        for source in other.sources:
            if source not in self.sources:
                self.sources.append(source)
        if other.sanitized:
            self.sanitized = True
        for step in other.path:
            if step not in self.path:
                self.path.append(step)
        for note in getattr(other, "limitations", []) or []:
            if note not in self.limitations:
                self.limitations.append(note)
        self.confidence = _max_confidence(self.confidence, other.confidence)

    def limit(self, note):
        """Record an analysis limitation and lower confidence accordingly.

        Advanced JS taint analysis cannot model every construct; being honest
        about *what did not resolve* (dynamic property access, an unknown
        third-party function, a callback boundary) makes the finding
        transparent instead of overclaiming.
        """
        if note not in self.limitations:
            self.limitations.append(note)
        # A flow that crosses a construct the engine cannot model is never
        # stronger than medium confidence.
        if self.confidence == "high":
            self.confidence = "medium"


def _max_confidence(a, b):
    order = {"low": 0, "medium": 1, "high": 2}
    return a if order.get(a, 0) >= order.get(b, 0) else b


def min_confidence(conf, ceiling="medium"):
    """Cap confidence for line-based heuristic flows (never claim high)."""
    order = {"low": 0, "medium": 1, "high": 2}
    conf = conf if conf in order else "low"
    return conf if order[conf] <= order[ceiling] else ceiling


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
        self.props = {}
        self.functions = {}
        self.urlsearch_vars = set()
        # Identifiers bound to statically-known values (literals, constant
        # expressions).  The by-name identifier heuristic must never fire for
        # these: `const input = 'welcome'` is not user input.
        self.known_static = set()
        self.findings = []
        self._seen = set()
        self._func_depth = 0
        # Analysis-quality bookkeeping: which constructs did we fail to model?
        self.limitations = []
        self.ast_used = False

    def _note_limitation(self, note):
        if note not in self.limitations:
            self.limitations.append(note)

    def _quality(self):
        """Overall analysis quality for this document.

        ``high``   = AST parsed and the propagation path resolved cleanly
        ``medium`` = AST parsed but a construct could not be fully modeled
        ``heuristic`` = AST unavailable; line/regex fallback only
        """
        if not self.ast_used:
            return "heuristic"
        return "medium" if self.limitations else "high"

    def _finding_limitations(self, taint, extra=None):
        notes = list(getattr(taint, "limitations", []) or [])
        for note in extra or []:
            if note not in notes:
                notes.append(note)
        # Document-level limitations apply to every flow (e.g. parser fallback).
        if not self.ast_used:
            note = "AST parser unavailable; flow derived from line-based heuristics."
            if note not in notes:
                notes.append(note)
        return notes[:8]

    # ---------------- source extraction ----------------
    def _strip_calls(self, expr):
        """Return a compact text representation used for source classification."""
        expr = expr or {}
        ntype = _node_kind_str(expr)

        if ntype == "Identifier":
            return expr.get("name", "")
        if ntype == "ThisExpression":
            return "this"
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
        if ntype == "NewExpression":
            callee = self._strip_calls(expr.get("callee", {}))
            args = expr.get("arguments", []) or []
            arg_texts = [self._node_simple_text(a) for a in args[:2]]
            return f"new {callee}({','.join(a for a in arg_texts if a)})"
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
            # A name bound to a statically-known value (a literal or a
            # constant expression) is not input, whatever it is called:
            # `const input = 'welcome'` must not become a taint source.
            if name in self.known_static:
                return None
            # Conservative source: common input-ish identifiers.  This only
            # applies to *unresolved* names (function parameters, globals)
            # whose value the engine could not see; a tracked or static
            # binding above already decided the case.
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

        # Object/array payloads: preserve taint in fetch bodies, headers, and
        # JSON-like structures without treating every object as sensitive.
        if ntype in ("ObjectExpression", "ArrayExpression"):
            combined = None
            values = node.get("properties", []) if ntype == "ObjectExpression" else node.get("elements", [])
            for item in values or []:
                candidate = item.get("value") if isinstance(item, dict) and ntype == "ObjectExpression" else item
                t = self._taint_of_expr(candidate, depth + 1)
                if t:
                    if combined is None:
                        combined = t.copy()
                    else:
                        combined.merge(t)
            return combined

        if ntype in ("AwaitExpression", "UnaryExpression", "ChainExpression"):
            return self._taint_of_expr(node.get("argument") or node.get("expression"), depth + 1)

        # Computed/dynamic property access (obj[x]) cannot be resolved
        # statically; flag it on the tainted value so the reported flow carries
        # the limitation instead of pretending the object model was fully
        # understood.
        if ntype in ("MemberExpression",) and node.get("computed"):
            obj_taint = self._taint_of_expr(node.get("object"), depth + 1)
            if obj_taint and obj_taint.sources:
                prop_node = node.get("property")
                prop_txt = self._node_simple_text(prop_node)
                # A *literal* index is not an unresolved lookup. `location
                # .search.split('=')[1]` is a fully understood expression, and
                # calling it "property resolution incomplete" downgraded one of
                # the most common query-parsing idioms to medium confidence for
                # no reason. Only genuinely dynamic keys (obj[userVar]) are a
                # real gap in the model.
                literal_index = (
                    isinstance(prop_node, dict)
                    and _node_kind_str(prop_node) == "Literal"
                    and isinstance(prop_node.get("value"), (int, str))
                    and not isinstance(prop_node.get("value"), bool)
                )
                if not literal_index:
                    note = (f"Dynamic/computed property access [{prop_txt or '?'}]; "
                            "property resolution incomplete.")
                    obj_taint.limit(note)
                return obj_taint

        # Member expression sources (location/search, storage, cookie, value...)
        if ntype in ("MemberExpression", "ChainExpression"):
            callee_txt = self._strip_calls(node).lower()
            for marker, source_label in SOURCE_PATTERNS.items():
                if marker.lower() == "value" and not _is_form_value_read(callee_txt):
                    # `.value` alone is not a taint source: a static config
                    # object's `value` property (Vue/Pinia state, options,
                    # this.value in a class) is not attacker input.  Only
                    # reads off real form/DOM elements count, matching the
                    # regex fallback's source_specs.
                    continue
                # callee_txt is lower-cased; the catalogue mixes case
                # (localStorage, document.baseURI, history.state), so compare
                # case-insensitively or those sources are never recognized.
                if marker.lower() in callee_txt:
                    return _Taint([f"source:{source_label}"], False, [f"read {callee_txt}"], "high")
            # Track tainted object properties, e.g. `const cfg={q:location.search}; ...cfg.q`.
            obj = node.get("object") if ntype == "MemberExpression" else (node.get("expression") or {}).get("object")
            prop = node.get("property") if ntype == "MemberExpression" else None
            if _node_kind_str(obj) == "Identifier" and isinstance(prop, dict):
                obj_name = obj.get("name")
                prop_name = _name(prop)
                key = f"{obj_name}.{prop_name}"
                if key in self.props:
                    return self.props[key].copy()
            # Numeric property reads (.length, .size, geometry) return numbers
            # and cannot carry markup, code or a navigation payload, so taint
            # stops here instead of flagging `el.innerHTML = q.length`.
            if isinstance(prop, dict) and str(_name(prop) or "").lower() in _NUMERIC_PROPS:
                return None
            # A member access on a tracked object should propagate taint.
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

            # Explicit source getters.  A generic ``client.get()`` is not a
            # browser source and must not become a taint origin.
            if ("searchparams.get" in lower or "searchparams.getall" in lower
                    or "urlsearchparams" in lower and lower.rstrip(")").endswith((".get", ".getall"))):
                return _Taint(["source:URL search params"], False, [f"read {callee_txt}"], "high")
            if "getitem" in lower and ("localstorage" in lower or "sessionstorage" in lower):
                return _Taint(["source:browser storage"], False, [f"read {callee_txt}"], "high")
            # Cookie *reads* (Cookies.get, getCookie, cookieStore.get) are
            # sources; cookie *writes* (Cookies.set, setCookie) write data and
            # must not taint their return value as though it had been read
            # from the jar. document.cookie reads are handled by the
            # member-expression branch via SOURCE_PATTERNS.
            if "cookie" in lower and ("get" in lower or "read" in lower):
                return _Taint([f"source:document.cookie"], False, [f"read {callee_txt}"], "high")
            if "referrer" in lower:
                return _Taint(["source:document.referrer"], False, [f"read {callee_txt}"], "high")

            # String reshaping keeps user input user input.
            #
            # `location.hash.substring(1)` is the single most common way a
            # fragment is read (you almost always strip the leading '#'), and
            # treating it as an untracked call meant the textbook DOM-XSS
            # flow degraded to a medium-confidence guess -- or vanished
            # entirely once another flow existed. These methods reshape a
            # string without cleaning it, so taint must survive them, along
            # with the source's own confidence.
            string_transforms = (
                ".substring", ".substr", ".slice", ".trim", ".tolowercase",
                ".touppercase", ".replace", ".replaceall", ".split", ".join",
                ".concat", ".padstart", ".padend", ".normalize", ".at",
                ".charat", ".repeat", ".tostring", ".valueof",
            )
            if lower.endswith(string_transforms):
                # The receiver carries the taint: `<tainted>.substring(1)`.
                callee_node = node.get("callee", {})
                receiver = callee_node.get("object") if isinstance(callee_node, dict) else None
                inherited = self._taint_of_expr(receiver, depth + 1) if receiver else None
                if inherited:
                    result = inherited.copy()
                    result.path.append(f"transform {callee_txt}")
                    # `.replace()` is where sanitization is usually attempted;
                    # flag it as reshaped but do not claim it is safe.
                    return result
                # A tainted *argument* also flows through (e.g. "".concat(x)).
                for arg in node.get("arguments", []) or []:
                    candidate = self._taint_of_expr(arg, depth + 1)
                    if candidate:
                        result = candidate.copy()
                        result.path.append(f"transform {callee_txt}")
                        return result

            # Transparent transforms retain a source for a downstream sink.
            if any(lower.endswith(name) or lower == name for name in ("json.stringify", "encodeuricomponent", "encodeuri", "btoa")):
                combined = None
                for arg in node.get("arguments", []) or []:
                    candidate = self._taint_of_expr(arg, depth + 1)
                    if candidate:
                        combined = candidate.copy() if combined is None else combined
                        if combined is not candidate:
                            combined.merge(candidate)
                return combined

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
            # Unknown call: if a tracked source is passed as an argument we
            # conservatively retain the taint through the call, but at medium
            # confidence with a limitation note so the flow is transparent
            # rather than silently dropped or overclaimed.
            unknown_limitation = f"Return value of unmodeled call '{callee_txt}' is assumed to propagate its arguments."
            tracked_arg = None
            for arg in node.get("arguments", []) or []:
                candidate = self._taint_of_expr(arg, depth + 1)
                if candidate and candidate.sources:
                    tracked_arg = candidate.copy() if tracked_arg is None else tracked_arg
                    if tracked_arg is not candidate:
                        tracked_arg.merge(candidate)
            if tracked_arg:
                tracked_arg.path.append(f"call {callee_txt}(...)")
                tracked_arg.limit(unknown_limitation)
                return tracked_arg
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
        extra = extra or {}
        if sanitized:
            severity = "LOW"
            confidence = "low"
            # Sanitized flows are observations, not vulnerabilities.
            status = "informational"
            observation = True
        else:
            severity = extra.get("severity", "HIGH")
            confidence = taint.confidence or "medium"
            # A static source-to-sink path is strong *evidence* but not proof
            # of an exploitable bug: encoding, framework behavior, an
            # unreachable branch or an unmodeled sanitizer may still neutralize
            # it. So high confidence -> 'open' (actionable), never 'confirmed'.
            observation = bool(extra.get("observation", False))
            status = "informational" if observation else (
                "open" if confidence in ("high", "confirmed") else "needs_review"
            )
        sources = [s.replace("source:", "") for s in taint.sources]
        flow_steps = list(dict.fromkeys(taint.path))[:12]
        limitations = self._finding_limitations(taint, extra.get("limitations"))
        self._record({
            "id": extra.get("id", sink_type),
            "type": extra.get("type", sink_type),
            "severity": severity,
            "confidence": confidence,
            "status": status,
            "file": self.filename,
            "line": _line(node),
            "source": " → ".join(dict.fromkeys(sources)),
            "sink": _node_text(node, self.content)[:160] or sink_type,
            "flow": flow_steps,
            "sanitization_detected": sanitized,
            "evidence": (("sanitized: " if sanitized else "") + _node_text(node, self.content)[:240]).strip(),
            "evidence_type": "source_to_sink",
            "analysis_quality": self._quality() if not limitations or self._quality() != "high" else "medium",
            "limitations": limitations,
            "observation": observation,
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
        callee_node = node.get("callee", {}) or {}
        callee = self._strip_calls(callee_node)
        lower = callee.lower()
        # The method name matters for jQuery-style sinks ($('#x').html(...)):
        # the callee text there carries an argument list that hides it.
        prop_name = None
        if _node_kind_str(callee_node) == "MemberExpression":
            prop = callee_node.get("property")
            prop_name = _name(prop) if isinstance(prop, dict) else None
        method = (prop_name or "").lower()

        # Network sinks are reported only when a tracked source reaches the
        # request URL, body, header, or send() payload.  A bare fetch is an
        # inventory observation, not data exfiltration.
        is_network = lower in ("fetch", "axios", "navigator.sendbeacon", "sendbeacon") or lower.endswith(".send") or lower.endswith(".request")
        if is_network:
            args = node.get("arguments", []) or []
            taint = None
            for arg in args:
                candidate = self._taint_of_expr(arg)
                if candidate:
                    taint = candidate if taint is None else (taint.copy() if not taint else taint)
                    if candidate is not taint:
                        taint.merge(candidate)
            if not taint or not taint.sources:
                return
            source_text = " → ".join(taint.sources)
            # Exfiltration means *sensitive* material (cookies, storage,
            # tokens, credentials) leaving the page.  Reflecting a URL/query
            # parameter into a request is normal client behaviour (search,
            # pagination, sharing) and is not a leak; it only matters when the
            # destination is clearly external, and even then it is a LOW
            # candidate, not a confirmed leak -- consistent with the
            # line-fallback heuristic.
            if SENSITIVE_SOURCE_RE.search(source_text):
                self._record_sink("data_exfiltration_flow", node, taint, {
                    "id": "data_exfiltration_flow",
                    "type": "Sensitive data sent to a network sink",
                    "severity": "HIGH",
                })
            else:
                destination = str(self._node_simple_text(args[0]) if args else "").strip("'\"")
                if re.match(r"^(https?:)?//", destination):
                    self._record_sink("data_exfiltration_candidate", node, taint, {
                        "id": "data_exfiltration_candidate",
                        "type": "URL-derived data sent to an external destination",
                        "severity": "LOW",
                        "observation": True,
                        "limitations": [
                            "Destination is external but the payload is URL-derived data; "
                            "review whether it leaks identifiers to a third party.",
                        ],
                    })
            return

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

        # setAttribute('href'|'src'|'srcdoc', tainted) -- the DOM equivalent of
        # an href/src assignment, and a common way to smuggle a javascript: URL.
        if method == "setattribute":
            args = node.get("arguments", []) or []
            attr = str(self._node_simple_text(args[0]) if args else "").strip("'\"").lower()
            taint = self._taint_of_expr(args[1]) if len(args) > 1 else None
            if taint and attr in ("href", "src", "srcdoc"):
                redirect = attr == "href"
                self._record_sink("open_redirect" if redirect else "dom_injection", node, taint, {
                    "id": "open_redirect" if redirect else "dom_injection",
                    "type": "Client-side open redirect" if redirect else "DOM injection",
                    "severity": "HIGH",
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

        if ("insertadjacenthtml" in lower or ".html(" in lower or ".append(" in lower
                or method in ("html", "append", "prepend", "attr")):
            args = node.get("arguments", []) or []
            taint = self._taint_of_expr(args[-1] if args else {})
            self._record_sink("dom_injection", node, taint, {
                "id": "dom_injection",
                "type": "DOM injection",
                "severity": "HIGH",
            })
            return

        # Object.assign(target, merged) is a prototype-pollution vector when
        # the merged object can carry "__proto__" keys -- most commonly a
        # JSON.parse() payload (`Object.assign(config, JSON.parse(q))`).
        # Gate on that evidence so ordinary object merging stays silent.
        if "object.assign" in lower:
            args = node.get("arguments", []) or []
            merged = None
            for arg in args:
                candidate = self._taint_of_expr(arg)
                if candidate:
                    if merged is None:
                        merged = candidate.copy()
                    else:
                        merged.merge(candidate)
            if merged and merged.sources and re.search(
                r"__proto__|prototype|json\s*\.\s*parse", self.content, re.I
            ):
                self._record_sink("prototype_pollution", node, merged, {
                    "id": "prototype_pollution",
                    "type": "Prototype pollution",
                    "severity": "MEDIUM",
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

        # Any element whose href/src is assigned from tainted data -- a poisoned
        # <a href> is the classic "phishing link inside your own page" bug.
        # (window.location.* is handled by the branch below.)
        if prop_name and str(prop_name).lower() in ("href", "src") and "location" not in left_txt:
            taint = self._taint_of_expr(right)
            if taint:
                redirect = str(prop_name).lower() == "href"
                self._record_sink("open_redirect" if redirect else "dom_injection", node, taint, {
                    "id": "open_redirect" if redirect else "dom_injection",
                    "type": "Client-side open redirect" if redirect else "DOM injection",
                    "severity": "HIGH",
                })
                return

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
        if "__proto__" in left_txt or "constructor.prototype" in left_txt or ("object.assign" in left_txt and re.search(r"__proto__|prototype", self.content.lower())):
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
            elif _is_static_value(init):
                # Statically-known value: the by-name identifier heuristic
                # must not turn this into a "user input" source.
                self.known_static.add(name)
            if _node_kind_str(init) == "NewExpression" and _name(init.get("callee")) == "URLSearchParams":
                self.urlsearch_vars.add(name)
            # Track tainted object properties so `cfg.q` propagates the same source.
            if _node_kind_str(init) == "ObjectExpression":
                for prop in init.get("properties", []) or []:
                    if not isinstance(prop, dict) or prop.get("type") != "Property":
                        continue
                    key = _name(prop.get("key"))
                    if not key:
                        continue
                    tval = self._taint_of_expr(prop.get("value"))
                    if tval:
                        self.props[f"{name}.{key}"] = tval.copy()

    def _handle_assignment(self, node):
        left = node.get("left", {})
        right = node.get("right", {})
        if _node_kind_str(left) != "Identifier":
            if _node_kind_str(left) == "MemberExpression":
                obj = left.get("object")
                prop = left.get("property")
                obj_name = _name(obj) if isinstance(obj, dict) else None
                prop_name = _name(prop) if isinstance(prop, dict) else None
                if obj_name and prop_name:
                    taint = self._taint_of_expr(right)
                    if taint:
                        self.props[f"{obj_name}.{prop_name}"] = taint.copy()
            self._check_assignment_sink(node)
            return
        name = left.get("name")
        taint = self._taint_of_expr(right)
        if taint:
            taint = taint.copy()
            taint.path.append(f"{name} = {self._node_simple_text(right)[:60]}")
            self.vars[name] = taint
            self.known_static.discard(name)
        elif _is_static_value(right):
            # Reassignment to a constant value clears any earlier taint.
            self.vars.pop(name, None)
            self.known_static.add(name)

    # ---------------- inter-procedural helpers ----------------
    def _collect_functions(self, node):
        ntype = _node_kind_str(node)
        if ntype == "FunctionDeclaration":
            name = _name(node.get("id"))
            if name:
                self.functions.setdefault(name, {"params": self._param_names(node), "body": node.get("body", {}).get("body", []) if isinstance(node.get("body"), dict) else []})
            return
        if ntype == "VariableDeclarator":
            init = node.get("init")
            name = _name(node.get("id"))
            if name and init and _node_kind_str(init) in ("ArrowFunctionExpression", "FunctionExpression"):
                self.functions.setdefault(name, {"params": self._param_names(init), "body": (init.get("body") or {}).get("body", []) if isinstance(init.get("body"), dict) else []})
            return
        if ntype == "AssignmentExpression":
            left = node.get("left")
            right = node.get("right")
            name = _name(left)
            if name and _node_kind_str(left) == "Identifier" and _node_kind_str(right) in ("ArrowFunctionExpression", "FunctionExpression"):
                self.functions.setdefault(name, {"params": self._param_names(right), "body": (right.get("body") or {}).get("body", []) if isinstance(right.get("body"), dict) else []})

    def _param_names(self, fn):
        names = []
        for p in fn.get("params", []) or []:
            if isinstance(p, dict):
                if _node_kind_str(p) in ("Identifier", "RestElement"):
                    names.append(_name(p.get("argument") if _node_kind_str(p) == "RestElement" else p))
                else:
                    # Destructuring: count the top-level bound names conservatively.
                    names.append(_name(p))
        return names

    def _function_call_name(self, node):
        if not isinstance(node, dict):
            return None
        callee = node.get("callee")
        if not isinstance(callee, dict):
            return None
        if callee.get("type") == "Identifier":
            return callee.get("name")
        if _node_kind_str(callee) == "MemberExpression":
            obj = callee.get("object")
            if _node_kind_str(obj) == "Identifier":
                # this.method(...) / obj.method(...)
                return f"{obj.get('name')}.{_name(callee.get('property'))}"
        return None

    def _analyze_function_flow(self, call_node, func_name):
        fn = self.functions.get(func_name)
        if not fn:
            return
        if self._func_depth > 4:
            # Inter-procedural depth bound: record that propagation may be
            # incomplete instead of silently treating the flow as fully proven.
            self._note_limitation(
                f"Call chain through '{func_name}' exceeded the inter-procedural depth bound; "
                "downstream propagation may be incomplete."
            )
            return
        params = fn["params"]
        args = call_node.get("arguments", []) or []
        taints = []
        for arg in args:
            t = self._taint_of_expr(arg)
            taints.append(t)
        if not any(taints):
            return
        saved = {}
        for idx, param in enumerate(params):
            if idx < len(taints) and taints[idx]:
                saved[param] = self.vars.get(param)
                t = taints[idx].copy()
                t.path.append(f"call {func_name}({self._node_simple_text(args[idx])[:40]})")
                self.vars[param] = t
        self._func_depth += 1
        try:
            for stmt in fn["body"]:
                self._walk(stmt, self._check_assignment_sink)
                self._walk(stmt, self._check_call_sink)
                self._walk(stmt, self._check_function_flow)
        finally:
            self._func_depth -= 1
            for param, old in saved.items():
                if old is None:
                    self.vars.pop(param, None)
                else:
                    self.vars[param] = old

    def _check_function_flow(self, node):
        if _node_kind_str(node) not in ("CallExpression", "OptionalCallExpression"):
            return
        name = self._function_call_name(node)
        if name and name in self.functions:
            self._analyze_function_flow(node, name)
        # Also allow a simple single-identifier alias to the collected function.
        if name and "." not in (name or ""):
            for fn_name, fn in self.functions.items():
                if fn_name == name:
                    self._analyze_function_flow(node, fn_name)

    def analyze(self):
        tree = parse_raw(self.content)
        if tree is None:
            self.ast_used = False
            self._note_limitation("AST parser unavailable or unable to parse this source.")
            self._regex_analyze()
            self._apply_quality_metadata()
            return self.findings
        self.ast_used = True

        # Pass 0: index declared functions so call args can be propagated into sinks.
        statements = tree.get("body", []) or []
        for stmt in statements:
            self._walk(stmt, self._collect_functions)

        # Two passes: first assignments so reads later see taint, then sink checks.
        for stmt in statements:
            self._walk(stmt, self._handle_variable_declaration)
        for stmt in statements:
            self._walk(stmt, self._handle_assignment)
        for stmt in statements:
            self._walk(stmt, self._check_call_sink)
            self._walk(stmt, self._check_assignment_sink)
        for stmt in statements:
            self._walk(stmt, self._check_function_flow)

        # If AST parsed but found no flows, only run the regex fallback when the code
        # actually has a taint source. A bare `eval("...")` is a pattern the scanner's
        # `unsafe_runtime` risk signal already covers, not a source-to-sink flow.
        if not self.findings and self._has_obvious_dangerous_patterns() and self._has_source_like_pattern():
            before = set()
            self._regex_analyze()
            self.ast_used = True  # AST parsed; fallback only supplemented missing flows.
        self._apply_quality_metadata()
        return self.findings

    def _apply_quality_metadata(self):
        """Stamp every emitted flow with analysis quality and limitations.

        A source-to-sink path that resolved entirely through the AST is high
        quality; any crossing of an unmodeled construct (dynamic property,
        untracked call, depth bound, regex fallback) lowers it and is listed
        under ``limitations`` so the tester sees exactly what did not resolve.
        """
        doc_limitations = list(self.limitations)
        if not self.ast_used:
            doc_limitations.insert(0, "AST parser unavailable; flow derived from line-based heuristics.")
        quality = "heuristic" if not self.ast_used else ("medium" if doc_limitations else "high")
        for finding in self.findings:
            notes = []
            for note in list(finding.get("limitations", []) or []) + doc_limitations:
                if note and note not in notes:
                    notes.append(note)
            finding["limitations"] = notes[:8]
            # A flow carrying any limitation is never "high" quality analysis.
            finding["analysis_quality"] = "heuristic" if not self.ast_used else ("medium" if notes else "high")
            finding.setdefault("evidence_type", "source_to_sink")
            finding.setdefault("observation", bool(finding.get("sanitization_detected")))

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
        """Conservative fallback for bundles the optional parser cannot parse.

        The old fallback guessed the source variable from a whole minified
        line, which frequently selected ``innerHTML`` or another sink.  This
        version records explicit source labels and propagates simple aliases
        and object properties without claiming unrelated patterns are flows.
        """
        text = self.content
        tainted = {}
        properties = {}

        source_specs = [
            (r"(?:new\s+URLSearchParams\s*\(\s*)?location\.search|url\.search|searchParams(?:\.get)?", "URL query string"),
            (r"location\.hash|url\.hash", "URL fragment"),
            (r"location\.href|window\.location", "full URL"),
            (r"document\.referrer", "referrer"),
            (r"document\.baseURI", "document base URL"),
            (r"history\.state|history\.pushState\s*\(", "history state"),
            (r"window\.name", "window.name"),
            (r"(?:event|e|msg|message)\.data", "postMessage/window message data"),
            (r"(?:localStorage|sessionStorage)\.getItem\s*\(", "browser storage"),
            (r"document\.cookie", "document.cookie"),
            (r"(?:document\.querySelector|document\.getElementById)\s*\([^)]*\)\s*\.value", "form/input value"),
        ]

        # Reads whose value leaving the page would matter.  Broader than the
        # module-level SENSITIVE_READ_RE on purpose: for an exfiltration
        # heuristic a false lead costs a review, a missed lead costs data.
        EXFIL_READ_RE = re.compile(
            r"cookie|localStorage|sessionStorage|storage|token|password|credential|session",
            re.I,
        )

        def source_for(expr):
            for pattern, label in source_specs:
                if re.search(pattern, expr, re.I):
                    return label
            return None

        # Split at statement boundaries but retain line numbers. This works for
        # ordinary source and still gives useful evidence for minified bundles.
        statements = [(text[:m.start()].count("\n") + 1, m.group(0).strip())
                      for m in re.finditer(r"[^;\n]+", text) if m.group(0).strip()]

        for line_no, statement in statements:
            # `search` (not `match`) so assignments nested inside an expression
            # are still tracked -- a minified bundle puts several of them on one
            # line.  The lookbehind/lookahead keep member assignments
            # (`el.innerHTML = …`) and comparisons (`a == b`) out of the taint
            # table; member expressions are handled as sinks below.
            assignment = re.search(
                r"(?<![.\w$])(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=(?![=>])\s*(.+)$",
                statement, re.I | re.S,
            ) or re.search(
                r"(?<![.\w$!=<>])([A-Za-z_$][\w$]*)\s*=(?![=>])\s*(.+)$",
                statement, re.I | re.S,
            )
            if not assignment:
                continue
            name, expr = assignment.groups()
            source = source_for(expr)
            aliases = [value for value in tainted if re.search(rf"\b{re.escape(value)}\b", expr)]
            if source or aliases:
                value = {
                    "sources": [f"source:{source}"] if source else [],
                    "sanitized": any(h in expr.lower() for h in SANITIZER_HINTS),
                    "path": [f"read {source}" if source else f"alias {', '.join(aliases)}"],
                    "confidence": "high" if source else "medium",
                }
                for alias in aliases:
                    for src in tainted[alias]["sources"]:
                        if src not in value["sources"]:
                            value["sources"].append(src)
                    value["path"].extend(tainted[alias]["path"])
                    value["sanitized"] = value["sanitized"] or tainted[alias]["sanitized"]
                    value["confidence"] = _max_confidence(value["confidence"], tainted[alias]["confidence"])
                if value["sanitized"]:
                    value["path"].append("sanitized transformation")
                tainted[name] = value
            elif name in tainted:
                # Reassignment to a value that is neither a source nor a
                # tracked alias clears any earlier taint: `q = '/about'`
                # after `q = location.hash` must not keep the fragment
                # source alive on a later read.
                tainted.pop(name, None)

            # Track object literal properties, e.g. { q: location.search }.
            for prop, expr_value in re.findall(r"([A-Za-z_$][\w$]*)\s*:\s*([^,}]+)", expr):
                prop_source = source_for(expr_value)
                prop_alias = next((v for v in tainted if re.search(rf"\b{re.escape(v)}\b", expr_value)), None)
                if prop_source or prop_alias:
                    base = tainted[prop_alias] if prop_alias else None
                    properties[f"{name}.{prop}"] = {
                        "sources": [f"source:{prop_source}"] if prop_source else list(base["sources"]),
                        "sanitized": bool(base and base["sanitized"]),
                        "path": [f"read {prop_source}" if prop_source else f"property {name}.{prop}"],
                        "confidence": "high" if prop_source else "medium",
                    }

        def combine(values):
            if not values:
                return None
            sources, path, sanitized, confidence = [], [], False, "low"
            for value in values:
                for src in value["sources"]:
                    if src not in sources:
                        sources.append(src)
                for step in value["path"]:
                    if step not in path:
                        path.append(step)
                sanitized = sanitized or value["sanitized"]
                confidence = _max_confidence(confidence, value["confidence"])
            return {"sources": sources, "path": path, "sanitized": sanitized, "confidence": confidence}

        def inline_sources(expr):
            """Taint from a source used *directly* in a sink expression.

            Without this the fallback only recognised previously assigned
            variables, so `document.write(document.referrer)` and
            `eval(location.hash)` -- both textbook flows -- were missed
            entirely whenever the AST parser was unavailable.
            """
            values = []
            for pattern, label in source_specs:
                if re.search(pattern, expr, re.I):
                    values.append({
                        "sources": [f"source:{label}"],
                        "sanitized": any(h in expr.lower() for h in SANITIZER_HINTS),
                        "path": [f"read {label}"],
                        "confidence": "high",
                    })
            return values

        def taints_in(expr):
            values = []
            numeric_props = "|".join(sorted(_NUMERIC_PROPS))
            # A numeric property read (q.length, q.size) cannot carry a
            # payload, so an alias followed by one does not propagate taint.
            not_numeric = rf"(?!\s*\.\s*(?:{numeric_props})\b)"
            for name, value in tainted.items():
                if re.search(rf"\b{re.escape(name)}\b{not_numeric}", expr):
                    values.append(value)
            for key, value in properties.items():
                if re.search(rf"\b{re.escape(key)}\b{not_numeric}", expr):
                    values.append(value)
            values.extend(inline_sources(expr))
            return values

        for line_no, statement in statements:
            sink = re.search(
                r"(?:innerHTML|outerHTML|srcdoc)\s*(?:=|\+=)|insertAdjacentHTML\s*\(|"
                r"document\.(?:write|writeln)\s*\(|\beval\s*\(|new\s+Function\s*\(|"
                # jQuery-style sinks: $('#x').html(...) / .append(...)
                r"\.\s*html\s*\(|\$\s*\([^)]*\)\s*\.\s*(?:append|prepend|attr)\s*\(|"
                # redirect / script URL sinks via setAttribute
                r"setAttribute\s*\(\s*['\"](?:href|src|srcdoc)['\"]",
                statement, re.I,
            )
            if sink:
                flow = combine(taints_in(statement[sink.end():]))
                is_dom = bool(re.search(
                    r"innerHTML|outerHTML|srcdoc|insertAdjacentHTML|document\."
                    r"|\.\s*html\s*\(|setAttribute\s*\(\s*['\"](?:href|src|srcdoc)",
                    statement, re.I,
                ))
                if flow:
                    heuristic_note = "Line-based heuristic flow; statement-level aliasing may over- or under-approximate taint."
                    self._record({
                        "id": "dom_injection" if is_dom else "dangerous_dynamic_code",
                        "type": "DOM injection" if is_dom else "Dangerous dynamic code execution",
                        "severity": "LOW" if flow["sanitized"] else "HIGH",
                        "confidence": "low" if flow["sanitized"] else min_confidence(flow["confidence"]),
                        "status": "informational" if flow["sanitized"] else ("open" if flow["confidence"] == "high" else "needs_review"),
                        "file": self.filename, "line": line_no,
                        "source": " → ".join(s.replace("source:", "") for s in flow["sources"]),
                        "sink": statement[sink.start():sink.end()].strip() + statement[sink.end():sink.end() + 120],
                        "flow": flow["path"][:8], "sanitization_detected": flow["sanitized"],
                        "evidence": ("sanitized: " if flow["sanitized"] else "") + statement[:240],
                        "evidence_type": "source_to_sink",
                        "analysis_quality": "heuristic",
                        "limitations": [heuristic_note],
                        "observation": bool(flow["sanitized"]),
                    })
                elif not is_dom:
                    self._record({
                        "id": "dangerous_dynamic_code", "type": "Dangerous dynamic code execution", "severity": "MEDIUM",
                        "confidence": "low", "status": "needs_review", "file": self.filename, "line": line_no,
                        "source": "", "sink": statement[:160], "flow": [], "sanitization_detected": False,
                        "evidence": statement[:240],
                        "evidence_type": "static_pattern",
                        "analysis_quality": "heuristic",
                        "limitations": ["Regex pattern match without an established data flow."],
                        "observation": True,
                    })

            # Redirect sinks: location.href/assign/replace, and any element
            # whose href is assigned from data (a tainted <a href> is the
            # classic "phishing link inside your own page" primitive).
            redirect = re.search(
                r"\blocation\s*\.\s*(?:href|assign|replace)\s*(?:=|\()"
                r"|\.href\s*(?:=(?!=)|\+=)"
                r"|\.\s*(?:assign|replace)\s*\(",
                statement, re.I,
            )
            if redirect:
                flow = combine(taints_in(statement[redirect.end():]))
                if flow:
                    self._record({
                        "id": "open_redirect", "type": "Client-side open redirect", "severity": "HIGH",
                        "confidence": min_confidence(flow["confidence"]),
                        "status": "informational" if flow["sanitized"] else ("open" if flow["confidence"] == "high" else "needs_review"),
                        "file": self.filename, "line": line_no,
                        "source": " → ".join(s.replace("source:", "") for s in flow["sources"]),
                        "sink": statement[:160], "flow": flow["path"][:8],
                        "sanitization_detected": flow["sanitized"], "evidence": statement[:240],
                        "evidence_type": "source_to_sink", "analysis_quality": "heuristic",
                        "limitations": ["Line-based heuristic flow; statement-level aliasing may over- or under-approximate taint."],
                        "observation": bool(flow["sanitized"]),
                    })

            # Exfiltration heuristic: a sensitive read reaching an outbound
            # transport.  Reported as a *candidate* (medium confidence,
            # behavioural correlation) because the fallback cannot establish
            # that the destination is external or attacker-controlled.
            outbound = re.search(
                r"\b(?:fetch|axios|XMLHttpRequest|sendBeacon)\s*\("
                r"|\.\s*(?:send|post)\s*\(|new\s+WebSocket\s*\(",
                statement, re.I,
            )
            if outbound:
                flow = combine(taints_in(statement))
                sensitive = [src for src in (flow or {}).get("sources", [])
                             if EXFIL_READ_RE.search(src)]
                if flow and sensitive:
                    self._record({
                        "id": "data_exfiltration_candidate",
                        "type": "Sensitive data sent to an outbound destination",
                        "severity": "MEDIUM" if flow["sanitized"] else "HIGH",
                        "confidence": min_confidence(flow["confidence"]),
                        "status": "needs_review",
                        "file": self.filename, "line": line_no,
                        "source": " → ".join(s.replace("source:", "") for s in flow["sources"]),
                        "sink": statement[:160], "flow": flow["path"][:8],
                        "sanitization_detected": flow["sanitized"],
                        "evidence": statement[:240],
                        "evidence_type": "behavioral_correlation",
                        "analysis_quality": "heuristic",
                        "limitations": [
                            "Line-based heuristic: the destination is not proven to be external, "
                            "and the payload is not proven to contain the sensitive value."
                        ],
                        "observation": False,
                    })

            if re.search(r"postMessage\s*\([^)]*,\s*['\"]\*['\"]", statement, re.I):
                self._record({
                    "id": "insecure_postmessage", "type": "Insecure postMessage", "severity": "MEDIUM",
                    "confidence": "medium", "status": "needs_review", "file": self.filename, "line": line_no,
                    "source": "message data", "sink": statement[:160], "flow": [],
                    "sanitization_detected": False, "evidence": statement[:240],
                    "evidence_type": "static_pattern", "analysis_quality": "heuristic",
                    "limitations": ["Wildcard targetOrigin observed; payload sensitivity not established."],
                    "observation": False,
                })
            if re.search(r"(?:__proto__|constructor\.prototype|Object\.assign\s*\([^)]*(?:__proto__|prototype))", statement, re.I):
                self._record({
                    "id": "prototype_pollution", "type": "Prototype pollution", "severity": "MEDIUM",
                    "confidence": "low", "status": "needs_review", "file": self.filename, "line": line_no,
                    "source": "", "sink": statement[:160], "flow": [],
                    "sanitization_detected": False, "evidence": statement[:240],
                    "evidence_type": "static_pattern", "analysis_quality": "heuristic",
                    "limitations": ["Prototype-touching pattern; attacker control of the merged object not proven."],
                    "observation": True,
                })

        # Small inter-procedural fallback: propagate a tainted argument into a
        # function body when the AST parser is unavailable.  This is deliberately
        # limited to named functions and direct calls.
        for function in re.finditer(r"function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{([^{}]*)\}", text, re.I | re.S):
            fn_name, params_text, body = function.groups()
            params = [p.strip() for p in params_text.split(",") if p.strip()]
            sink = re.search(r"(?:innerHTML|outerHTML|srcdoc)\s*=|insertAdjacentHTML\s*\(", body, re.I)
            if not sink or not params:
                continue
            for call in re.finditer(rf"\b{re.escape(fn_name)}\s*\(([^)]*)\)", text[function.end():], re.I):
                args = [a.strip() for a in call.group(1).split(",") if a.strip()]
                if not args:
                    continue
                flow = combine(taints_in(args[0]))
                if not flow:
                    continue
                rendered = body
                for index, param in enumerate(params):
                    if index < len(args):
                        rendered = re.sub(rf"\b{re.escape(param)}\b", args[index], rendered)
                line_no = text[:function.start()].count("\n") + 1
                self._record({
                    "id": "dom_injection", "type": "DOM injection",
                    "severity": "LOW" if flow["sanitized"] else "HIGH",
                    "confidence": "low" if flow["sanitized"] else min_confidence(flow["confidence"]),
                    "status": "informational" if flow["sanitized"] else ("open" if flow["confidence"] == "high" else "needs_review"),
                    "file": self.filename, "line": line_no,
                    "source": " → ".join(src.replace("source:", "") for src in flow["sources"]),
                    "sink": rendered[sink.start():sink.end()].strip() + rendered[sink.end():sink.end() + 120],
                    "flow": flow["path"][:8] + [f"call {fn_name}"],
                    "sanitization_detected": flow["sanitized"],
                    "evidence": ("sanitized: " if flow["sanitized"] else "") + rendered[:240],
                    "evidence_type": "source_to_sink",
                    "analysis_quality": "heuristic",
                    "limitations": ["Simple regex inter-procedural substitution; closures, aliases and callbacks are not modeled."],
                    "observation": bool(flow["sanitized"]),
                })



def analyze_taint(content, filename="inline.js"):
    """Public entrypoint: return source-to-sink data-flow findings."""
    analyzer = TaintAnalyzer(content or "", filename=filename)
    return analyzer.analyze()
