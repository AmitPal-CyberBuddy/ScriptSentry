"""Tree-sitter powered JavaScript/TypeScript parsing (estree-shaped output).

The optional ``esprima`` parser predates optional chaining, nullish
coalescing, class fields and the rest of post-2020 JavaScript, so modern
bundles silently dropped to the capped-confidence regex fallback -- or worse,
were analyzed through :func:`core.js_parser._sanitize_modern_syntax`, which
rewrites ``?.`` to ``.`` and ``??`` to ``||`` *in the source* before parsing.
That hack keeps the walkers alive but changes what the code means.

This module adds tree-sitter as the primary AST engine: a fast, tolerant,
C-speed parser whose JavaScript grammar covers current syntax. Its trees are
converted here into the same plain-dict ESTree-ish shape every existing
consumer already walks (:mod:`core.taint`, :mod:`core.attack_surface`,
:mod:`core.module_discovery`, :func:`core.js_parser.parse_ast`), so the
upgrade is invisible above this seam.

Fidelity notes (deliberate):

* The consumers key on a specific ESTree subset (Identifier,
  MemberExpression, CallExpression, Literal, VariableDeclaration, ...).
  Those are mapped faithfully; the rest get generic dicts that keep their
  converted children under ``children`` so generic walkers still traverse.
* ``a?.b`` becomes ``MemberExpression`` with ``optional: True`` (no
  ChainExpression wrapper -- every consumer already handles plain member
  expressions; the optional flag is preserved for evidence).
* TypeScript-only constructs (``as``/``satisfies`` casts, non-null ``!``,
  type annotations) are unwrapped to the expression underneath; parameters
  keep their pattern and drop the annotation.
* Unparseable regions (``ERROR`` nodes) do not fail the parse: the partial
  tree is returned and the error count travels alongside so callers can be
  honest about quality.
"""
import re
import sys
import threading

try:
    import tree_sitter_javascript as _tsjs
except ImportError:
    _tsjs = None
try:
    import tree_sitter_typescript as _tsTS
except ImportError:
    _tsTS = None

try:
    from tree_sitter import Language, Parser
except ImportError:
    Language = Parser = None


_MAX_DEPTH = 4000


class _State:
    """Lazily built parser/language singletons (shared, thread-safe)."""

    lock = threading.Lock()
    js = None
    ts = None
    parser_js = None
    parser_ts = None
    attempted = False


def _make_parser(language):
    try:
        return Parser(language)
    except TypeError:  # bindings < 0.22
        parser = Parser()
        try:
            parser.language = language
        except AttributeError:
            parser.set_language(language)
        return parser


def _ensure_engines():
    with _State.lock:
        if _State.attempted:
            return
        _State.attempted = True
        if Language is None:
            return
        try:
            if _tsjs is not None:
                _State.js = Language(_tsjs.language())
                _State.parser_js = _make_parser(_State.js)
        except Exception:
            _State.js = _State.parser_js = None
        try:
            if _tsTS is not None and hasattr(_tsTS, "language_typescript"):
                _State.ts = Language(_tsTS.language_typescript())
                _State.parser_ts = _make_parser(_State.ts)
        except Exception:
            _State.ts = _State.parser_ts = None


def tree_sitter_available():
    """True when the tree-sitter engine and at least one grammar are usable."""
    _ensure_engines()
    return _State.parser_js is not None or _State.parser_ts is not None


def engine_name():
    _ensure_engines()
    return "tree-sitter"


def _looks_like_typescript(source):
    head = source[:200_000]
    markers = (
        ": string", ": number", ": boolean", ": void", ": any", ": unknown",
        "interface ", "implements ", "readonly ", " enum ", "namespace ",
        "<T>", " as const", "!.", "@Component", "declare ",
    )
    return any(marker in head for marker in markers)


def _raw_parse(source_bytes):
    """Parse once with the JS grammar, retrying with TS when it looks needed."""
    _ensure_engines()
    tree = None
    if _State.parser_js is not None:
        tree = _State.parser_js.parse(source_bytes)
        if tree is not None and not tree.root_node.has_error:
            return tree, "javascript"
    if _State.parser_ts is not None and (
        tree is None or tree.root_node.has_error or _looks_like_typescript(source_bytes)
    ):
        ts_tree = _State.parser_ts.parse(source_bytes)
        if ts_tree is not None and (
            ts_tree.root_node.has_error <= (tree.root_node.has_error if tree else True)
        ):
            return ts_tree, "typescript"
    if tree is not None:
        return tree, "javascript"
    return None, None


def _text(node):
    try:
        return node.text.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _loc(node):
    sr, sc = node.start_point
    er, ec = node.end_point
    return {
        "start": {"line": sr + 1, "column": sc},
        "end": {"line": er + 1, "column": ec},
    }


def _byte_to_char_table(text):
    """Byte offset -> str index for ``text`` (identity when pure ASCII)."""
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) == len(text):
        return None
    table = [0] * (len(encoded) + 1)
    char = 0
    for index, byte in enumerate(encoded):
        table[index] = char
        if byte < 0x80 or byte >= 0xC0:  # not a continuation byte
            char += 1
    table[len(encoded)] = char
    return table


class _Converter:
    def __init__(self, byte_map=None):
        self.comments = []
        self.error_count = 0
        # byte_map translates UTF-8 byte offsets to str indices; None when
        # the source is pure ASCII and the offsets are already identical.
        self._byte_map = byte_map

    def range_of(self, node):
        """Estree-style ``range`` in character offsets for the source str."""
        start = node.start_byte
        end = node.end_byte
        byte_map = self._byte_map
        if byte_map is not None:
            start = byte_map[start]
            end = byte_map[end]
        return [start, end]

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _children(node):
        return node.named_children

    @staticmethod
    def _fields(node):
        """Named children keyed by their field name (unnamed -> None)."""
        out = []
        for index, child in enumerate(node.children):
            out.append((node.field_name_for_child(index), child))
        return out

    _OPERATOR_RE = re.compile(r"^[=!<>+\-*/%&|^~?]+$|^(?:typeof|void|delete|await|in|of|instanceof)$")

    @classmethod
    def _operator(cls, node):
        """The operator of an expression is an *anonymous* child ('=', '+=', '&&'...)."""
        for _field, child in _Converter._fields(node):
            if child.named_child_count == 0 and child.type not in ("identifier", "number", "string", "comment"):
                text = _text(child)
                if text and cls._OPERATOR_RE.match(text):
                    return text
        return None

    @staticmethod
    def _field(node, name):
        child = node.child_by_field_name(name)
        return child

    # -- dispatch ----------------------------------------------------------
    def convert(self, node, depth=0):
        # Missing fields (e.g. the `alternative` of an if without else) come
        # through as None -- that is an absent subtree, not an error.
        if node is None or depth > _MAX_DEPTH:
            return None
        if node.type == "ERROR":
            self.error_count += 1
        builder = _NODE_BUILDERS.get(node.type)
        if builder is not None:
            tree = builder(node, self, depth)
            if tree is not None:
                return tree
        if node.type == "comment":
            text = _text(node)
            self.comments.append({
                "type": "Block" if text.startswith("/*") else "Line",
                "value": text.strip("/").strip("*").strip()[:200],
                "loc": _loc(node),
                "range": self.range_of(node),
            })
            return None
        if node.type in ("regex", "regex_pattern"):
            return {"type": "Literal", "value": _text(node), "raw": _text(node), "regex": {"pattern": _text(node)},
                    "loc": _loc(node), "range": self.range_of(node)}
        if node.named_child_count == 1 and node.type not in ("program",):
            inner = self.convert(node.named_children[0], depth + 1)
            return inner
        # Generic node: keep named children under "children" so walkers that
        # traverse every dict/list still see the whole subtree.
        children = [self.convert(child, depth + 1) for child in self._children(node)]
        return {
            "type": node.type,
            "children": [child for child in children if child is not None],
            "loc": _loc(node),
            "range": self.range_of(node),
        }

    # -- shared builders ---------------------------------------------------
    def _list(self, node, field, depth):
        child = self._field(node, field)
        if child is None:
            return []
        if child.named_child_count == 0 and child.type not in _LEAF_TYPES:
            return []
        out = []
        for named in child.named_children:
            converted = self.convert(named, depth + 1)
            if converted is not None:
                out.append(converted)
        return out

def _build_variable_declaration(node, conv, depth):
    kind_text = "var"
    for _, child in conv._fields(node):
        if child.type in ("var", "let", "const", "declaration"):
            kind_text = _text(child) or kind_text
            break
    return {
        "type": "VariableDeclaration",
        "kind": kind_text,
        "declarations": [c for c in (conv.convert(child, depth + 1) for child in node.named_children
                                     if child.type == "variable_declarator") if c],
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_variable_declarator(node, conv, depth):
    return {
        "type": "VariableDeclarator",
        "id": conv.convert(conv._field(node, "name"), depth + 1),
        "init": conv.convert(conv._field(node, "value"), depth + 1),
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_expression_statement(node, conv, depth):
    return {
        "type": "ExpressionStatement",
        "expression": conv.convert(node.named_children[0] if node.named_children else None, depth + 1),
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_return(node, conv, depth):
    return {
        "type": "ReturnStatement",
        "argument": conv.convert(node.named_children[0] if node.named_children else None, depth + 1),
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_identifier(node, conv, depth):
    return {"type": "Identifier", "name": _text(node), "loc": _loc(node), "range": conv.range_of(node)}


def _build_this(node, conv, depth):
    return {"type": "ThisExpression", "loc": _loc(node), "range": conv.range_of(node)}


def _build_meta_property(node, conv, depth):
    name = "target" if "new.target" in _text(node) else "meta"
    return {
        "type": "MetaProperty",
        "meta": {"type": "Identifier", "name": "import" if name == "meta" else "new", "loc": _loc(node), "range": conv.range_of(node)},
        "property": {"type": "Identifier", "name": name, "loc": _loc(node), "range": conv.range_of(node)},
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_string(node, conv, depth):
    raw = _text(node)
    quote = raw[0] if raw[:1] in ("'", '"') else None
    value = raw[1:-1] if quote and raw.endswith(quote) else raw
    return {"type": "Literal", "value": value, "raw": raw, "loc": _loc(node), "range": conv.range_of(node)}


def _build_number(node, conv, depth):
    raw = _text(node)
    try:
        value = int(raw, 0)
    except ValueError:
        try:
            value = float(raw)
        except ValueError:
            value = raw
    return {"type": "Literal", "value": value, "raw": raw, "loc": _loc(node), "range": conv.range_of(node)}


def _build_bool_or_null(node, conv, depth):
    raw = _text(node)
    value = {"true": True, "false": False, "null": None, "undefined": None}.get(raw)
    return {"type": "Literal", "value": value, "raw": raw, "loc": _loc(node), "range": conv.range_of(node)}


def _build_template_string(node, conv, depth):
    raw_text = _text(node)
    quasis = []
    expressions = []
    buffer = []

    def flush(tail):
        text = "".join(buffer)
        quasis.append({
            "type": "TemplateElement",
            "value": {"raw": text, "cooked": text},
            "tail": tail,
            "loc": _loc(node), "range": conv.range_of(node),
        })
        buffer.clear()

    for child in node.children:
        if child.type == "template_substitution":
            flush(False)
            converted = conv.convert(child.named_children[0] if child.named_children else child, depth + 1)
            if converted is not None:
                expressions.append(converted)
        elif child.type in ('"', "'", "`"):
            continue
        elif child.type in ("string_content", "string_fragment"):
            buffer.append(_text(child))
    flush(True)
    return {
        "type": "TemplateLiteral",
        "quasis": quasis,
        "expressions": expressions,
        "raw": raw_text[:500],
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_member(node, conv, depth):
    object_node = conv.convert(conv._field(node, "object"), depth + 1)
    property_node = conv.convert(conv._field(node, "property"), depth + 1)
    optional = False
    for _field_name, child in conv._fields(node):
        if child.type == "optional_chain":
            optional = True
    computed = False
    if object_node is None:
        return None
    return {
        "type": "MemberExpression",
        "object": object_node,
        "property": property_node,
        "computed": computed,
        "optional": optional,
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_subscript(node, conv, depth):
    return {
        "type": "MemberExpression",
        "object": conv.convert(conv._field(node, "object"), depth + 1),
        "property": conv.convert(conv._field(node, "index"), depth + 1),
        "computed": True,
        "optional": False,
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_call(node, conv, depth):
    callee_node = conv._field(node, "function")
    arguments = conv._list(node, "arguments", depth)
    optional = any(child.type == "optional_chain" for child in node.children)
    if callee_node is None:
        return None
    if callee_node.type == "import":
        # Dynamic import("x") -- estree models it as ImportExpression.
        return {
            "type": "ImportExpression",
            "source": arguments[0] if arguments else None,
            "arguments": arguments,
            "optional": optional,
            "loc": _loc(node), "range": conv.range_of(node),
        }
    callee = conv.convert(callee_node, depth + 1)
    if callee is None:
        return None
    return {
        "type": "CallExpression",
        "callee": callee,
        "arguments": arguments,
        "optional": optional,
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_new(node, conv, depth):
    return {
        "type": "NewExpression",
        "callee": conv.convert(conv._field(node, "constructor"), depth + 1),
        "arguments": conv._list(node, "arguments", depth),
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_binary(node, conv, depth):
    left = conv.convert(conv._field(node, "left"), depth + 1)
    right = conv.convert(conv._field(node, "right"), depth + 1)
    if left is None or right is None:
        return None
    return {
        "type": "BinaryExpression",
        "operator": conv._operator(node) or "+",
        "left": left,
        "right": right,
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_unary(node, conv, depth):
    argument = conv.convert(conv._field(node, "argument"), depth + 1)
    if argument is None:
        return None
    return {
        "type": "UnaryExpression",
        "operator": conv._operator(node) or "typeof",
        "argument": argument,
        "prefix": True,
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_update(node, conv, depth):
    argument = conv.convert(node.named_children[0] if node.named_children else None, depth + 1) if node.named_children else None
    if argument is None:
        return None
    operator = conv._operator(node) or "++"
    return {
        "type": "UpdateExpression",
        "operator": operator,
        "argument": argument,
        "prefix": _text(node).startswith(operator),
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_assignment(node, conv, depth):
    left = conv.convert(conv._field(node, "left"), depth + 1)
    right = conv.convert(conv._field(node, "right"), depth + 1)
    if left is None:
        return None
    return {
        "type": "AssignmentExpression",
        "operator": conv._operator(node) or "=",
        "left": left,
        "right": right,
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_conditional(node, conv, depth):
    return {
        "type": "ConditionalExpression",
        "test": conv.convert(conv._field(node, "condition"), depth + 1),
        "consequent": conv.convert(conv._field(node, "consequence"), depth + 1),
        "alternate": conv.convert(conv._field(node, "alternative"), depth + 1),
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_sequence(node, conv, depth):
    return {
        "type": "SequenceExpression",
        "expressions": [c for c in (conv.convert(child, depth + 1) for child in node.named_children) if c],
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_arrow(node, conv, depth):
    body = conv.convert(conv._field(node, "body"), depth + 1)
    return {
        "type": "ArrowFunctionExpression",
        "id": None,
        "params": conv._list(node, "parameters", depth),
        "body": body,
        "expression": bool(body) and body.get("type") != "BlockStatement",
        "async": "async" in _text(node)[:40],
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_function(node, conv, depth, estree_type="FunctionExpression"):
    name_node = conv._field(node, "name") or conv._field(node, "declarator")
    return {
        "type": estree_type,
        "id": conv.convert(name_node, depth + 1),
        "params": conv._list(node, "parameters", depth),
        "body": conv.convert(conv._field(node, "body"), depth + 1),
        "async": _text(node).lstrip().startswith("async"),
        "generator": "function*" in _text(node)[:40],
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_class(node, conv, depth, estree_type="ClassExpression"):
    body_node = conv._field(node, "body")
    members = []
    if body_node is not None:
        for member in body_node.named_children:
            converted = conv.convert(member, depth + 1)
            if converted is not None:
                members.append(converted)
    heritage = conv._field(node, "heritage")
    if heritage is None:
        for child in node.named_children:
            if child.type == "class_heritage" and child.named_children:
                heritage = child.named_children[0]
    return {
        "type": estree_type,
        "id": conv.convert(conv._field(node, "name"), depth + 1),
        "superClass": conv.convert(heritage, depth + 1),
        "body": {"type": "ClassBody", "body": members, "loc": _loc(node), "range": conv.range_of(node)},
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_object(node, conv, depth):
    return {
        "type": "ObjectExpression",
        "properties": [c for c in (conv.convert(child, depth + 1) for child in node.named_children) if c],
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_pair(node, conv, depth):
    return {
        "type": "Property",
        "key": conv.convert(conv._field(node, "key"), depth + 1),
        "value": conv.convert(conv._field(node, "value"), depth + 1),
        "kind": "init",
        "computed": False,
        "shorthand": False,
        "method": False,
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_shorthand_pair(node, conv, depth):
    identifier = {"type": "Identifier", "name": _text(node), "loc": _loc(node), "range": conv.range_of(node)}
    return {
        "type": "Property",
        "key": identifier,
        "value": identifier,
        "kind": "init",
        "computed": False,
        "shorthand": True,
        "method": False,
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_array(node, conv, depth):
    return {
        "type": "ArrayExpression",
        "elements": [c for c in (conv.convert(child, depth + 1) for child in node.named_children) if c],
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_spread(node, conv, depth):
    return {
        "type": "SpreadElement",
        "argument": conv.convert(node.named_children[0] if node.named_children else None, depth + 1),
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_rest(node, conv, depth):
    return {
        "type": "RestElement",
        "argument": conv.convert(node.named_children[0] if node.named_children else None, depth + 1),
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_assignment_pattern(node, conv, depth):
    return {
        "type": "AssignmentPattern",
        "left": conv.convert(conv._field(node, "left"), depth + 1),
        "right": conv.convert(conv._field(node, "right"), depth + 1),
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_object_pattern(node, conv, depth):
    return {
        "type": "ObjectPattern",
        "properties": [c for c in (conv.convert(child, depth + 1) for child in node.named_children) if c],
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_array_pattern(node, conv, depth):
    return {
        "type": "ArrayPattern",
        "elements": [c for c in (conv.convert(child, depth + 1) for child in node.named_children) if c],
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_statement_block(node, conv, depth):
    return {
        "type": "BlockStatement",
        "body": [c for c in (conv.convert(child, depth + 1) for child in node.named_children) if c],
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_if(node, conv, depth):
    return {
        "type": "IfStatement",
        "test": conv.convert(conv._field(node, "condition"), depth + 1),
        "consequent": conv.convert(conv._field(node, "consequence"), depth + 1),
        "alternate": conv.convert(conv._field(node, "alternative"), depth + 1),
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_for(node, conv, depth):
    return {
        "type": "ForStatement",
        "init": conv.convert(conv._field(node, "init"), depth + 1),
        "test": conv.convert(conv._field(node, "condition"), depth + 1),
        "update": conv.convert(conv._field(node, "update"), depth + 1),
        "body": conv.convert(conv._field(node, "body"), depth + 1),
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_for_in_or_of(node, conv, depth, of=False):
    left = conv.convert(conv._field(node, "left"), depth + 1)
    if not of:
        # tree-sitter-javascript names both loops "for_in_statement"; the
        # loop keyword is the anonymous child ("in" vs "of").
        for _field_name, child in conv._fields(node):
            if child.named_child_count == 0 and _text(child) == "of":
                of = True
                break
    return {
        "type": "ForOfStatement" if of else "ForInStatement",
        "left": left,
        "right": conv.convert(conv._field(node, "right"), depth + 1),
        "body": conv.convert(conv._field(node, "body"), depth + 1),
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_while(node, conv, depth):
    return {
        "type": "WhileStatement",
        "test": conv.convert(conv._field(node, "condition"), depth + 1),
        "body": conv.convert(conv._field(node, "body"), depth + 1),
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_try(node, conv, depth):
    handler = conv.convert(conv._field(node, "handler"), depth + 1)
    finalizer = None
    for child in node.named_children:
        if child.type == "finally_clause":
            finalizer = conv.convert(child.named_children[0] if child.named_children else child, depth + 1)
    return {
        "type": "TryStatement",
        "block": conv.convert(conv._field(node, "body"), depth + 1),
        "handler": handler,
        "finalizer": finalizer,
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_catch(node, conv, depth):
    param = None
    body = None
    for child in node.named_children:
        if child.type in ("formal_parameters", "identifier", "object_pattern", "array_pattern"):
            param = conv.convert(child, depth + 1)
        elif child.type == "statement_block":
            body = conv.convert(child, depth + 1)
    return {"type": "CatchClause", "param": param, "body": body, "loc": _loc(node), "range": conv.range_of(node)}


def _build_import(node, conv, depth):
    source_literal = None
    specifiers = []
    for _, child in conv._fields(node):
        if child.type == "string":
            source_literal = conv.convert(child, depth + 1)
        elif child.type == "import_specifier":
            names = child.named_children
            imported = conv.convert(names[0], depth + 1) if names else None
            local = conv.convert(names[1], depth + 1) if len(names) > 1 else imported
            specifiers.append({"type": "ImportSpecifier", "imported": imported, "local": local,
                               "loc": _loc(child), "range": conv.range_of(child)})
        elif child.type == "import_default_specifier":
            specifiers.append({"type": "ImportDefaultSpecifier",
                               "local": conv.convert(child.named_children[0] if child.named_children else child, depth + 1),
                               "loc": _loc(child), "range": conv.range_of(child)})
        elif child.type == "import_namespace_specifier":
            specifiers.append({"type": "ImportNamespaceSpecifier",
                               "local": conv.convert(child.named_children[0] if child.named_children else child, depth + 1),
                               "loc": _loc(child), "range": conv.range_of(child)})
    return {
        "type": "ImportDeclaration",
        "specifiers": specifiers,
        "source": source_literal,
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_export(node, conv, depth):
    declaration = None
    specifiers = []
    source_literal = None
    default = "export default" in _text(node)[:30]
    for child in node.named_children:
        if child.type == "export_specifier":
            names = child.named_children
            local = conv.convert(names[0], depth + 1) if names else None
            exported = conv.convert(names[1], depth + 1) if len(names) > 1 else local
            specifiers.append({"type": "ExportSpecifier", "local": local, "exported": exported,
                               "loc": _loc(child), "range": conv.range_of(child)})
        elif child.type == "string":
            source_literal = conv.convert(child, depth + 1)
        elif child.type not in ("export",):
            declaration = conv.convert(child, depth + 1)
    if default:
        return {"type": "ExportDefaultDeclaration", "declaration": declaration, "loc": _loc(node), "range": conv.range_of(node)}
    return {"type": "ExportNamedDeclaration", "declaration": declaration,
            "specifiers": specifiers, "source": source_literal, "loc": _loc(node), "range": conv.range_of(node)}


def _build_method_definition(node, conv, depth):
    key = conv.convert(conv._field(node, "name"), depth + 1)
    if key is None and node.named_children:
        key = conv.convert(node.named_children[0], depth + 1)
    params = conv._list(node, "parameters", depth)
    body = conv.convert(conv._field(node, "body"), depth + 1)
    return {
        "type": "MethodDefinition",
        "key": key,
        "value": {
            "type": "FunctionExpression",
            "id": None,
            "params": params,
            "body": body,
            "loc": _loc(node), "range": conv.range_of(node),
        },
        "kind": "method",
        "computed": False,
        "static": _text(node).lstrip().startswith("static"),
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_property_definition(node, conv, depth):
    key = None
    value = None
    for field_name, child in conv._fields(node):
        if field_name in ("name", "property") and key is None:
            key = conv.convert(child, depth + 1)
        elif field_name == "value":
            value = conv.convert(child, depth + 1)
    if key is None and node.named_children:
        key = conv.convert(node.named_children[0], depth + 1)
    return {
        "type": "PropertyDefinition",
        "key": key,
        "value": value,
        "kind": "init",
        "computed": False,
        "static": _text(node).lstrip().startswith("static"),
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_switch(node, conv, depth):
    cases = []
    for child in node.named_children:
        if child.type == "switch_body":
            for clause in child.named_children:
                if clause.type == "switch_case":
                    cases.append({
                        "type": "SwitchCase",
                        "test": conv.convert(conv._field(clause, "value"), depth + 1),
                        "consequent": [c for c in (conv.convert(cc, depth + 1) for cc in clause.named_children[1:]) if c],
                        "loc": _loc(clause), "range": conv.range_of(clause),
                    })
                elif clause.type == "switch_default":
                    cases.append({
                        "type": "SwitchCase",
                        "test": None,
                        "consequent": [c for c in (conv.convert(cc, depth + 1) for cc in clause.named_children) if c],
                        "loc": _loc(clause), "range": conv.range_of(clause),
                    })
    return {
        "type": "SwitchStatement",
        "discriminant": conv.convert(conv._field(node, "value"), depth + 1),
        "cases": cases,
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_await(node, conv, depth):
    return {
        "type": "AwaitExpression",
        "argument": conv.convert(node.named_children[0] if node.named_children else None, depth + 1),
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_yield(node, conv, depth):
    return {
        "type": "YieldExpression",
        "argument": conv.convert(node.named_children[0] if node.named_children else None, depth + 1),
        "delegate": "* " in _text(node)[:10],
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_throw(node, conv, depth):
    return {
        "type": "ThrowStatement",
        "argument": conv.convert(node.named_children[0] if node.named_children else None, depth + 1),
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_labeled(node, conv, depth):
    return {
        "type": "LabeledStatement",
        "label": {"type": "Identifier", "name": _text(conv._field(node, "label") or node.named_children[0]), "loc": _loc(node), "range": conv.range_of(node)},
        "body": conv.convert(node.named_children[-1], depth + 1) if node.named_children else None,
        "loc": _loc(node), "range": conv.range_of(node),
    }


def _build_unwrap(node, conv, depth):
    """TS wrappers (as/satisfies/non-null/assertion) and parenthesized expressions."""
    inner = conv._field(node, "value") or conv._field(node, "expression")
    if inner is None and node.named_children:
        inner = node.named_children[0]
    return conv.convert(inner, depth + 1)


def _build_required_parameter(node, conv, depth):
    """TS parameter with annotations: keep the pattern, drop the type."""
    pattern = conv._field(node, "pattern")
    if pattern is None and node.named_children:
        pattern = node.named_children[0]
    converted = conv.convert(pattern, depth + 1)
    default = conv._field(node, "default") if node.child_by_field_name("default") else None
    if default is not None and converted is not None:
        return {
            "type": "AssignmentPattern",
            "left": converted,
            "right": conv.convert(default, depth + 1),
            "loc": _loc(node), "range": conv.range_of(node),
        }
    return converted


# ts type -> builder
_NODE_BUILDERS = {
    # expressions
    "identifier": _build_identifier,
    "property_identifier": _build_identifier,
    "shorthand_property_identifier": _build_identifier,
    "shorthand_property_identifier_pattern": _build_identifier,
    "this": _build_this,
    "meta_property": _build_meta_property,
    "string": _build_string,
    "number": _build_number,
    "true": _build_bool_or_null,
    "false": _build_bool_or_null,
    "null": _build_bool_or_null,
    "undefined": _build_bool_or_null,
    "template_string": _build_template_string,
    "member_expression": _build_member,
    "subscript_expression": _build_subscript,
    "call_expression": _build_call,
    "new_expression": _build_new,
    "binary_expression": _build_binary,
    "unary_expression": _build_unary,
    "update_expression": _build_update,
    "assignment_expression": _build_assignment,
    "augmented_assignment_expression": _build_assignment,
    "conditional_expression": _build_conditional,
    "sequence_expression": _build_sequence,
    "arrow_function": _build_arrow,
    "function_expression": lambda n, c, d: _build_function(n, c, d, "FunctionExpression"),
    "generator_function_expression": lambda n, c, d: _build_function(n, c, d, "FunctionExpression"),
    "function_declaration": lambda n, c, d: _build_function(n, c, d, "FunctionDeclaration"),
    "generator_function_declaration": lambda n, c, d: _build_function(n, c, d, "FunctionDeclaration"),
    "class_declaration": lambda n, c, d: _build_class(n, c, d, "ClassDeclaration"),
    "class": lambda n, c, d: _build_class(n, c, d, "ClassExpression"),
    "object": _build_object,
    "pair": _build_pair,
    "method_definition": _build_method_definition,
    "public_field_definition": _build_property_definition,
    "field_definition": _build_property_definition,
    "array": _build_array,
    "spread_element": _build_spread,
    "rest_pattern": _build_rest,
    "assignment_pattern": _build_assignment_pattern,
    "object_pattern": _build_object_pattern,
    "array_pattern": _build_array_pattern,
    "await_expression": _build_await,
    "yield_expression": _build_yield,
    # statements
    "statement_block": _build_statement_block,
    "if_statement": _build_if,
    "for_statement": _build_for,
    "for_in_statement": lambda n, c, d: _build_for_in_or_of(n, c, d, of=False),
    "for_of_statement": lambda n, c, d: _build_for_in_or_of(n, c, d, of=True),
    "while_statement": _build_while,
    "do_statement": _build_while,
    "try_statement": _build_try,
    "catch_clause": _build_catch,
    "switch_statement": _build_switch,
    "throw_statement": _build_throw,
    "labeled_statement": _build_labeled,
    "empty_statement": lambda n, c, d: {"type": "EmptyStatement", "loc": _loc(n), "range": c.range_of(n)},
    "debugger_statement": lambda n, c, d: {"type": "DebuggerStatement", "loc": _loc(n), "range": c.range_of(n)},
    "break_statement": lambda n, c, d: {"type": "BreakStatement", "label": None, "loc": _loc(n), "range": c.range_of(n)},
    "continue_statement": lambda n, c, d: {"type": "ContinueStatement", "label": None, "loc": _loc(n), "range": c.range_of(n)},
    "with_statement": lambda n, c, d: {
        "type": "WithStatement",
        "object": c.convert(c._field(n, "object"), d + 1),
        "body": c.convert(c._field(n, "body"), d + 1),
        "loc": _loc(n),
        "range": c.range_of(n),
    },
    # statements
    "lexical_declaration": _build_variable_declaration,
    "variable_declaration": _build_variable_declaration,
    "variable_declarator": _build_variable_declarator,
    "expression_statement": _build_expression_statement,
    "return_statement": _build_return,
    # declarations
    "import_statement": _build_import,
    "export_statement": _build_export,
    # TS wrappers -> unwrap
    "parenthesized_expression": _build_unwrap,
    "as_expression": _build_unwrap,
    "satisfies_expression": _build_unwrap,
    "non_null_expression": _build_unwrap,
    "type_assertion": _build_unwrap,
    "expression_as_function_value": _build_unwrap,
    "required_parameter": _build_required_parameter,
    "optional_parameter": _build_required_parameter,
    "annotated_identifier": _build_unwrap,
}

_LEAF_TYPES = {"identifier", "property_identifier", "string", "number", "true", "false", "null", "undefined"}


def parse_to_dict(content):
    """Parse ``content`` and return ``(estree-shaped dict, error_or_None)``.

    ``error`` is ``None`` for a clean parse, or a short description when the
    tree contains ERROR regions (the partial tree is still returned -- every
    other node converted normally).
    """
    if not tree_sitter_available():
        return None, "tree-sitter-not-installed"
    # Minified bundles nest deeply; the converter walks with the interpreter's
    # recursion, so give it explicit headroom (bounded by _MAX_DEPTH anyway).
    if sys.getrecursionlimit() < 20_000:
        sys.setrecursionlimit(20_000)
    text = str(content or "")
    if not text.strip():
        return None, "empty"
    tree, _grammar = _raw_parse(text.encode("utf-8", errors="replace"))
    if tree is None:
        return None, "tree-sitter-parse-failed"
    root = tree.root_node
    converter = _Converter(_byte_to_char_table(text))
    body = []
    for child in root.named_children:
        if child.type == "comment":
            converter.convert(child)
            continue
        converted = converter.convert(child)
        if converted is not None:
            body.append(converted)
    program = {
        "type": "Program",
        "body": body,
        "sourceType": "module",
        "comments": converter.comments[:500],
        "loc": _loc(root),
        "range": converter.range_of(root),
    }
    error = None
    if converter.error_count or root.has_error:
        error = f"tree-sitter: {converter.error_count or 1} unparseable region(s); partial AST used"
    return program, error
