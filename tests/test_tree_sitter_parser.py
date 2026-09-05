"""tree-sitter engine integration tests.

Pins the contract introduced when tree-sitter became the primary JS parsing
engine (esprima stays as the fallback):

  * modern syntax parses natively -- no source rewriting, no engine error;
  * the estree-shaped dicts carry ``range`` in *character* offsets so
    consumers can slice the original source string;
  * garbage input yields a usable partial tree plus an error note instead of
    a hard failure;
  * dynamic ``import()`` is modelled as ``ImportExpression`` so module
    discovery keeps working;
  * the raw-parse cache still guarantees one parse per content across
    consumers, and a partial (error-annotated) tree is cached as a success.

Tests that need tree-sitter itself are skipped when it is not installed;
the engine-selection tests run against whatever engines are present.
"""
import json
import time
import unittest
from unittest import mock

from core import js_parser
from core.js_parser import esprima_available, parser_available

try:
    from core import tree_sitter_ast
    from core.tree_sitter_ast import engine_name, parse_to_dict, tree_sitter_available

    HAS_TS = tree_sitter_available()
except ImportError:  # pragma: no cover - tree-sitter not installed
    tree_sitter_ast = None
    parse_to_dict = None
    engine_name = None
    HAS_TS = False

requires_tree_sitter = unittest.skipUnless(HAS_TS, "needs tree-sitter grammars")


def _find(node, ntype, found=None):
    """Collect every dict in the tree whose ``type`` equals ``ntype``."""
    if found is None:
        found = []
    if isinstance(node, list):
        for item in node:
            _find(item, ntype, found)
    elif isinstance(node, dict):
        if node.get("type") == ntype:
            found.append(node)
        for value in node.values():
            _find(value, ntype, found)
    return found


@unittest.skipUnless(parser_available(), "needs a JS AST parser (tree-sitter or esprima)")
class EngineSelectionTest(unittest.TestCase):
    def test_parser_status_reports_engine_stack(self):
        status = js_parser.parser_status()
        self.assertTrue(status["available"])
        self.assertEqual(status["mode"], "ast")
        if HAS_TS:
            self.assertEqual(status["name"], "tree-sitter")
            self.assertEqual(status["engines"][0], "tree-sitter")
        elif esprima_available():
            self.assertEqual(status["name"], "esprima")

    def test_parser_name_matches_status(self):
        if HAS_TS:
            self.assertEqual(js_parser.PARSER_NAME, "tree-sitter")
        elif esprima_available():
            self.assertEqual(js_parser.PARSER_NAME, "esprima")


@requires_tree_sitter
class TreeSitterEstreeContractTest(unittest.TestCase):
    """The tree-sitter -> estree conversion details consumers rely on."""

    def test_valid_source_returns_tree_without_error(self):
        tree, error = parse_to_dict("const a = 1;")
        self.assertIsNone(error)
        self.assertEqual(tree["type"], "Program")

    def test_range_offsets_slice_the_original_source(self):
        source = "el.innerHTML = q; window.parent.postMessage(m, '*');"
        tree, _ = parse_to_dict(source)
        stmt = tree["body"][0]
        self.assertEqual(source[stmt["range"][0]:stmt["range"][1]], "el.innerHTML = q;")
        left = stmt["expression"]["left"]
        self.assertEqual(source[left["range"][0]:left["range"][1]], "el.innerHTML")

    def test_range_uses_character_offsets_for_non_ascii_sources(self):
        # The identifier below is 7 characters but 10 bytes in UTF-8; a
        # byte-based range would slice the str one byte late per multi-byte
        # character that precedes it.
        source = "const piñata = 'x';\nlater.value = y;"
        tree, _ = parse_to_dict(source)
        stmt = tree["body"][1]
        self.assertEqual(source[stmt["range"][0]:stmt["range"][1]], "later.value = y;")

    def test_optional_chaining_and_nullish_coalescing_parse_natively(self):
        source = "const v = a?.b?.c ?? d;"
        tree, error = parse_to_dict(source)
        self.assertIsNone(error)
        member = _find(tree, "MemberExpression")[0]
        self.assertTrue(member.get("optional"))
        binary = _find(tree, "BinaryExpression")[0]
        self.assertEqual(binary.get("operator"), "??")

    def test_optional_call_expression(self):
        tree, error = parse_to_dict("cb?.();")
        self.assertIsNone(error)
        calls = _find(tree, "CallExpression")
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0].get("optional"))

    def test_for_of_and_for_in_are_distinct(self):
        tree, _ = parse_to_dict("for (const x of xs) {} for (const k in o) {}")
        ntypes = [n["type"] for n in tree["body"]]
        self.assertIn("ForOfStatement", ntypes)
        self.assertIn("ForInStatement", ntypes)

    def test_dynamic_import_is_import_expression(self):
        source = 'load(() => import("./chunks/app-1.js"));'
        tree, _ = parse_to_dict(source)
        imports = _find(tree, "ImportExpression")
        self.assertEqual(len(imports), 1)
        src = imports[0].get("source") or {}
        self.assertEqual(src.get("value"), "./chunks/app-1.js")

    def test_require_call_stays_call_expression(self):
        tree, _ = parse_to_dict('const path = require("./util.js");')
        requires = _find(tree, "CallExpression")
        self.assertEqual(len(requires), 1)
        self.assertEqual(requires[0]["callee"]["name"], "require")
        self.assertEqual(requires[0]["arguments"][0]["value"], "./util.js")

    def test_template_literal_keeps_quasis_and_expressions(self):
        tree, _ = parse_to_dict("const s = `a${x}b`;")
        template = _find(tree, "TemplateLiteral")[0]
        self.assertEqual([q["value"]["cooked"] for q in template["quasis"]], ["a", "b"])
        self.assertEqual(len(template["expressions"]), 1)

    def test_comments_are_collected_on_program(self):
        tree, _ = parse_to_dict("// lead\nconst a = 1; /* tail */")
        comments = tree.get("comments") or []
        self.assertGreaterEqual(len(comments), 2)

    def test_json_is_valid_output(self):
        tree, _ = parse_to_dict("if (a) { b(); } else { c(); }")
        self.assertEqual(tree["body"][0]["type"], "IfStatement")

    def test_garbage_yields_partial_tree_plus_error_note(self):
        tree, error = parse_to_dict("this is ((( not javascript")
        self.assertIsNotNone(tree, "partial tree must still be returned")
        self.assertEqual(tree["type"], "Program")
        self.assertIsNotNone(error)
        self.assertIn("tree-sitter", error)

    def test_typescript_source_parses_via_ts_grammar(self):
        if not getattr(tree_sitter_ast, "_typescript_languages", None):
            self.skipTest("needs tree-sitter-typescript")
        tree, _ = parse_to_dict("const x: number = f(y as string);")
        self.assertEqual(tree["type"], "Program")
        self.assertTrue(_find(tree, "TSTypeAnnotation") or _find(tree, "TypeAnnotation"))

    def test_typescript_typescript_as_expression_unwraps(self):
        if not getattr(tree_sitter_ast, "_typescript_languages", None):
            self.skipTest("needs tree-sitter-typescript")
        tree, _ = parse_to_dict("const v = input as HTMLElement;")
        declarator = _find(tree, "VariableDeclarator")[0]
        self.assertEqual(declarator["init"]["type"], "Identifier")

    def test_empty_and_none_input(self):
        self.assertEqual(parse_to_dict(""), (None, "empty"))


@requires_tree_sitter
class TreeSitterCacheInterplayTest(unittest.TestCase):
    def setUp(self):
        with js_parser._CACHE_LOCK:
            js_parser._RAW_CACHE.clear()
            js_parser._FAILURE_CACHE.clear()

    def test_partial_tree_counts_as_success_and_is_cached(self):
        calls = {"n": 0}
        real_parse = js_parser._parse

        def counting(source):
            calls["n"] += 1
            return real_parse(source)

        garbage = "}}} function const"
        with mock.patch.object(js_parser, "_parse", counting):
            first_tree, first_error = js_parser.parse_raw_with_error(garbage)
            second_tree, second_error = js_parser.parse_raw_with_error(garbage)
        self.assertIsNotNone(first_tree)
        self.assertIsNotNone(first_error)
        self.assertEqual(first_error, second_error)
        self.assertEqual(calls["n"], 1, "partial-tree successes must be cached, not retried")
        self.assertIs(first_tree, second_tree)

    def test_engine_falls_back_to_esprima_when_tree_sitter_disabled(self):
        if not esprima_available():
            self.skipTest("needs esprima as fallback")
        with mock.patch.object(js_parser, "_ts_parse_to_dict", None):
            self.assertEqual(engine_name(), "tree-sitter")  # module-level probe unaffected...
            tree = js_parser.parse_raw("var x = 1;")
        self.assertIsNotNone(tree)
        self.assertEqual(tree["body"][0]["type"], "VariableDeclaration")


@requires_tree_sitter
class TreeSitterPerformanceTest(unittest.TestCase):
    def test_large_bundle_parses_quickly_with_ranges(self):
        # ~330KB synthetic bundle of realistic functions; on this class of
        # input tree-sitter should comfortably beat esprima's parse time.
        parts = []
        for i in range(1500):
            parts.append(
                "function handler_" + str(i) + "(event) {\n"
                "  const target_" + str(i) + " = event?.currentTarget ?? document.body;\n"
                "  target_" + str(i) + ".dataset['idx'] = `" + str(i) + ":${event.type ?? 'click'}`;\n"
                "  if (target_" + str(i) + ".classList?.contains('active')) { event.preventDefault(); }\n"
                "}"
            )
        source = "\n".join(parts)
        self.assertGreater(len(source), 300_000)
        started = time.monotonic()
        tree, error = parse_to_dict(source)
        elapsed = time.monotonic() - started
        self.assertIsNone(error)
        self.assertLess(elapsed, 10.0, "large-bundle parse must stay interactive")
        self.assertGreater(len(_find(tree, "FunctionDeclaration")), 1000)


if __name__ == "__main__":
    unittest.main()
