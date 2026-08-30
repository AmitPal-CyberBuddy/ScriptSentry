"""Tests for layered (AST + bundler adapter) module/script discovery."""
import unittest

from core.js_parser import parser_available

from core.analyzer_service import extract_script_refs
from core.module_discovery import discover_module_refs, _ast_module_refs, _bundler_refs, _is_script_ref

# These contracts assert AST-layer behaviour.  Without the optional esprima parser the
# engine falls back to line-based analysis, which cannot satisfy them -- skip instead of
# reporting a false regression.
requires_ast_parser = unittest.skipUnless(
    parser_available(),
    "needs the optional esprima AST parser (pip install esprima)",
)



class ModuleDiscoveryTest(unittest.TestCase):
    @requires_ast_parser
    def test_ast_layer_finds_imports_requires_and_dynamic_import(self):
        content = """
        import x from "./a.js";
        import { b } from "../b.mjs";
        const c = require("./lib/c.js");
        import("./lazy/d.js").then(m => m.run());
        import data from "./data.json";
        import "./side-effect.js";
        """
        refs = set(_ast_module_refs(content))
        self.assertIn("./a.js", refs)
        self.assertIn("../b.mjs", refs)
        self.assertIn("./lib/c.js", refs)
        self.assertIn("./lazy/d.js", refs)
        self.assertIn("./side-effect.js", refs)
        # JSON import must not be treated as a script.
        self.assertNotIn("./data.json", refs)

    def test_bundler_layer_finds_chunk_maps_and_hashed_assets(self):
        content = """
        const e = {12:"assets/index-Bq9k.js", 34:"chunks/vendor-Ab21.mjs"};
        const p = "/static/js/main.7f3a2b.js";
        fetch("/api/v1/users");
        """
        refs = set(_bundler_refs(content))
        self.assertTrue(any("index-Bq9k.js" in r for r in refs))
        self.assertTrue(any("main.7f3a2b.js" in r for r in refs))
        self.assertFalse(any("/api/" in r for r in refs))

    def test_extract_script_refs_matches_depth_analysis_contract(self):
        content = """
        import main from "./dep.js";
        import data from "./data.json";
        const helper = require("../utils/helper.js");
        import("./pages/home_123.js");
        const name = "chunk-42.js";
        fetch("/api/v1/items");
        new WebSocket("wss://example.com/live");
        """
        refs = extract_script_refs(content)
        self.assertIn("./dep.js", refs)
        self.assertIn("../utils/helper.js", refs)
        self.assertIn("./pages/home_123.js", refs)
        self.assertIn("chunk-42.js", refs)
        self.assertNotIn("./data.json", refs)
        self.assertNotIn("/api/v1/items", refs)
        self.assertNotIn("wss://example.com/live", refs)

    def test_non_script_references_are_filtered(self):
        self.assertTrue(_is_script_ref("./app.js"))
        self.assertTrue(_is_script_ref("assets/chunk-1.js"))
        self.assertFalse(_is_script_ref("./styles.css"))
        self.assertFalse(_is_script_ref("./data.json"))
        self.assertFalse(_is_script_ref("/api/v1/items"))
        self.assertFalse(_is_script_ref("https://example.com/img/logo.png"))

    def test_discovery_is_deterministic_and_sorted(self):
        content = 'import b from "./b.js"; import a from "./a.js";'
        first = discover_module_refs(content)
        second = discover_module_refs(content)
        self.assertEqual(first, second)
        self.assertEqual(first, sorted(first))


if __name__ == "__main__":
    unittest.main()
