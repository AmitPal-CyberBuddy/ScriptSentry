"""Presentation pass: SVG icons, print themes, CWE in SARIF + rule reference.

The emoji chrome is gone from the hosted pages (emoji render differently on
every platform and read as decoration), print gets a light theme on both the
dashboard and the exported HTML report, and SARIF/rules docs carry the
standard CWE mapping.
"""
import json
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_JS = os.path.join(ROOT, "webui", "app.js")
TOOL_HTML = os.path.join(ROOT, "webui", "tool", "index.html")
HOME_HTML = os.path.join(ROOT, "webui", "home", "index.html")
STYLES = os.path.join(ROOT, "webui", "styles.css")

# Emoji ranges; deliberately excludes text symbols that carry meaning
# (✓ ✗ ▲ ▼ ＋) and the status-message prefix contract in app.js.
_EMOJI = re.compile(
    "([\U0001F000-\U0001FAFF\U00002600-\U000026FF\U00002700-\U000027BF"
    "\U00002B00-\U00002BFF\u2705\u2716])\ufe0f?")


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class IconMigrationTest(unittest.TestCase):
    def test_hosted_pages_have_no_emoji_chrome(self):
        for path in (TOOL_HTML, HOME_HTML):
            with self.subTest(page=os.path.basename(os.path.dirname(path))):
                self.assertEqual([], _EMOJI.findall(_read(path)),
                                 "emoji chrome must be SVG icons")

    def test_hosted_pages_use_inline_svg_icons(self):
        for path in (TOOL_HTML, HOME_HTML):
            with self.subTest(page=os.path.basename(os.path.dirname(path))):
                self.assertGreater(_read(path).count('<svg class="icon"'), 10)

    def test_app_bundle_ships_the_icon_system(self):
        src = _read(APP_JS)
        self.assertIn("function svgIcon", src)
        self.assertIn("ICON_PATHS", src)
        # A real set, not a stub: at least forty distinct icon shapes.
        self.assertGreaterEqual(len(re.findall(r"<path d=|<rect |<circle ", src)), 40)

    def test_icon_css_exists(self):
        css = _read(STYLES)
        self.assertIn(".icon {", css)
        self.assertIn(".step-ico .icon", css)

    def test_icons_inherit_color_and_scale(self):
        css = _read(STYLES)
        self.assertRegex(css, r"\.icon \{[^}]*width: 1em;")
        self.assertIn("vertical-align", css.split(".icon {")[1].split("}")[0])
        # Color inheritance lives on the SVG wrapper the helper emits.
        self.assertIn('stroke="currentColor"', _read(APP_JS))

    def test_meaningful_text_symbols_survive(self):
        src = _read(APP_JS)
        # The status-message prefix contract (setStorageStatus / startsWith).
        self.assertIn('startsWith("✅")', src)


class PrintThemeTest(unittest.TestCase):
    def test_dashboard_print_stylesheet(self):
        css = _read(STYLES)
        self.assertIn("@media print", css)
        block = css.split("@media print", 1)[1]
        self.assertIn("background: #fff", block, "print must be light")
        self.assertIn("break-inside: avoid", block, "cards must not split")
        self.assertIn(".site-nav", block, "navigation chrome must hide")
        self.assertIn("#console", block, "the input console must hide")

    def test_html_report_prints_light_and_unsplit(self):
        import sys
        sys.path.insert(0, ROOT)
        from core.reporter import generate_html_report
        results = {"app.js": {"findings": [
            {"id": "dom_injection", "severity": "HIGH", "type": "DOM injection",
             "file": "app.js", "sink": "el.innerHTML = q", "line": 3,
             "evidence": ["q -> el.innerHTML"], "confidence": "high",
             "status": "open"}], "name": "app.js"},
            "__scan_summary__": {"files": 1}}
        html = generate_html_report(results, metadata={"mode": "code", "source": "app.js"})
        self.assertIn("@media print", html)
        self.assertIn("print-color-adjust: exact", html,
                      "severity chips are the one place color carries meaning")
        self.assertIn("break-inside: avoid", html)
        # The gradient header must gain print-safe dark-on-white colors.
        self.assertIn(".hd { background: #fff", html)
        # Headings are icons, not emoji.
        self.assertEqual([], _EMOJI.findall(html))
        self.assertIn('<svg class="icon"', html)


class SarifCweTest(unittest.TestCase):
    def _sarif(self):
        import sys
        sys.path.insert(0, ROOT)
        from core.reporter import generate_sarif_report
        results = {"app.js": {"findings": [
            {"id": "dom_injection", "severity": "HIGH", "type": "DOM injection",
             "file": "app.js", "sink": "el.innerHTML = q", "line": 3,
             "evidence": ["q -> el.innerHTML"], "confidence": "high",
             "status": "open"},
            {"id": "api_surface", "severity": "INFO", "type": "API surface mapped",
             "file": "app.js", "line": 5, "evidence": ["fetch"], "confidence": "medium",
             "status": "informational", "observation": True}],
            "name": "app.js"},
            "__scan_summary__": {"files": 1}}
        return json.loads(generate_sarif_report(results))

    def test_rules_carry_cwe_tag_and_helpuri(self):
        sarif = self._sarif()
        rules = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        self.assertIn("cwe-79", rules["dom_injection"]["properties"]["tags"])
        self.assertEqual(rules["dom_injection"]["properties"]["cwe"], "CWE-79")
        self.assertEqual(rules["dom_injection"]["helpUri"],
                         "https://amitpal-cyberbuddy.github.io/ScriptSentry/rules/#dom_injection")

    def test_results_carry_cwe_and_cvss_severity(self):
        sarif = self._sarif()
        by_rule = {r["ruleId"]: r for r in sarif["runs"][0]["results"]}
        self.assertEqual(by_rule["dom_injection"]["properties"]["cwe"], "CWE-79")
        self.assertEqual(by_rule["dom_injection"]["properties"]["security-severity"], "8.0")

    def test_inventory_rules_stay_unmapped(self):
        sarif = self._sarif()
        rules = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        self.assertNotIn("cwe", rules["api_surface"]["properties"])
        self.assertFalse(any(t.startswith("cwe-") for t in rules["api_surface"]["properties"]["tags"]))

    def test_rule_descriptions_are_plain_language(self):
        sarif = self._sarif()
        rules = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        # From PLAIN_TERMS, not the internal id.
        self.assertEqual(rules["dom_injection"]["shortDescription"]["text"],
                         "Unsafe use of page content")

    def test_cwe_map_only_names_real_findings(self):
        # The rendered rule reference is the registry of real finding ids:
        # every rule section plus the documented legacy aliases.
        import sys
        sys.path.insert(0, ROOT)
        from core.reporter import CWE_MAP
        doc = _read(os.path.join(ROOT, "docs", "RULES.md"))
        documented = set(re.findall(r"^### `([\w:]+)`", doc, re.M))
        documented |= set(re.findall(r"^- `(\w+)` —", doc, re.M))
        unknown = sorted(k.rstrip(":") for k in CWE_MAP
                         if k.rstrip(":") not in documented)
        self.assertEqual([], unknown, "CWE_MAP names ids the engine never reports")

    def test_rules_reference_shows_cwe(self):
        doc = _read(os.path.join(ROOT, "docs", "RULES.md"))
        self.assertIn("CWE-79", doc)
        self.assertIn("https://cwe.mitre.org/data/definitions/79.html", doc)
        page = _read(os.path.join(ROOT, "webui", "rules", "index.html"))
        self.assertIn('class="sev-chip sev-cwe"', page)


if __name__ == "__main__":
    unittest.main()
