"""UI/UX quality gates for the shipped web pages.

These encode the checks from the UI/UX review pass (design-skill pre-delivery
checklist): WCAG AA contrast for the declared token pairs, one visible global
focus ring, reduced-motion support, 44px touch targets on primary controls,
accessible names for icon-only controls, live regions for dynamic status
text, and clean SVG markup (the emoji->SVG migration once left stray quote
text nodes inside every icon -- this suite exists so that class of bug can
never ship again).
"""
import os
import re
import unittest
from html.parser import HTMLParser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEBUI = os.path.join(ROOT, "webui")
STYLES = os.path.join(WEBUI, "styles.css")
PAGES = [os.path.join(WEBUI, p) for p in
         ("tool/index.html", "home/index.html", "rules/index.html",
          "changelog/index.html")]


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# ---------------------------------------------------------------- contrast

def _hex_to_rgb(value):
    value = value.lstrip("#")
    return tuple(int(value[i:i + 2], 16) / 255 for i in (0, 2, 4))


def _relative_luminance(hexcolor):
    r, g, b = _hex_to_rgb(hexcolor)
    def channel(c):
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def contrast_ratio(fg, bg):
    l1, l2 = _relative_luminance(fg), _relative_luminance(bg)
    hi, lo = max(l1, l2), min(l1, l2)
    return (hi + 0.05) / (lo + 0.05)


def design_tokens():
    """Parse the :root custom properties out of styles.css."""
    css = _read(STYLES)
    root = css.split(":root", 1)[1].split("}", 1)[0]
    return dict(re.findall(r"(--[\w-]+):\s*(#[0-9a-fA-F]{6})", root))


class ColorContrastTest(unittest.TestCase):
    """WCAG 2.1 AA: normal-size text needs 4.5:1 against every surface it
    is declared on. The palette is dark-only by design, so panels are the
    worst case surfaces."""

    def test_text_tokens_pass_aa_on_every_surface(self):
        tokens = design_tokens()
        surfaces = [tokens["--bg"], tokens["--panel"], tokens["--panel-2"]]
        for name in ("--text", "--muted", "--faint", "--primary", "--primary-2",
                     "--danger", "--warning", "--success", "--accent"):
            for surface in surfaces:
                ratio = contrast_ratio(tokens[name], surface)
                self.assertGreaterEqual(
                    ratio, 4.5,
                    f"{name} ({tokens[name]}) on {surface} is {ratio:.2f}:1 "
                    f"-- WCAG AA needs 4.5:1")

    def test_button_text_passes_on_primary_fill(self):
        tokens = design_tokens()
        # .btn primary text is #04131c on the cyan fill.
        ratio = contrast_ratio("#04131c", tokens["--primary"])
        self.assertGreaterEqual(ratio, 4.5)


# ---------------------------------------------------------------- markup

class SvgMarkupTest(unittest.TestCase):
    def test_no_stray_quote_text_nodes_inside_icons(self):
        """The migration to inline SVGs once wrapped every path group in
        stray quotes (<svg ...>'<path/>'</svg>): invisible, but malformed.
        Icons must contain only elements."""
        for page in PAGES:
            with self.subTest(page=os.path.relpath(page, ROOT)):
                html = _read(page)
                self.assertNotIn(">'<", html)
                self.assertNotIn("'</svg>", html)
                self.assertNotIn(">'<", _read(os.path.join(WEBUI, "app.js")))


# ------------------------------------------------------- focus and motion

class FocusAndMotionTest(unittest.TestCase):
    def test_global_focus_visible_ring(self):
        css = _read(STYLES)
        self.assertRegex(css, r"(^|\n):focus-visible\s*\{[^}]*outline")

    def test_inputs_that_remove_outline_have_a_focus_style(self):
        css = _read(STYLES)
        # The console inputs drop the native ring...
        self.assertIn("textarea:focus,", css)
        # ...but must replace it with a visible border/box-shadow change.
        block = css.split("textarea:focus,", 1)[1].split("}", 1)[0]
        self.assertTrue("border-color" in block or "box-shadow" in block,
                        "focused inputs must show a visible change")

    def test_reduced_motion_neutralizes_animation(self):
        css = _read(STYLES)
        self.assertIn("@media (prefers-reduced-motion: reduce)", css)
        self.assertRegex(css, r"prefers-reduced-motion: reduce[^@]*"
                              r"animation-duration: 0\.001ms")

    def test_dark_only_ui_declares_color_scheme(self):
        # Native controls, scrollbars and autofill styles follow the page
        # scheme; without this they render light on a dark UI.
        self.assertRegex(_read(STYLES), r"(^|\n):root\s*\{[^}]*color-scheme: dark")


# ------------------------------------------------------------ touch + a11y

class TouchTargetTest(unittest.TestCase):
    def test_primary_controls_meet_44px_minimum(self):
        css = _read(STYLES)
        for selector in (".btn {", ".view-tab {"):
            block = css.split(selector, 1)[1].split("}", 1)[0]
            m = re.search(r"min-height:\s*(\d+)px", block)
            self.assertIsNotNone(m, f"{selector} must declare a min-height")
            self.assertGreaterEqual(int(m.group(1)), 44,
                                    f"{selector} target must be >= 44px")

    def test_clickable_chips_have_pointer_cursor(self):
        css = _read(STYLES)
        for selector in (".file-tab {", ".status-chip {"):
            block = css.split(selector, 1)[1].split("}", 1)[0]
            self.assertIn("cursor: pointer", block,
                          selector + " must look clickable")


class _ButtonAudit(HTMLParser):
    """Collect <button>/<a> elements whose content is only an icon."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.icon_only = []
        self._stack = []

    def handle_starttag(self, tag, attrs):
        if tag not in ("button", "a"):
            return
        attrs = dict(attrs)
        # A control is fine if it is named for a11y or hidden entirely.
        named = "aria-label" in attrs or attrs.get("title") or attrs.get("aria-hidden") == "true"
        self._stack.append({"tag": tag, "named": named or "aria-label" in attrs,
                            "ok": bool(named), "text": ""})

    def handle_startendtag(self, tag, attrs):
        # <svg/> never happens, but self-closing children are fine.
        pass

    def handle_data(self, data):
        if self._stack:
            self._stack[-1]["text"] += data

    def handle_endtag(self, tag):
        if tag in ("button", "a") and self._stack:
            el = self._stack.pop()
            has_text = bool(el["text"].strip())
            if not has_text and not el["ok"]:
                self.icon_only.append((tag, self.getpos()))


class AccessibleNamesTest(unittest.TestCase):
    def test_icon_only_controls_have_accessible_names(self):
        for page in PAGES[:2]:  # interactive pages
            with self.subTest(page=os.path.relpath(page, ROOT)):
                parser = _ButtonAudit()
                parser.feed(_read(page))
                self.assertEqual(
                    [], parser.icon_only,
                    "icon-only controls need aria-label or title")

    def test_dynamic_status_regions_are_live(self):
        html = _read(PAGES[0])
        m = re.search(r'id="storage-status"[^>]*', html)
        self.assertIsNotNone(m)
        self.assertIn("aria-live", m.group(0))


if __name__ == "__main__":
    unittest.main()
