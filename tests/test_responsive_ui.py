"""Responsive contract tests for the hosted web UI.

These do not render anything -- there is no browser in CI. They assert
the *structural* invariants that make the layout responsive, because
every one of them corresponds to a real bug this stylesheet has had:

  * a bare `1fr` track that pushed the page wider than the viewport
  * an auto-fit minimum wider than the container it lived in
  * a media-query override that lost the cascade to a later base rule,
    which silently disabled the mobile navigation entirely
  * a fluid font-size set on <html>, which moved the rem basis out from
    under every clamp() in the file

The checks are deliberately literal: they read the stylesheet as text
so a failure points at the line that caused it.
"""
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
WEBUI = os.path.join(os.path.dirname(HERE), "webui")
CSS_PATH = os.path.join(WEBUI, "styles.css")

with open(CSS_PATH, encoding="utf-8") as fh:
    CSS = fh.read()


def strip_comments(text):
    out, i, n = [], 0, len(text)
    while i < n:
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j == -1 else j + 2
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


CSS_NC = strip_comments(CSS)


def declarations(prop):
    """Every (selector, value) for `prop`, including inside media queries."""
    found = []
    for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", CSS_NC):
        selector = m.group(1).strip()
        if selector.startswith("@") or "{" in selector:
            continue
        dm = re.search(r"(?:^|;)\s*" + re.escape(prop) + r"\s*:\s*([^;]+)", m.group(2))
        if dm:
            found.append((selector, dm.group(1).strip()))
    return found


def line_of(needle):
    for i, line in enumerate(CSS.splitlines(), 1):
        if needle in line:
            return i
    return None


def _media_ranges():
    out = []
    for m in re.finditer(r"@media[^{]*\{", CSS_NC):
        depth, i = 1, m.end()
        while i < len(CSS_NC) and depth:
            depth += CSS_NC[i] == "{"
            depth -= CSS_NC[i] == "}"
            i += 1
        out.append((m.start(), i, CSS_NC[m.start():m.end()]))
    return out


MEDIA_RANGES = _media_ranges()


def _media_cond_at(pos):
    for start, end, head in MEDIA_RANGES:
        if start <= pos < end:
            return head
    return None


def _matches(cond, width):
    if not cond:
        return True
    for part in re.split(r"\band\b", cond.replace("@media", "").strip().strip("{}()")):
        part = part.strip().strip("()")
        if part.startswith("prefers-") or part.startswith("pointer"):
            return False
        m = re.match(r"(min|max)-width:\s*([0-9]+)px", part)
        if not m:
            return False
        kind, val = m.group(1), int(m.group(2))
        if kind == "min" and width < val:
            return False
        if kind == "max" and width > val:
            return False
    return True


def resolve_at(selector, prop, width):
    """Cascade-last value of `prop` for `selector` at a viewport width."""
    value = None
    for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", CSS_NC):
        if any(a <= m.start() < b for a, b, _ in MEDIA_RANGES):
            # inside some @media body -- check that block's condition
            pass
        sel = m.group(1).strip()
        if sel.startswith("@"):
            continue
        if not _matches(_media_cond_at(m.start()), width):
            continue
        for part in [x.strip() for x in sel.split(",")]:
            if part != selector:
                continue
            dm = re.search(r"(?:^|;)\s*" + re.escape(prop) + r"\s*:\s*([^;]+)",
                           m.group(2))
            if dm:
                value = dm.group(1).strip()
    return value


def track_count(value):
    m = re.match(r"repeat\(\s*(\d+)\s*,", value or "")
    return int(m.group(1)) if m else (1 if value else 0)



class GridTrackTest(unittest.TestCase):
    """Grid tracks must be able to shrink below their content width."""

    def test_no_bare_fr_tracks(self):
        offenders = []
        for selector, value in declarations("grid-template-columns"):
            if "1fr" not in value:
                continue
            if "minmax(0" in value or "min(" in value:
                continue
            if "auto-fit" in value or "auto-fill" in value:
                continue
            offenders.append(f"{selector}: {value}")
        self.assertEqual(
            [], offenders,
            "Bare 1fr tracks resolve to minmax(auto, 1fr) and refuse to shrink "
            "below their content, which pushes the page into horizontal scroll. "
            "Use minmax(0, 1fr).",
        )

    def test_autofit_minimums_are_container_bounded(self):
        offenders = []
        for selector, value in declarations("grid-template-columns"):
            for m in re.finditer(r"minmax\(\s*([0-9.]+)px\s*,", value):
                if "min(100%" not in value:
                    offenders.append(f"{selector}: {value}")
        self.assertEqual(
            [], offenders,
            "auto-fit tracks with a hard px minimum overflow any container "
            "narrower than that minimum. Wrap it: minmax(min(100%, Npx), 1fr).",
        )


class GridCompositionTest(unittest.TestCase):
    """Item counts that do not divide by every track count need care."""

    @staticmethod
    def _rule_body(selector):
        m = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", CSS_NC)
        return m.group(1) if m else ""

    def test_steps_never_land_on_three_tracks(self):
        """Four step cards on three tracks leave one stranded alone."""
        body = self._rule_body(".steps")
        self.assertIn("grid-template-columns", body)
        self.assertNotIn(
            "auto-fit", body,
            "auto-fit puts 4 steps on 3 tracks between ~880 and ~1170px, "
            "stranding a single card on its own row. Use an explicit "
            "4 / 2 / 1 ladder -- those are the counts 4 divides into.",
        )
        # The ladder itself: 4 tracks by default, 2 and 1 on the way down.
        self.assertIn("@media (max-width: 880px)", CSS_NC)
        self.assertIn("@media (max-width: 560px)", CSS_NC)

    def test_feature_grid_is_capped_at_four_tracks(self):
        """Eight feature cards on five tracks leave a lopsided 5 + 3."""
        self.assertIn(
            "@media (min-width: 1700px)", CSS_NC,
            "auto-fit reaches 5 tracks on a wide monitor; cap it at 4 so "
            "the eight cards form two even rows.",
        )

    def test_metric_tiles_stay_four_up_on_a_tablet(self):
        """Four stat tiles on two tracks are 360px boxes -- mostly air."""
        for width in (768, 820, 1024, 1280, 1440):
            self.assertEqual(
                4, track_count(resolve_at("#metrics.grid-4",
                                          "grid-template-columns", width)),
                f"#{width}px: stat tiles dropped below four across, which "
                "leaves a 42px number adrift in a very wide card.",
            )

    def test_metric_tiles_go_two_up_on_a_phone(self):
        for width in (320, 414, 600):
            self.assertEqual(
                2, track_count(resolve_at("#metrics.grid-4",
                                          "grid-template-columns", width)),
                f"#{width}px: four stat tiles do not fit across a phone.",
            )

    def test_grids_never_produce_a_single_track_wider_than_700px(self):
        """Two-up cards stop reading as cards past ~700px.

        Calibrated against the bug it guards: widening the console
        container produced 750-830px tracks on a 1920px screen, which
        turned the overview cards into letterboxes. Two-up at ~600px is
        normal for a dashboard and passes.
        """
        for width in (768, 1024, 1280, 1920, 2560):
            for selector in (".grid-2", ".grid-3"):
                n = track_count(resolve_at(selector, "grid-template-columns", width))
                if not n:
                    continue
                avail = min(width, 1440) - 2 * 40
                self.assertLessEqual(
                    (avail - (n - 1) * 18) / n, 700,
                    f"{selector} at {width}px produces over-wide cards.",
                )

    def test_console_container_is_not_wider_than_the_content_column(self):
        """A wider console only stretched the two-up overview cards."""
        m = re.search(r"--container-wide:\s*([0-9]+)px", CSS_NC)
        self.assertIsNotNone(m, "--container-wide must be defined")
        self.assertLessEqual(
            int(m.group(1)), 1400,
            "Widening the console past the landing measure turned the "
            "two-up overview cards into letterboxes; its density is "
            "vertical (lists), not horizontal.",
        )


class CascadeOrderTest(unittest.TestCase):
    """A media query is not a specificity bump -- source order decides."""

    def test_nav_toggle_override_wins(self):
        base = CSS_NC.index(".nav-toggle {")
        base_display = CSS_NC.index("display: none;", base)
        mq = CSS_NC.index("@media (max-width: 1040px)")
        override = CSS_NC.index("display: inline-flex;", mq)
        self.assertGreater(
            override, base_display,
            "The hamburger button is display:none by default; the override that "
            "shows it below 1040px must come LATER in the file or it loses the "
            "cascade and the mobile navigation becomes unreachable.",
        )

    @staticmethod
    def _specificity(selector):
        sel = re.sub(r"::?[a-zA-Z-]+(\([^)]*\))?", "", selector)
        ids = len(re.findall(r"#", sel))
        classes = len(re.findall(r"\.|\[", sel))
        tags = len(re.findall(r"(?:^|[\s>+~])([a-zA-Z][a-zA-Z0-9]*)", sel))
        return (ids, classes, tags)

    @staticmethod
    def _decls(block):
        out = {}
        for d in block.split(";"):
            if ":" in d:
                k, v = d.split(":", 1)
                out[k.strip()] = v.strip()
        return out

    def test_no_media_override_precedes_its_base_rule(self):
        """Every width-based override must sit after the rule it overrides.

        Only flagged when the override re-declares a property the base
        rule also sets AND the two selectors have equal specificity --
        otherwise the override legitimately wins on its own.
        """
        # Ranges occupied by @media bodies, so their inner rules are not
        # mistaken for top-level base rules (an override would otherwise
        # be compared against itself).
        media_ranges = []
        for m in re.finditer(r"@media[^{]*\{", CSS_NC):
            depth, i = 1, m.end()
            while i < len(CSS_NC) and depth:
                depth += CSS_NC[i] == "{"
                depth -= CSS_NC[i] == "}"
                i += 1
            media_ranges.append((m.end(), i))

        plain = {}
        for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", CSS_NC):
            if any(a <= m.start() < b for a, b in media_ranges):
                continue
            sel = m.group(1).strip()
            if sel.startswith("@"):
                continue
            for part in [p.strip() for p in sel.split(",")]:
                if part:
                    plain.setdefault(part, []).append((m.end(), self._decls(m.group(2))))

        offenders = []
        for m in re.finditer(r"@media[^{]*\(max-width:\s*[0-9]+px\)[^{]*\{", CSS_NC):
            block_start = m.end()
            depth, i = 1, block_start
            while i < len(CSS_NC) and depth:
                depth += CSS_NC[i] == "{"
                depth -= CSS_NC[i] == "}"
                i += 1
            block = CSS_NC[block_start:i - 1]
            for bm in re.finditer(r"([^{}]+)\{([^{}]*)\}", block):
                sel = bm.group(1).strip()
                if sel.startswith("@"):
                    continue
                mq_decls = self._decls(bm.group(2))
                for part in [p.strip() for p in sel.split(",")]:
                    for end, base_decls in plain.get(part, []):
                        shared = set(mq_decls) & set(base_decls)
                        if not shared:
                            continue
                        if end <= block_start:
                            continue  # base comes first: override wins
                        if self._specificity(part) != self._specificity(part):
                            continue
                        offenders.append(f"{part} -> {sorted(shared)}")
        self.assertEqual(
            [], sorted(set(offenders)),
            "These selectors have a base rule later in the file than their "
            "media-query override, so the override never applies.",
        )


class ViewportUnitTest(unittest.TestCase):
    """dvh must never ship without a vh fallback ahead of it."""

    def test_every_dvh_has_a_vh_fallback(self):
        lines = CSS_NC.splitlines()
        offenders = []
        for i, line in enumerate(lines):
            if "dvh" in line and re.search(r"^\s*[a-z-]+\s*:", line):
                prev = lines[i - 1] if i else ""
                prop = line.split(":")[0].strip()
                if prop not in prev or "dvh" in prev:
                    offenders.append(line.strip())
        self.assertEqual([], offenders,
                         "dvh is unsupported on older browsers; declare the vh "
                         "value first and let dvh override it.")


class TypographyTest(unittest.TestCase):
    def test_base_font_size_is_not_on_html(self):
        """A fluid font-size on <html> moves the rem basis under every clamp()."""
        for m in re.finditer(r"(^|\})\s*(html|html,\s*body|body,\s*html)\s*\{([^}]*)\}",
                             CSS_NC, re.M):
            body = m.group(3)
            self.assertNotIn(
                "font-size", body,
                "Do not set font-size on <html>: it redefines rem, so every "
                "clamp() written in rem scales twice over, and it overrides the "
                "visitor's own browser font-size setting. Put it on <body>.",
            )

    def test_no_micro_type(self):
        tiny = sorted({v for v in re.findall(r"font-size:\s*([0-9.]+)px", CSS_NC)
                       if float(v) < 11.5})
        self.assertEqual([], tiny,
                         "Sub-11.5px text is unreadable on a phone; use the "
                         "fluid type tokens instead.")


class OverflowTest(unittest.TestCase):
    def test_no_wide_fixed_widths(self):
        offenders = []
        for prop in ("width", "min-width"):
            for selector, value in declarations(prop):
                m = re.fullmatch(r"([0-9.]+)px", value)
                if m and float(m.group(1)) > 280:
                    offenders.append(f"{selector} {{ {prop}: {value} }}")
        self.assertEqual([], offenders,
                         "A fixed width above 280px cannot fit a 320px viewport; "
                         "use min(Npx, 100%) or a fluid clamp.")

    def test_overflow_x_hidden_is_a_backstop_not_a_fix(self):
        hits = re.findall(r"overflow-x:\s*hidden", CSS_NC)
        self.assertLessEqual(
            len(hits), 1,
            "overflow-x:hidden hides the symptom. Fix the element that "
            "overflows instead of clipping the page.",
        )

    def test_no_zoom_or_scale_layout_hacks(self):
        self.assertNotIn("zoom:", CSS_NC,
                         "`zoom` is not a responsive strategy.")


class TouchTargetTest(unittest.TestCase):
    def test_coarse_pointer_block_exists(self):
        self.assertIn("@media (pointer: coarse)", CSS_NC,
                      "Touch devices need enlarged tap targets.")

    def test_tap_token_is_44px(self):
        self.assertIn("--tap: 44px", CSS_NC,
                      "The tap-target token should be 44px.")

    def test_interactive_controls_get_the_tap_floor(self):
        block = CSS_NC.split("@media (pointer: coarse)")[-1]
        block = block[:block.index("}")]
        for selector in (".tab", ".view-tab", ".engine-pill", ".btn"):
            self.assertIn(selector, block,
                          f"{selector} should be given a 44px minimum on touch.")


class BreakpointTest(unittest.TestCase):
    def test_breakpoints_cover_phone_to_ultrawide(self):
        widths = sorted({int(v) for v in re.findall(
            r"(?:max|min)-width:\s*([0-9]+)px", CSS_NC)})
        self.assertTrue(any(w <= 640 for w in widths),
                        "There must be a phone breakpoint.")
        self.assertTrue(any(768 <= w <= 1100 for w in widths),
                        "There must be a tablet breakpoint.")
        self.assertTrue(any(w >= 1400 for w in widths),
                        "Large displays need containment or a dedicated layout.")

    def test_ultrawide_content_is_contained(self):
        self.assertIn("min-width: 1600px", CSS_NC,
                      "Past 1600px the content width must be capped so it does "
                      "not stretch across a 2560px monitor.")


if __name__ == "__main__":
    unittest.main()
