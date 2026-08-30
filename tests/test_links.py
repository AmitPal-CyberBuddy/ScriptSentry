"""Link integrity for the hosted pages.

The hosted site is two static files, so a broken link is invisible until
a visitor clicks it -- there is no build step and no router to complain.
These checks are the build step.

They also encode a content rule that was broken before: the footer used
to carry four separate links that all pointed at the same GitHub repo,
each labelled as though it were its own destination ("Changelog",
"Documentation", "Report an Issue"), plus a "Next: Bundle Diffing" entry
that looked like a roadmap page but only jumped to the contact section.
Navigation should lead somewhere distinct.
"""
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
WEBUI = os.path.join(os.path.dirname(HERE), "webui")
PAGES = ["index.html", "tool.html"]

with open(os.path.join(WEBUI, "index.html"), encoding="utf-8") as fh:
    INDEX = fh.read()
with open(os.path.join(WEBUI, "tool.html"), encoding="utf-8") as fh:
    TOOL = fh.read()

PAGES_SRC = {"index.html": INDEX, "tool.html": TOOL}

# Anchors can legitimately live in either page when linked cross-page,
# so ids are pooled.
ALL_IDS = set()
for src in PAGES_SRC.values():
    ALL_IDS |= set(re.findall(r'id="([^"]+)"', src))


def links(src):
    return [(m.group(1), m.group(2)) for m in
            re.finditer(r"<a\b[^>]*href=\"([^\"]*)\"[^>]*>(.*?)</a>", src, re.S)]


class LinkTargetTest(unittest.TestCase):
    """Every href must lead somewhere that exists."""

    def test_internal_page_links_resolve(self):
        missing = []
        for page, src in PAGES_SRC.items():
            for href, _ in links(src):
                if not href or href.startswith(("#", "mailto:", "http")):
                    continue
                target = href.split("#")[0]
                if not target:
                    continue
                if not os.path.isfile(os.path.join(WEBUI, target)):
                    missing.append(f"{page}: {href}")
        self.assertEqual([], missing,
                         "Internal links point at files that do not exist.")

    def test_in_page_anchors_have_a_target(self):
        dangling = []
        for page, src in PAGES_SRC.items():
            for href, _ in links(src):
                if not href.startswith("#") or href == "#":
                    continue
                if href[1:] not in ALL_IDS:
                    dangling.append(f"{page}: {href}")
        self.assertEqual([], dangling, "Anchor links with no matching id.")

    def test_cross_page_anchors_have_a_target(self):
        dangling = []
        for page, src in PAGES_SRC.items():
            for href, _ in links(src):
                m = re.match(r"(index|tool)\.html#(.+)$", href)
                if not m:
                    continue
                if m.group(2) not in ALL_IDS:
                    dangling.append(f"{page}: {href}")
        self.assertEqual([], dangling, "Cross-page anchors with no target id.")

    def test_no_placeholder_hrefs(self):
        bad = []
        for page, src in PAGES_SRC.items():
            for href, _ in links(src):
                if href in ("#", "", "javascript:void(0)"):
                    bad.append(f"{page}: {href!r}")
        self.assertEqual([], bad, "Placeholder hrefs.")

    def test_asset_references_resolve(self):
        missing = []
        for page, src in PAGES_SRC.items():
            for href in re.findall(r'href="(assets/[^"]+)"', src):
                if not os.path.isfile(os.path.join(WEBUI, href)):
                    missing.append(f"{page}: {href}")
            for src_attr in re.findall(r'src="(assets/[^"]+)"', src):
                if not os.path.isfile(os.path.join(WEBUI, src_attr)):
                    missing.append(f"{page}: {src_attr}")
        self.assertEqual([], missing, "Missing asset files.")


class ExternalLinkTest(unittest.TestCase):
    def test_blank_targets_are_safe(self):
        """target=_blank without rel=noopener exposes window.opener."""
        bad = []
        for page, src in PAGES_SRC.items():
            for m in re.finditer(r"<a\b([^>]*)>", src):
                attrs = m.group(1)
                if 'target="_blank"' not in attrs:
                    continue
                if "noopener" not in attrs:
                    bad.append(f"{page}: {attrs.strip()[:70]}")
        self.assertEqual([], bad, "target=_blank without rel=noopener.")


class NavigationQualityTest(unittest.TestCase):
    """Navigation should lead somewhere distinct."""

    @staticmethod
    def _footer_links(src):
        start = src.index('<footer class="site-footer">')
        end = src.index("</footer>", start)
        return links(src[start:end])

    def test_footer_has_no_dead_end_links(self):
        """A footer link that scrolls to a section the header already
        reaches is noise, not navigation."""
        for page, src in PAGES_SRC.items():
            hrefs = [h for h, _ in self._footer_links(src)]
            self.assertNotIn(
                "#connect", hrefs,
                f"{page}: the footer links to #connect, which the header "
                "already covers and which is not a distinct destination.",
            )

    def test_footer_does_not_repeat_one_destination(self):
        """Four links to the same repo read as four missing pages."""
        for page, src in PAGES_SRC.items():
            gh = [h for h, _ in self._footer_links(src)
                  if "github.com" in h]
            self.assertLessEqual(
                len(set(gh)), 1,
                f"{page}: {len(set(gh))} distinct GitHub destinations in the "
                "footer. Label one entry as the way to source, docs and "
                "changelog rather than listing each as its own link.",
            )

    def test_footer_stays_lean(self):
        for page, src in PAGES_SRC.items():
            count = len(self._footer_links(src))
            self.assertLessEqual(
                count, 8,
                f"{page}: footer has {count} links; it should be a short "
                "wayfinding list, not a sitemap.",
            )


class ContentHygieneTest(unittest.TestCase):
    def test_no_coming_soon_copy(self):
        for page, src in PAGES_SRC.items():
            low = src.lower()
            for phrase in ("coming soon", "tbd", "under construction"):
                self.assertNotIn(phrase, low, f"{page}: placeholder copy.")

    def test_legal_notice_is_not_repeated_more_than_twice(self):
        """A notice repeated three times on one page stops being read."""
        for page, src in PAGES_SRC.items():
            n = src.lower().count("authorized testing only")
            self.assertLessEqual(
                n, 2, f"{page}: 'authorized testing only' appears {n} times.",
            )


if __name__ == "__main__":
    unittest.main()
