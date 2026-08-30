"""Generated documentation pages and the metadata that describes them.

``webui/changelog.html`` is generated from ``CHANGELOG.md`` by
``tools/build_changelog.py``. That is only a promise if something checks
it, so the first test here runs the generator in ``--check`` mode and
fails when the committed page has drifted from the file a person
actually edits.

The rest apply the static-site contract to the changelog page. It is a
third page on the hosted site, but the completeness test in
``test_hardening.py`` only ever knew about two, so nothing was stopping
it from quietly losing its stylesheet, its CSP or its shared scripts.
"""
import os
import re
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WEBUI = os.path.join(ROOT, "webui")
CHANGELOG_HTML = os.path.join(WEBUI, "changelog.html")
GENERATOR = os.path.join(ROOT, "tools", "build_changelog.py")

with open(CHANGELOG_HTML, encoding="utf-8") as fh:
    PAGE = fh.read()


class GeneratedPageFreshnessTest(unittest.TestCase):
    """The committed page must match what CHANGELOG.md renders to."""

    def test_changelog_page_is_up_to_date(self):
        proc = subprocess.run(
            [sys.executable, GENERATOR, "--check"],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertEqual(
            proc.returncode, 0,
            "webui/changelog.html is out of date. Regenerate it with:\n"
            "    python3 tools/build_changelog.py\n"
            f"generator said: {proc.stdout.strip()}{proc.stderr.strip()}",
        )

    def test_page_is_generated_not_hand_edited(self):
        """A hand-edited page would silently diverge from CHANGELOG.md
        on the next release. The banner marks it as machine-written."""
        self.assertIn(
            "generated from CHANGELOG.md", PAGE,
            "changelog.html lost its generated-from banner; it looks "
            "hand-edited.",
        )


class ChangelogPageContractTest(unittest.TestCase):
    """The changelog page obeys the same rules as the other two pages."""

    def test_shared_assets_are_linked(self):
        for asset in ('href="styles.css"', 'src="config.js"', 'src="app.js"'):
            self.assertIn(asset, PAGE,
                          f"changelog.html is missing {asset}.")

    def test_content_security_policy_is_present(self):
        self.assertIn("Content-Security-Policy", PAGE,
                      "changelog.html has no CSP.")

    def test_no_external_fonts(self):
        self.assertNotIn(
            "fonts.googleapis.com", PAGE,
            "changelog.html pulls a font from Google; the site is "
            "static-only and must not make third-party requests.",
        )

    def test_no_inline_scripts(self):
        """The CSP sets script-src 'self', so an inline script would be
        blocked and the page would break silently."""
        self.assertEqual(
            [], re.findall(r"<script(?![^>]*\bsrc=)[^>]*>", PAGE),
            "changelog.html has an inline <script>, which its own CSP "
            "would block.",
        )

    def test_exactly_one_h1(self):
        self.assertEqual(
            1, len(re.findall(r"<h1\b", PAGE)),
            "changelog.html should have exactly one h1.",
        )

    def test_does_not_link_to_raw_repository_files(self):
        """A visitor clicking 'Changelog' expects a page, not a file
        listing. Links out to the repo should go to destinations that
        read as pages in their own right."""
        # Only real anchors count. Changelog prose quotes markup inside
        # <code> spans (e.g. describing the old launcher download bug),
        # and that text must not be mistaken for a link.
        raw = [
            href for href in re.findall(r'<a\b[^>]*href="([^"]+)"', PAGE)
            if "raw.githubusercontent.com" in href
            or href.endswith((".md", ".txt", ".json"))
        ]
        self.assertEqual(
            [], raw,
            f"changelog.html links to raw file locations: {raw}. Build a "
            "page for it or drop the link.",
        )

    def test_releases_have_anchor_targets(self):
        """Each release is a section with an id, so a version can be
        linked to directly."""
        sections = re.findall(r'<section class="release" id="([^"]+)"', PAGE)
        self.assertTrue(sections, "No release sections were rendered.")
        for slug in sections:
            self.assertRegex(
                slug, r"^[a-z0-9]+(?:-[a-z0-9]+)*$",
                f"Release anchor {slug!r} is not a clean slug.",
            )


if __name__ == "__main__":
    unittest.main()
