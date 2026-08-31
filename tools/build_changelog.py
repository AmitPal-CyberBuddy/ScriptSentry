#!/usr/bin/env python3
"""Render ``CHANGELOG.md`` into the hosted page ``webui/changelog/index.html``.

The hosted UI is a set of plain static files (GitHub Pages serves ``webui/``
as-is), so "Changelog" has to be a real page rather than a link into the
repository. This script keeps that page honest: it is *generated* from
``CHANGELOG.md``, so the site can never drift from the file that actually gets
edited when something changes.

Run it after editing the changelog::

    python3 tools/build_changelog.py

Three things keep the result in sync:

* the page is generated from the source file (no hand-edited copy to rot),
* ``tests/test_docs.py`` fails if the committed page is out of date, and
* the Pages workflow regenerates it on every deploy as a safety net.

The page chrome (head, header, footer) is lifted straight out of
``index.html`` so a change to the site's navigation or metadata lands on the
changelog page too, without anyone having to remember to copy it over.
"""

from __future__ import annotations

import html
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "CHANGELOG.md"
WEBUI = ROOT / "webui"
INDEX = WEBUI / "home" / "index.html"
OUTPUT = WEBUI / "changelog" / "index.html"

PAGE_TITLE = "Changelog — ScriptSentry"
PAGE_DESCRIPTION = (
    "Every notable change to ScriptSentry, the privacy-first JavaScript "
    "security and script-behavior analyzer. Release history, accuracy "
    "improvements and dashboard updates."
)

# The engine status pill answers "is *my* browser paired with a local engine?".
# That is useful in the console and on the landing page, but on a static
# "what's new" page the question a visitor actually has is "how do I set it up" —
# so the pill is dropped and "Setup" joins the navigation instead. Keeping a
# single header button (Go to tool) also stops the actions crowding at 320px.
PILL_RE = re.compile(r'\s*<button class="engine-pill".*?</button>', re.S)
SETUP_NAV_LINK = '\n        <a href="home/#setup">Setup</a>'
CONNECT_NAV_LINK = '<a href="home/#connect">Connect</a>'


# --------------------------------------------------------------------------
# Markdown (the small, boring subset CHANGELOG.md actually uses)
# --------------------------------------------------------------------------

CODE_RE = re.compile(r"`([^`]+)`")
BOLD_RE = re.compile(r"\*\*(.+?)\*\*", re.S)
ITALIC_RE = re.compile(r"(?<![*\w])\*([^*\n]+)\*(?!\*)")
LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")


def inline(text: str) -> str:
    """Escape and apply the inline Markdown the changelog uses."""
    out = html.escape(text, quote=False)
    out = CODE_RE.sub(r"<code>\1</code>", out)
    out = BOLD_RE.sub(r"<strong>\1</strong>", out)
    out = ITALIC_RE.sub(r"<em>\1</em>", out)
    out = LINK_RE.sub(r'<a href="\2">\1</a>', out)
    return out


HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
BULLET_RE = re.compile(r"^[-*]\s+(.*)$")


def parse(markdown: str) -> list[tuple[str, object]]:
    """Group the source into block-level chunks."""
    lines = markdown.replace("\r\n", "\n").split("\n")
    blocks: list[tuple[str, object]] = []
    index = 0

    while index < len(lines):
        line = lines[index]

        if not line.strip():
            index += 1
            continue

        heading = HEADING_RE.match(line)
        if heading:
            blocks.append(("heading", (len(heading.group(1)), heading.group(2).strip())))
            index += 1
            continue

        if line.startswith(">"):
            quoted = []
            while index < len(lines) and lines[index].startswith(">"):
                quoted.append(re.sub(r"^>\s?", "", lines[index]))
                index += 1
            blocks.append(("quote", " ".join(part.strip() for part in quoted).strip()))
            continue

        if BULLET_RE.match(line):
            items: list[str] = []
            while index < len(lines):
                current = lines[index]
                bullet = BULLET_RE.match(current)
                if bullet:
                    items.append(bullet.group(1).strip())
                    index += 1
                elif current.strip() and current[:1].isspace():
                    # A wrapped continuation line of the bullet above.
                    items[-1] = f"{items[-1]} {current.strip()}"
                    index += 1
                else:
                    break
            blocks.append(("list", items))
            continue

        paragraph = []
        while index < len(lines) and lines[index].strip():
            if HEADING_RE.match(lines[index]) or BULLET_RE.match(lines[index]):
                break
            if lines[index].startswith(">"):
                break
            paragraph.append(lines[index].strip())
            index += 1
        blocks.append(("para", " ".join(paragraph)))

    return blocks


def slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "section"


def render_body(blocks: list[tuple[str, object]]) -> tuple[str, str]:
    """Render the parsed blocks as ``(intro_html, releases_html)``.

    Everything before the first release heading is the page introduction
    (title, what-this-is note, status); everything after it is rendered as one
    ``<section class="release">`` per version.
    """
    intro: list[str] = []
    out: list[str] = []
    used_slugs: set[str] = set()
    open_section = False
    started = False  # the leading "Changelog" heading becomes the page <h1>

    def unique_slug(text: str) -> str:
        base = slugify(text)
        slug, counter = base, 2
        while slug in used_slugs:
            slug = f"{base}-{counter}"
            counter += 1
        used_slugs.add(slug)
        return slug

    for kind, payload in blocks:
        if kind == "heading":
            level, text = payload  # type: ignore[misc]
            if not started:
                # First heading is "# Changelog": it becomes the page title.
                started = True
                intro.append("      <h1>" + inline(text) + "</h1>")
                continue

            slug = unique_slug(text)
            if level <= 2:
                if open_section:
                    out.append("      </section>")
                out.append(f'      <section class="release" id="{slug}">')
                out.append("        <h2>" + inline(text) + "</h2>")
                open_section = True
            else:
                if not open_section:
                    out.append('      <section class="release">')
                    open_section = True
                out.append(f'        <h3 id="{slug}">' + inline(text) + "</h3>")
            continue

        if not started:
            continue

        if kind == "para":
            out.append(f"        <p>{inline(str(payload))}</p>")
        elif kind == "quote":
            out.append(f"        <blockquote>{inline(str(payload))}</blockquote>")
        elif kind == "list":
            items = payload  # type: ignore[assignment]
            out.append("        <ul>")
            for item in items:  # type: ignore[union-attr]
                out.append(f"          <li>{inline(str(item))}</li>")
            out.append("        </ul>")

    if open_section:
        out.append("      </section>")

    return "\n".join(intro), "\n".join(out)


# --------------------------------------------------------------------------
# Page assembly
# --------------------------------------------------------------------------

def slice_block(html_text: str, start: str, end: str, label: str) -> str:
    try:
        begin = html_text.index(start)
        finish = html_text.index(end, begin) + len(end)
    except ValueError as exc:  # pragma: no cover - guards a rename in index.html
        raise SystemExit(f"Could not find the {label} block in index.html: {exc}")
    return html_text[begin:finish]


def relink(chrome: str) -> str:
    """Point landing-page anchors at the page they actually live on."""
    # In-page anchors ("#features") belong to the overview page, not here.
    # The overview lives at the clean URL /home/ on the hosted site.
    chrome = re.sub(r'href="#(?!top")([^"]+)"', r'href="home/#\1"', chrome)
    # The brand mark is "back to the top" on the landing page; here it is home.
    chrome = chrome.replace('href="#top"', 'href="home/"')
    return chrome


def adapt_header(header: str) -> str:
    header = relink(header)
    header, swaps = PILL_RE.subn("", header)
    if swaps != 1:
        raise SystemExit(f"Expected one engine pill in the header, removed {swaps}.")
    # The landing page's nav skips Setup (it is hero/footer territory there);
    # on a standalone page the nav is the whole site, so it belongs in the list.
    if CONNECT_NAV_LINK not in header:
        raise SystemExit("Could not find the Connect link in the header nav.")
    header = header.replace(
        CONNECT_NAV_LINK, SETUP_NAV_LINK + "\n        " + CONNECT_NAV_LINK
    )
    return header


def adapt_footer(footer: str) -> str:
    footer = relink(footer)
    # The changelog is a page on this site now, so the footer must not send
    # people to the repository for it.
    for match in re.finditer(r'<a [^>]*href="(?!changelog\.html")[^"]*"[^>]*>([^<]*)</a>', footer):
        if "changelog" in match.group(1).lower():
            raise SystemExit(
                "The footer still advertises the changelog as a GitHub file: "
                + match.group(1)
            )
    footer = footer.replace(
        '<a href="changelog/">', '<a href="changelog/" aria-current="page">'
    )
    return footer


def adapt_head(head: str) -> str:
    head = re.sub(
        r"<title>.*?</title>", f"<title>{PAGE_TITLE}</title>", head, flags=re.S
    )
    head = re.sub(
        r'(<meta name="description" content=")[^"]*(")',
        lambda m: m.group(1) + PAGE_DESCRIPTION + m.group(2),
        head,
    )
    head = re.sub(
        r'(<meta property="og:title" content=")[^"]*(")',
        lambda m: m.group(1) + "ScriptSentry — Changelog" + m.group(2),
        head,
    )
    head = re.sub(
        r'(<meta property="og:description" content=")[^"]*(")',
        lambda m: m.group(1) + PAGE_DESCRIPTION + m.group(2),
        head,
    )
    head = re.sub(
        r'(<meta name="twitter:title" content=")[^"]*(")',
        lambda m: m.group(1) + "ScriptSentry — Changelog" + m.group(2),
        head,
    )
    head = re.sub(
        r'(<meta name="twitter:description" content=")[^"]*(")',
        lambda m: m.group(1) + PAGE_DESCRIPTION + m.group(2),
        head,
    )
    if 'rel="canonical"' not in head:
        head = head.replace(
            '  <link rel="stylesheet" href="../styles.css" />',
            '  <link rel="canonical" href="changelog/" />\n'
            '  <link rel="stylesheet" href="../styles.css" />',
        )
    return head


def build() -> str:
    if not SOURCE.is_file():
        raise SystemExit(f"Missing {SOURCE}")
    if not INDEX.is_file():
        raise SystemExit(f"Missing {INDEX}")

    markdown = SOURCE.read_text(encoding="utf-8")
    intro, releases = render_body(parse(markdown))

    page = INDEX.read_text(encoding="utf-8")
    head = adapt_head(slice_block(page, "<head>", "</head>", "head"))
    header = adapt_header(
        slice_block(page, "<!-- ============================ Header", "</header>", "header")
    )
    footer = adapt_footer(
        slice_block(page, "<!-- ============================ Footer", "</footer>", "footer")
    )

    return f"""<!DOCTYPE html>
<!--
  GENERATED FILE -- DO NOT EDIT BY HAND.
  This page is generated from CHANGELOG.md by tools/build_changelog.py.
  Edit the Markdown, then run: python3 tools/build_changelog.py
-->
<html lang="en">
{head}
<body>
  <canvas id="particles" aria-hidden="true"></canvas>
  <div class="bg-glow bg-glow-1"></div>
  <div class="bg-glow bg-glow-2"></div>
  <div class="bg-glow bg-glow-3"></div>
  <a class="skip-link" href="#main">Skip to Content</a>

{header}

  <main class="wrap" id="main">
    <header class="changelog-intro">
      <span class="section-kicker">What's new</span>
{intro}
    </header>

    <div class="changelog">
{releases}
    </div>

    <p class="changelog-back">
      <a href="home/">← Back to the overview</a> ·
      <a href="tool/">Open the analyzer →</a>
    </p>
  </main>

{footer}

  <script src="../app.js"></script>
</body>
</html>
"""


def main(argv: list[str]) -> int:
    check = "--check" in argv
    rendered = build()

    if check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.is_file() else ""
        if current != rendered:
            print(
                f"{OUTPUT.relative_to(ROOT)} is out of date. "
                "Run: python3 tools/build_changelog.py",
                file=sys.stderr,
            )
            return 1
        print(f"{OUTPUT.relative_to(ROOT)} is up to date.")
        return 0

    OUTPUT.write_text(rendered, encoding="utf-8")
    print(f"Wrote {OUTPUT.relative_to(ROOT)} ({len(rendered):,} bytes) from {SOURCE.name}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
