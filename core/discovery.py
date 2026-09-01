"""Page-level JavaScript discovery.

Discovery is intentionally limited to script-bearing resources.  Network/API
URLs are inventory data, not crawl targets; keeping that distinction prevents a
page's ``fetch('/api/...')`` strings from turning the analyzer into a generic
web crawler.
"""
import re
from urllib.parse import urljoin

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

from config import FILE_RULES, REQUEST_HEADERS
from core.url_policy import MAX_PAGE_BYTES, safe_get, read_response_text



def fetch_url(url, timeout=15, cancel_check=None):
    """Fetch one public page, bounded to avoid retaining an unbounded body."""
    try:
        response = safe_get(url, timeout=timeout, headers=REQUEST_HEADERS, cancel_check=cancel_check)
        if response is not None and response.status_code == 200:
            return read_response_text(response, max_bytes=MAX_PAGE_BYTES) or ""
    except Exception:
        return ""
    return ""


def _extract_assets(html, url):
    soup = BeautifulSoup(html, "html.parser") if BeautifulSoup is not None else None
    js_files = set()
    inline_scripts = []

    if soup is not None:
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                js_files.add(urljoin(url, src))
            elif script.string and script.string.strip():
                body = script.string.strip()
                # Keep module/bootstrap inline code even when it is short.  The
                # previous arbitrary 20-character threshold lost tiny loaders.
                if len(body.encode("utf-8", errors="ignore")) >= int(FILE_RULES.get("min_js_size", 1)):
                    inline_scripts.append(body)

        # Modern module delivery: modulepreload, JS preloads and prefetches.
        for link in soup.find_all("link"):
            href = link.get("href")
            rel = {str(x).lower() for x in (link.get("rel") or [])}
            as_value = str(link.get("as") or "").lower()
            if not href:
                continue
            if "modulepreload" in rel or ("preload" in rel and as_value == "script") or "prefetch" in rel:
                if href.split("?", 1)[0].lower().endswith((".js", ".mjs")) or "modulepreload" in rel or as_value == "script":
                    js_files.add(urljoin(url, href))

        # Inline module imports are entry points too.
        for body in inline_scripts:
            for pattern in (
                r"(?:import|from)\s*[('\\\"]([^'\\\"]+)",
                r"(?:chunk-[A-Za-z0-9_.-]+|/static/js/[A-Za-z0-9_.-]+|assets/[A-Za-z0-9_.-]+)\.js",
            ):
                for match in re.findall(pattern, body):
                    ref = match if isinstance(match, str) else match[0]
                    if ref:
                        js_files.add(urljoin(url, ref))

    # Common bundler hints in HTML/bootstrap JSON.
    for pattern in (
        r"chunk-[A-Za-z0-9_.-]+\.js",
        r"/static/js/[A-Za-z0-9_.-]+\.js",
        r"assets/[A-Za-z0-9_.-]+\.js",
    ):
        for match in re.findall(pattern, html):
            js_files.add(urljoin(url, match))
    for link in re.findall(r"https?://[^\s\"']+\.m?js(?:\?[^\s\"']*)?", html):
        js_files.add(link)

    return sorted(js_files), inline_scripts


def extract_page_assets(url, timeout=15, cancel_check=None):
    """Return ``(external_scripts, inline_scripts, page metadata)`` in one fetch."""
    html = fetch_url(url, timeout=timeout, cancel_check=cancel_check)
    if not html:
        return [], [], {"page_fetch": "failed", "page_bytes": 0}
    scripts, inline = _extract_assets(html, url)
    return scripts, inline, {
        "page_fetch": "ok",
        "page_bytes": len(html.encode("utf-8", errors="ignore")),
        "inline_count": len(inline),
    }


def extract_inline_scripts(url, limit=80):
    """Backward-compatible inline script extraction."""
    _, inline, _ = extract_page_assets(url)
    return inline[:limit]


def extract_js(url):
    """Backward-compatible external script extraction."""
    scripts, _, _ = extract_page_assets(url)
    return scripts
