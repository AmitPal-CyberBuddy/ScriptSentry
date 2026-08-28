import re
from urllib.parse import urljoin

try:
    import requests
except ImportError:
    requests = None
try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36"
    )
}


def fetch_url(url):
    if requests is None:
        return ""
    try:
        response = requests.get(url, timeout=15, headers=HEADERS, allow_redirects=True)
        if response.status_code == 200:
            return response.text
    except Exception:
        return ""
    return ""


def extract_inline_scripts(url, limit=80):
    """Return inline <script> bodies from a page for direct analysis."""
    html = fetch_url(url)
    if not html or BeautifulSoup is None:
        return []
    soup = BeautifulSoup(html, "html.parser")
    scripts = []
    for script in soup.find_all("script"):
        src = script.get("src")
        if src or not script.string:
            continue
        body = script.string.strip()
        if len(body) >= 20:
            scripts.append(body)
        if len(scripts) >= limit:
            break
    return scripts


def extract_js(url):
    html = fetch_url(url)
    if not html:
        return []

    soup = BeautifulSoup(html, "html.parser") if BeautifulSoup is not None else None
    js_files = set()

    if soup is not None:
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                js_files.add(urljoin(url, src))

        # Modern module/asset delivery: Vite/Next/webpack emit modulepreload,
        # preload(as=script) and module links that a plain <script src> scan
        # would otherwise miss.
        for link in soup.find_all("link"):
            href = link.get("href")
            rel = (link.get("rel") or [])
            as_value = link.get("as") or ""
            if not href:
                continue
            if "modulepreload" in rel or "preload" in rel and as_value == "script" or "prefetch" in rel:
                if href.endswith((".js", ".mjs")) or "modulepreload" in rel or as_value == "script":
                    js_files.add(urljoin(url, href))

        for script in soup.find_all("script"):
            if not script.get("src") and script.get("type") == "module" and script.string:
                for pattern in [
                    r'["\']([^"\']+\.js[^"\']*)["\']',
                    r'["\']([^"\']*chunk-[A-Za-z0-9]+\.js[^"\']*)["\']',
                ]:
                    for match in re.findall(pattern, script.string):
                        js_files.add(urljoin(url, match))

        for script in soup.find_all("script"):
            if script.string:
                content = script.string
                for pattern in [
                    r'["\'](https?://[^"\']+\.js[^"\']*)["\']',
                    r'["\'](chunk-[A-Za-z0-9]+\.js)["\']',
                    r'["\']([A-Za-z0-9_\-]+\.js(?:\?[^"\']*)?)["\']'
                ]:
                    for match in re.findall(pattern, content):
                        js_files.add(urljoin(url, match))

    dynamic_patterns = [
        r'chunk-[A-Za-z0-9]+\.js',
        r'/static/js/[A-Za-z0-9\.\-]+\.js',
        r'assets/[A-Za-z0-9\.\-]+\.js'
    ]
    for pattern in dynamic_patterns:
        for match in re.findall(pattern, html):
            js_files.add(urljoin(url, match))

    for link in re.findall(r'https?://[^\s"\']+\.js(?:\?[^\s"\']*)?', html):
        js_files.add(link)

    return sorted(js_files)