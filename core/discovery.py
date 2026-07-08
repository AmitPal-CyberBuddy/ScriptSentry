import re
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36"
    )
}


def fetch_url(url):
    try:
        response = requests.get(url, timeout=15, headers=HEADERS, allow_redirects=True)
        if response.status_code == 200:
            return response.text
    except Exception:
        return ""
    return ""


def extract_js(url):
    html = fetch_url(url)
    if not html:
        return []

    soup = BeautifulSoup(html, "html.parser")
    js_files = set()

    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            js_files.add(urljoin(url, src))

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