import os
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, unquote

try:
    import requests
except ImportError:
    requests = None

from config import JS_DIR

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    )
}


def get_safe_filename(url):
    parsed = urlparse(url)
    name = os.path.basename(unquote(parsed.path))

    if not name or "." not in name:
        name = "unknown.js"
    elif not name.endswith(".js"):
        name = f"{name}.js"

    return name


def download_file(url):
    filename = get_safe_filename(url)
    path = os.path.join(JS_DIR, filename)

    if os.path.exists(path) and os.path.getsize(path) > 50:
        return path

    if requests is None:
        return None

    for _ in range(2):
        try:
            response = requests.get(url, timeout=15, headers=HEADERS)
            if response.status_code != 200:
                continue

            content = response.text.strip()
            if not content or len(content) < 50:
                continue
            if "<html" in content.lower():
                continue

            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            return path
        except Exception:
            continue

    return None


def download_js(js_links):
    os.makedirs(JS_DIR, exist_ok=True)
    with ThreadPoolExecutor(max_workers=6) as executor:
        results = list(executor.map(download_file, js_links))
    return [r for r in results if r]