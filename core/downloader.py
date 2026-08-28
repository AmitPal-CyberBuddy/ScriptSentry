import hashlib
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, unquote

try:
    import requests
except ImportError:
    requests = None

from config import FILE_RULES, JS_DIR

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    )
}


def get_safe_filename(url):
    """Return a collision-free, URL-unique filename for a script asset.

    Multiple bundles from different paths often share a basename
    (``app.js``, ``chunk-123.js``). Using an MD5 prefix keeps every URL's
    artifact separate so recursive chunk analysis does not silently reuse the
    wrong file.
    """
    parsed = urlparse(url)
    name = os.path.basename(unquote(parsed.path))

    if not name or "." not in name:
        name = "unknown.js"
    elif not name.endswith((".js", ".mjs")):
        name = f"{name}.js"

    stem, ext = os.path.splitext(name)
    digest = hashlib.md5(url.encode("utf-8", errors="ignore")).hexdigest()[:10]
    return f"{stem[:80]}-{digest}{ext}"


def download_file(url):
    filename = get_safe_filename(url)
    path = os.path.join(JS_DIR, filename)

    if os.path.exists(path) and os.path.getsize(path) >= max(1, int(FILE_RULES.get("min_js_size", 1))):
        return path

    if requests is None:
        return None

    for _ in range(2):
        try:
            response = requests.get(url, timeout=15, headers=HEADERS)
            if response.status_code != 200:
                continue

            content = response.text.strip()
            min_size = int(FILE_RULES.get("min_js_size", 1))
            if not content or len(content) < max(1, min_size):
                continue
            # A JS asset should never be an HTML page; reject those responses so a
            # soft-404 does not become a "JavaScript" file in the report.
            if "<html" in content.lower() or "<!doctype" in content.lower():
                continue

            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            return path
        except Exception:
            continue

    return None


def download_js(js_links, progress_callback=None):
    os.makedirs(JS_DIR, exist_ok=True)
    js_links = list(js_links or [])
    results = []
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {executor.submit(download_file, url): url for url in js_links}
        done = 0
        for future in as_completed(futures):
            try:
                path = future.result()
            except Exception:
                path = None
            if path:
                results.append(path)
            done += 1
            if progress_callback:
                progress_callback(
                    phase="download",
                    current=done,
                    total=max(1, len(js_links)),
                    message=f"Downloading scripts {done}/{max(1, len(js_links))}",
                )
    return [r for r in results if r]
