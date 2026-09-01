"""Bounded, URL-safe JavaScript downloads used by the crawler."""
import hashlib
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, unquote

from config import FILE_RULES, JS_DIR, REQUEST_HEADERS
from core.url_policy import read_response_text, safe_get


def get_safe_filename(url):
    """Return a collision-free, URL-unique filename for a script asset."""
    parsed = urlparse(url)
    name = os.path.basename(unquote(parsed.path))
    if not name or "." not in name:
        name = "unknown.js"
    elif not name.endswith((".js", ".mjs")):
        name = f"{name}.js"
    stem, ext = os.path.splitext(name)
    digest = hashlib.sha256(url.encode("utf-8", errors="ignore")).hexdigest()[:12]
    return f"{stem[:80]}-{digest}{ext}"


def _response_text(response, max_bytes):
    return read_response_text(response, max_bytes=max_bytes)


def download_file(url, output_dir=None, timeout=15, cancel_check=None):
    """Download one JS module with a hard response-size limit.

    ``output_dir`` is scan-scoped when supplied.  The default remains for CLI
    compatibility, but the URL analyzer uses a temporary workspace so scans do
    not reuse another target's files or grow ``output/`` forever.
    """
    output_dir = output_dir or JS_DIR
    filename = get_safe_filename(url)
    path = os.path.join(output_dir, filename)
    min_size = max(1, int(FILE_RULES.get("min_js_size", 1)))
    max_size = int(FILE_RULES.get("max_js_size", 2_000_000))

    if os.path.exists(path) and os.path.getsize(path) >= min_size:
        return path
    if cancel_check and cancel_check():
        return None

    for _ in range(2):
        if cancel_check and cancel_check():
            return None
        try:
            response = safe_get(url, timeout=timeout, headers=REQUEST_HEADERS, cancel_check=cancel_check)
            if response is None or response.status_code != 200:
                continue
            content = _response_text(response, max_size)
            if not content:
                continue
            content = content.strip()
            if len(content.encode("utf-8", errors="ignore")) < min_size:
                continue
            # A JS asset should never be an HTML page; reject soft-404s.
            if "<html" in content.lower() or "<!doctype" in content.lower():
                continue
            os.makedirs(output_dir, exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(content)
            return path
        except Exception:
            continue
    return None


def download_js(js_links, progress_callback=None, output_dir=None, timeout=15, cancel_check=None):
    """Download links in a bounded pool and report every attempted link."""
    output_dir = output_dir or JS_DIR
    os.makedirs(output_dir, exist_ok=True)
    js_links = list(dict.fromkeys(js_links or []))
    results = []
    with ThreadPoolExecutor(max_workers=min(6, max(1, len(js_links)))) as executor:
        futures = {
            executor.submit(download_file, url, output_dir, timeout, cancel_check): url
            for url in js_links
        }
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
    return [path for path in results if path]
