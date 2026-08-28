"""High-level analysis orchestration used by the CLI and the Web dashboard."""
import hashlib
import os
import re
from urllib.parse import urljoin, urlparse, unquote

try:
    import requests
except ImportError:  # allow pure-paste code analysis without network deps
    requests = None

from config import BEAUTIFY_DIR, FILE_RULES, JS_DIR
from core.beautifier import beautify
from core.crypto import extract_crypto_material
from core.discovery import extract_js
from core.downloader import download_js
from core.scanner import scan_file


REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36"
    )
}


def _merge_into(results, path, content, seen_hashes=None):
    """Run the full scanner plus crypto extractor for a single JS document.

    ``seen_hashes`` lets a URL scan skip duplicate content (mirrored bundles,
    cache-busted repeats) so the analyzer produces one set of evidence per
    unique payload instead of N copies of the same finding.
    """
    content = content or ""
    if len(content.encode("utf-8", errors="ignore")) > FILE_RULES.get("max_js_size", 2_000_000):
        return
    if seen_hashes is not None:
        digest = hashlib.md5(content.encode("utf-8", errors="ignore")).hexdigest()
        if digest in seen_hashes:
            return
        seen_hashes.add(digest)
    data = scan_file(path, content=content)
    crypto = extract_crypto_material(content, filename=os.path.basename(path))
    data.update(crypto)
    results[path] = data


def analyze_content(code, filename="inline.js"):
    """Analyze pasted JavaScript and return raw per-file results."""
    results = {}
    _merge_into(results, filename, code)
    return results


def _is_chunk(path):
    return bool(path and "chunk-" in path and path.endswith(".js"))


def _safe_name(url):
    parsed = urlparse(url)
    name = os.path.basename(unquote(parsed.path))
    if not name or "." not in name:
        name = "unknown.js"
    elif not name.endswith(".js"):
        name = f"{name}.js"
    return name


def _download_chunk(url):
    if requests is None:
        return None
    try:
        response = requests.get(url, timeout=15, headers=REQUEST_HEADERS)
        if response.status_code != 200:
            return None
        content = response.text.strip()
        if len(content) < FILE_RULES.get("min_js_size", 50):
            return None
        os.makedirs(BEAUTIFY_DIR, exist_ok=True)
        path = os.path.join(BEAUTIFY_DIR, _safe_name(url))
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path
    except Exception:
        return None


def _resolve_chunk(chunk_name, base_url):
    """Resolve an imported chunk against downloaded beautified files, then network."""
    chunk_name = chunk_name.split("?")[0]
    base = os.path.basename(chunk_name)
    if os.path.isdir(BEAUTIFY_DIR):
        for root, _, files in os.walk(BEAUTIFY_DIR):
            for filename in files:
                if filename == base or base in filename:
                    return os.path.join(root, filename)
    if base_url:
        return _download_chunk(urljoin(base_url, chunk_name))
    return None


def _walk_imports(content, path, results, base_url, depth, max_depth, seen_hashes=None):
    imports = set()
    for chunk in re.findall(r'["\']([^"\']*chunk-[A-Za-z0-9]+\.js[^"\']*)["\']', content):
        imports.add(chunk.split("?")[0])

    if depth >= max_depth:
        return

    for chunk in imports:
        next_path = _resolve_chunk(chunk, base_url)
        if not next_path or next_path in results:
            continue
        try:
            with open(next_path, encoding="utf-8") as f:
                next_content = f.read()
        except Exception:
            continue
        _merge_into(results, next_path, next_content, seen_hashes=seen_hashes)
        _walk_imports(next_content, next_path, results, base_url, depth + 1, max_depth, seen_hashes=seen_hashes)


def analyze_url(url, max_depth=5, timeout=15, max_files=50):
    """Discover, download, beautify and recursively analyze a web app's JS."""
    results = {}
    os.makedirs(JS_DIR, exist_ok=True)
    os.makedirs(BEAUTIFY_DIR, exist_ok=True)

    js_links = extract_js(url)
    if not js_links:
        return results

    js_links = js_links[:max_files]
    downloads = download_js(js_links)
    beautified = beautify(downloads)
    seen_hashes = set()

    for path in beautified[:max_files]:
        if path in results:
            continue
        with open(path, encoding="utf-8", errors="replace") as f:
            content = f.read()
        _merge_into(results, path, content, seen_hashes=seen_hashes)
        _walk_imports(content, path, results, url, 1, max_depth, seen_hashes=seen_hashes)

    return results
