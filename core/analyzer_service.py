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
from core.discovery import extract_inline_scripts, extract_js
from core.downloader import download_js, get_safe_filename
from core.runtime_evidence import attach_runtime_evidence, capture_runtime_evidence, runtime_evidence_enabled
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

    Returns ``True`` when the document was added and ``False`` when it was
    skipped (oversized or already analyzed), so callers can report skip counts
    instead of silently ignoring assets.
    """
    content = content or ""
    if len(content.encode("utf-8", errors="ignore")) > FILE_RULES.get("max_js_size", 2_000_000):
        return False
    if seen_hashes is not None:
        digest = hashlib.md5(content.encode("utf-8", errors="ignore")).hexdigest()
        if digest in seen_hashes:
            return False
        seen_hashes.add(digest)
    data = scan_file(path, content=content)
    crypto = extract_crypto_material(content, filename=os.path.basename(path))
    data.update(crypto)
    data["content_sha256"] = hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()
    results[path] = data
    return True


def analyze_content(code, filename="inline.js"):
    """Analyze pasted JavaScript and return raw per-file results."""
    results = {}
    _merge_into(results, filename, code)
    return results


def _is_chunk(path):
    return bool(path and ("chunk-" in path or ".chunk." in path) and path.endswith((".js", ".mjs")))


def _download_chunk(url):
    if requests is None:
        return None
    try:
        response = requests.get(url, timeout=20, headers=REQUEST_HEADERS)
        if response.status_code != 200:
            return None
        content = response.text.strip()
        if len(content) < max(1, int(FILE_RULES.get("min_js_size", 1))):
            return None
        if len(content) > FILE_RULES.get("max_js_size", 2_000_000):
            return None
        if "<html" in content.lower() or "<!doctype" in content.lower():
            return None
        os.makedirs(BEAUTIFY_DIR, exist_ok=True)
        path = os.path.join(BEAUTIFY_DIR, get_safe_filename(url))
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path
    except Exception:
        return None


def _is_followable_ref(ref):
    """Return True for script-like asset URLs only.

    API endpoints and arbitrary relative paths from ``fetch``/``axios`` must
    never be treated as module chunks --- otherwise crawl depth is wasted and
    the scanner may download JSON responses as JavaScript.
    """
    ref = str(ref or "").strip().split("?")[0].split("#")[0]
    if not ref:
        return False
    if re.search(r"\.(?:js|mjs)$", ref):
        return True
    if "chunk-" in ref or "/static/js/" in ref or "assets/" in ref:
        return True
    return False


def extract_script_refs(content):
    """Extract every script/module reference visible in a JS bundle.

    Covers the common real-world patterns: static imports, dynamic
    ``import(...)``, CommonJS ``require``, routed chunk files, ``/static/js``
    and ``assets`` bundles, and absolute script URLs. Bare module references
    from import/require are followed; arbitrary API paths are not.
    """
    refs = set()
    module_patterns = [
        r"""import\s*\(\s*['"]([^'"]+)['"]""",
        r"""require\s*\(\s*['"]([^'"]+)['"]""",
        r"""import\s+['"]([^'"]+)['"]""",
        r"""import\s+[^'"]+?\s+from\s+['"]([^'"]+)['"]""",
    ]
    asset_patterns = [
        r"""['"]([^'"]*chunk-[A-Za-z0-9]+\.js[^'"]*)['"]""",
        r"""['"]([^'"]*(?:/static/js/|assets/)[^'"]*\.js[^'"]*)['"]""",
        r"""(?:https?:)?//[^\s'"<>()\\]+\.js(?:[?#][^\s'"<>()\\]*)?""",
        r"""['"](/?[A-Za-z0-9_./-]+\.mjs[^'"]*)['"]""",
    ]
    for pattern in module_patterns:
        for match in re.findall(pattern, content):
            ref = str(match).strip().strip("'\"")
            if not ref:
                continue
            ref = ref.split("?")[0].split("#")[0]
            if ref.startswith((".", "/", "http://", "https://")):
                base = os.path.basename(ref)
                # Follow real JS/module bundles, including extensionless
                # relative imports, but never treat JSON/CSS/font imports as
                # JavaScript assets.
                if _is_followable_ref(ref) or ("." not in base and ref.startswith(("./", "../"))):
                    refs.add(ref)
    for pattern in asset_patterns:
        for match in re.findall(pattern, content):
            ref = str(match).strip().strip("'\"")
            if not ref:
                continue
            ref = ref.split("?")[0].split("#")[0]
            if _is_followable_ref(ref):
                refs.add(ref)
    return sorted(refs)


def _resolve_chunk(chunk_name, base_url):
    """Resolve an imported chunk against downloaded beautified files, then network."""
    chunk_name = chunk_name.split("?")[0]
    base = os.path.basename(chunk_name)
    stem = os.path.splitext(base)[0]
    if os.path.isdir(BEAUTIFY_DIR):
        for root, _, files in os.walk(BEAUTIFY_DIR):
            for filename in files:
                if filename == base:
                    return os.path.join(root, filename)
                if filename.startswith(f"{stem}-") and filename.endswith((".js", ".mjs")):
                    return os.path.join(root, filename)
    if base_url:
        absolute = urljoin(base_url, chunk_name)
        # Only add the .js fallback for extensionless module refs; a real
        # bundle URL with an extension should not cause a second 404 request.
        candidates = (absolute,) if absolute.endswith((".js", ".mjs")) else (absolute, absolute + ".js")
        for candidate in candidates:
            path = _download_chunk(candidate)
            if path:
                return path
    return None


def _walk_imports(
    content,
    path,
    results,
    base_url,
    depth,
    max_depth,
    seen_hashes=None,
    max_files=None,
    visited=None,
    progress_callback=None,
    state=None,
):
    if depth >= max_depth:
        return

    max_files = int(max_files or 1000)
    visited = set(visited or [])
    state = state if state is not None else {}
    skipped = state.setdefault("skipped_files", 0)
    for ref in extract_script_refs(content):
        if len(results) >= max_files:
            state["skipped_files"] = skipped = skipped + 1
            state.setdefault("skipped_reasons", []).append("scanned_files_limit")
            return
        absolute_url = urljoin(base_url, ref) if not ref.startswith(("http://", "https://")) else ref
        key = absolute_url.split("?")[0].split("#")[0]
        if key in visited:
            continue
        visited.add(key)

        next_path = _resolve_chunk(ref, base_url)
        if not next_path or next_path in results:
            continue
        try:
            with open(next_path, encoding="utf-8") as f:
                next_content = f.read()
        except Exception:
            continue
        if len(next_content.encode("utf-8", errors="ignore")) > FILE_RULES.get("max_js_size", 2_000_000):
            state["skipped_files"] = skipped = skipped + 1
            state.setdefault("skipped_reasons", []).append("oversized_script")
            continue
        if not _merge_into(results, next_path, next_content, seen_hashes=seen_hashes):
            state["skipped_files"] = skipped = skipped + 1
            state.setdefault("skipped_reasons", []).append("duplicate_content")
            continue
        state.setdefault("path_to_url", {})[next_path] = absolute_url
        if progress_callback:
            progress_callback(
                phase="recursive_scan",
                current=len(results),
                total=max_files,
                message=f"Following nested scripts: {len(results)}/{max_files}",
            )
        _walk_imports(
            next_content,
            next_path,
            results,
            absolute_url,
            depth + 1,
            max_depth,
            seen_hashes=seen_hashes,
            max_files=max_files,
            visited=visited,
            progress_callback=progress_callback,
            state=state,
        )


def _notify(callback, **kwargs):
    if callback:
        try:
            callback(**kwargs)
        except Exception:
            pass


def _attach_runtime(results, url, timeout=15, max_files=50, progress_callback=None):
    """Load the page in a local headless browser and merge its evidence."""
    if not runtime_evidence_enabled():
        _notify(progress_callback, phase="runtime", current=0, total=1, message="Runtime evidence disabled")
        runtime = {
            "enabled": False,
            "available": False,
            "captured": False,
            "status": "disabled",
            "reason": "Runtime evidence is disabled by configuration.",
            "url": url,
        }
        return attach_runtime_evidence(results, runtime, target_url=url)

    _notify(progress_callback, phase="runtime", current=0, total=1, message="Executing page in local headless browser")
    runtime = capture_runtime_evidence(
        url,
        timeout_ms=max(2_000, int(float(timeout or 15) * 1000)),
        max_requests=max(60, min(max(50, int(max_files or 50) * 6), 600)),
    )
    _notify(progress_callback, phase="runtime", current=1, total=1, message="Runtime evidence captured")
    return attach_runtime_evidence(results, runtime, target_url=url)


def analyze_url(url, max_depth=5, timeout=15, max_files=100, progress_callback=None):
    """Discover, download, beautify and recursively analyze a web app's JS.

    The scan is breadth-first across module/chunk references rather than only
    the entry scripts. Progress is reported through ``progress_callback`` so the
    dashboard can show phase, file count, byte count and an ETA while a large
    URL is being crawled.

    Every discoverable script is followed: static ``import``/``require``,
    dynamic ``import()``, ``chunk-*`` bundles, ``/static/js`` and ``assets``
    assets, modulepreload links and inline module scripts. When the configured
    file cap or a per-file limit is hit, the asset is reported through
    ``__scan_summary__`` instead of being silently dropped.
    """
    max_files = int(max_files or 1000)
    if max_files <= 0:
        max_files = 1000
    results = {}
    os.makedirs(JS_DIR, exist_ok=True)
    os.makedirs(BEAUTIFY_DIR, exist_ok=True)

    state = {"skipped_files": 0, "skipped_reasons": [], "path_to_url": {}}

    _notify(progress_callback, phase="recon", current=0, total=1, message="Reading page and extracting script references")
    js_links = extract_js(url)
    inline_scripts = extract_inline_scripts(url)
    discovered = list(dict.fromkeys(js_links))
    if not discovered and not inline_scripts:
        return _finish_scan(
            results,
            url,
            state=state,
            max_files=max_files,
            max_depth=max_depth,
            timeout=timeout,
            progress_callback=progress_callback,
            total_discovered=0,
            total_bytes=0,
        )

    # URL-unique naming guarantees the same basename from different folders does
    # not collide; keep the URL list itself too so the JS inventory can attribute
    # every downloaded asset back to its full source.
    for link in discovered[:max_files]:
        state.setdefault("script_urls", [])
        state["script_urls"].append(link)
    if len(discovered) > max_files:
        state["skipped_files"] += len(discovered) - max_files
        state.setdefault("skipped_reasons", []).append("discovered_scripts_limit")

    _notify(
        progress_callback,
        phase="download",
        current=0,
        total=len(discovered) or 1,
        message=f"Discovered {len(discovered)} external scripts and {len(inline_scripts)} inline script(s)",
    )
    downloads = download_js(discovered[:max_files], progress_callback=progress_callback)
    beautified = []
    if downloads:
        _notify(progress_callback, phase="beautify", current=0, total=len(downloads), message="Normalizing downloaded bundles")
        beautified = beautify(downloads)

    seen_hashes = set()
    visited = set()
    total_bytes = sum((os.path.getsize(path) if os.path.isfile(path) else 0) for path in beautified)

    # Top-level downloads keep the URL-unique safe name, so we can restore the
    # per-file base URL before walking that bundle's nested imports.
    safe_name_to_url = {}
    for link in discovered[:max_files]:
        safe_name_to_url[get_safe_filename(link)] = link

    def scan_progress(phase, message):
        scanned = sum(data.get("file_size", 0) for data in results.values())
        _notify(
            progress_callback,
            phase=phase,
            current=len(results),
            total=max_files,
            scanned_bytes=scanned,
            total_bytes=max(1, total_bytes),
            message=message,
        )

    # Inline page scripts are part of the surface too; they are not ignored.
    for index, body in enumerate(inline_scripts):
        if len(results) >= max_files:
            state["skipped_files"] += 1
            state.setdefault("skipped_reasons", []).append("scanned_files_limit")
            break
        path = f"inline-{index + 1}.js"
        if not _merge_into(results, path, body, seen_hashes=seen_hashes):
            state["skipped_files"] += 1
            state.setdefault("skipped_reasons", []).append("duplicate_content")
            continue
        scan_progress("inline_scan", f"Analyzing inline script {index + 1}/{len(inline_scripts)}")

    for path in beautified:
        if len(results) >= max_files:
            state["skipped_files"] += 1
            state.setdefault("skipped_reasons", []).append("scanned_files_limit")
            break
        if path in results:
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            state["skipped_files"] += 1
            state.setdefault("skipped_reasons", []).append("read_error")
            continue
        if len(content.encode("utf-8", errors="ignore")) > FILE_RULES.get("max_js_size", 2_000_000):
            state["skipped_files"] += 1
            state.setdefault("skipped_reasons", []).append("oversized_script")
            scan_progress("scan", f"Skipping oversized script {os.path.basename(path)}")
            continue
        if not _merge_into(results, path, content, seen_hashes=seen_hashes):
            state["skipped_files"] += 1
            state.setdefault("skipped_reasons", []).append("duplicate_content")
            scan_progress("scan", f"Skipping duplicate script {os.path.basename(path)}")
            continue
        current_url = safe_name_to_url.get(os.path.basename(path)) or state.get("path_to_url", {}).get(path) or url
        state.setdefault("path_to_url", {})[path] = current_url
        scan_progress("scan", f"Analyzing {os.path.basename(path)} ({len(results)}/{max_files})")
        _walk_imports(
            content,
            path,
            results,
            current_url,
            1,
            max_depth,
            seen_hashes=seen_hashes,
            max_files=max_files,
            visited=visited,
            progress_callback=progress_callback,
            state=state,
        )

    results["__scan_summary__"] = {
        "total_discovered": len(discovered) + len(inline_scripts),
        "total_files": len(results),
        "skipped_files": state.get("skipped_files", 0),
        "skipped_reasons": sorted(set(state.get("skipped_reasons", []))),
        "bytes_scanned": sum(data.get("file_size", 0) for data in results.values()),
        "total_bytes": max(1, total_bytes),
        "max_files": max_files,
        "capped": state.get("skipped_files", 0) > 0,
        "script_urls": sorted(set(state.get("script_urls", []))),
    }
    return _finish_scan(
        results,
        url,
        state=state,
        max_files=max_files,
        max_depth=max_depth,
        timeout=timeout,
        progress_callback=progress_callback,
        total_discovered=len(discovered) + len(inline_scripts),
        total_bytes=total_bytes,
    )


def _finish_scan(
    results,
    url,
    state=None,
    max_files=100,
    max_depth=5,
    timeout=15,
    progress_callback=None,
    total_discovered=0,
    total_bytes=0,
):
    """Attach the scan summary and runtime pass to a finished URL scan."""
    state = state or {}
    summary = results.get("__scan_summary__") or {
        "total_discovered": int(total_discovered or 0),
        "total_files": len(results),
        "skipped_files": int(state.get("skipped_files", 0)),
        "skipped_reasons": sorted(set(state.get("skipped_reasons", []))),
        "bytes_scanned": sum(data.get("file_size", 0) for data in results.values()),
        "total_bytes": max(1, int(total_bytes or 0)),
        "max_files": int(max_files or 100),
        "capped": int(state.get("skipped_files", 0)) > 0,
        "script_urls": sorted(set(state.get("script_urls", []))),
    }
    results["__scan_summary__"] = summary

    _notify(
        progress_callback,
        phase="done",
        current=len(results),
        total=len(results) or 1,
        percent=100,
        scanned_bytes=summary.get("bytes_scanned", 0),
        total_bytes=max(1, summary.get("total_bytes", 0)),
        message=f"Static analysis complete: {len(results)} unique script(s)",
    )
    runtime_results = _attach_runtime(results, url, timeout=timeout, max_files=max_files, progress_callback=progress_callback)
    runtime = runtime_results.get("__runtime_evidence__") or {}
    runtime_summary = runtime_results.get("__scan_summary__") or summary
    runtime_summary["runtime_status"] = runtime.get("status", "not_run")
    runtime_summary["runtime_captured"] = bool(runtime.get("captured"))
    runtime_results["__scan_summary__"] = runtime_summary
    return runtime_results
