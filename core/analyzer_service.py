"""High-level analysis orchestration used by the CLI and the Web dashboard."""
import hashlib
import os
import re
import shutil
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, unquote

try:
    import requests
except ImportError:  # allow pure-paste code analysis without network deps
    requests = None

from config import BEAUTIFY_DIR, FILE_RULES, JS_DIR, SCAN_MAX_WORKERS
from core.beautifier import beautify
from core.crypto import extract_crypto_material
from core.discovery import extract_inline_scripts, extract_js, extract_page_assets
from core.downloader import download_js, download_file, get_safe_filename
from core.url_policy import read_response_text, safe_get, validate_public_url
from core.source_maps import inspect_source_map
from core.runtime_evidence import attach_runtime_evidence, capture_runtime_evidence, runtime_evidence_enabled
from core.pipeline import ProgressModel, stage_plan
from core.scanner import scan_file

# Compatibility references keep older integrations that patch the two legacy
# discovery functions working, while normal scans use one cached page fetch.
_DISCOVERY_EXTRACT_JS = extract_js
_DISCOVERY_EXTRACT_INLINE = extract_inline_scripts


REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36"
    )
}


class ScanCancelled(Exception):
    """Raised internally when a user cancels an in-flight scan."""


def _check_cancel(cancel_check):
    if cancel_check and cancel_check():
        raise ScanCancelled("Scan cancelled by user")


def _scan_document(path, content, source_url=""):
    """Run all analyzers for one document and retain provenance.

    Provenance is essential for first/third-party classification and for
    manually verifying a finding.  A local artifact filename is not a URL and
    must never be used as a substitute for the script's actual origin.
    """
    content = content or ""
    data = scan_file(path, content=content)
    if data.get("source_map", {}).get("present"):
        try:
            data["source_map"] = inspect_source_map(content, source_url, timeout=10)
        except Exception as exc:
            data.setdefault("analysis_warnings", []).append(f"source_map: {exc}")
    crypto = extract_crypto_material(content, filename=os.path.basename(path))
    data.update(crypto)
    data["content_sha256"] = hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()
    data["url"] = str(source_url or "")
    data.setdefault("analysis_warnings", [])
    return data


def _merge_into(results, path, content, seen_hashes=None, source_url=""):
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
    data = _scan_document(path, content, source_url=source_url)
    results[path] = data
    return True


def analyze_content(code, filename="inline.js", progress_callback=None, cancel_check=None):
    """Analyze pasted JavaScript and return raw per-file results."""
    _check_cancel(cancel_check)
    progress = ProgressModel(stage_plan(mode="code"))

    def notify(phase, message, current=None, total=None):
        progress.set_stage(phase, current=0 if current is None else current,
                           total=0 if total is None else total)
        _notify(progress_callback, phase=phase, stage=progress.stage,
                stages=progress.stage_states(), current=progress.current,
                total=progress.total, percent=progress.percent, message=message)

    notify("analyze", "Analyzing pasted JavaScript", current=0, total=1)
    results = {}
    _merge_into(results, filename, code)
    _check_cancel(cancel_check)
    notify("correlate", "Correlating findings", current=1, total=1)
    progress.complete_stage()
    # "done" is the terminal phase the existing consumers watch for; the
    # canonical stage behind it is "report".
    notify("done", "Static analysis complete", current=1, total=1)
    return results


def _safe_local_filename(name, index):
    """Turn an uploaded file name into a safe, unique per-scan result key.

    Uploaded files are never written to disk; we only need a display-safe key
    for the results dict. Path components and newlines are stripped so a file
    named ``../../etc`` or ``a\\nb.js`` cannot confuse the UI.
    """
    base = os.path.basename(str(name or "").replace("\\", "/").strip())
    base = "".join(ch for ch in base if ch not in "\x00\r\n/").strip()
    if not base:
        base = f"snippet-{index + 1}.js"
    return base


def analyze_files(files, progress_callback=None, cancel_check=None):
    """Analyze several pasted/uploaded JavaScript documents in one scan.

    ``files`` is an iterable of ``{"filename": str, "code": str}``. Documents
    are analyzed locally and merged into one results dict, deduplicating
    identical content (the same way URL scans dedupe mirrored bundles). Nothing
    here is written to disk or sent anywhere; inputs come from the local UI.
    """
    files = [f for f in (files or []) if isinstance(f, dict)]
    total = max(1, len(files))
    _check_cancel(cancel_check)
    progress = ProgressModel(stage_plan(mode="files"))

    def notify(phase, message, current=None, total=None):
        progress.set_stage(phase, current=0 if current is None else current,
                           total=0 if total is None else total)
        _notify(progress_callback, phase=phase, stage=progress.stage,
                stages=progress.stage_states(), current=progress.current,
                total=progress.total, percent=progress.percent, message=message)

    notify("analyze", "Analyzing uploaded files", current=0, total=total)
    results = {}
    seen_hashes = set()
    used_names = set()
    for index, item in enumerate(files):
        _check_cancel(cancel_check)
        code = item.get("code") or ""
        if not isinstance(code, str) or not code.strip():
            continue
        name = _safe_local_filename(item.get("filename"), index)
        # Guarantee unique keys when two uploads share a basename.
        unique = name
        n = 2
        while unique in used_names:
            stem, ext = os.path.splitext(name)
            unique = f"{stem}-{n}{ext or '.js'}"
            n += 1
        used_names.add(unique)
        _merge_into(results, unique, code, seen_hashes=seen_hashes)
        notify("analyze", f"Analyzed {unique} ({index + 1}/{total})",
               current=index + 1, total=total)
    progress.complete_stage()
    notify("correlate", "Correlating findings", current=total, total=total)
    progress.complete_stage()
    notify("done", f"Static analysis complete: {len(results)} file(s)",
           current=total, total=total)
    return results



def _is_chunk(path):
    return bool(path and ("chunk-" in path or ".chunk." in path) and path.endswith((".js", ".mjs")))


def _download_chunk(url, output_dir=None, timeout=20, cancel_check=None):
    if requests is None or (cancel_check and cancel_check()):
        return None
    output_dir = output_dir or BEAUTIFY_DIR
    try:
        response = safe_get(url, timeout=timeout, headers=REQUEST_HEADERS)
        if response is None or response.status_code != 200:
            return None
        content = read_response_text(response, max_bytes=int(FILE_RULES.get("max_js_size", 2_000_000)))
        if not content:
            return None
        content = content.strip()
        if len(content.encode("utf-8", errors="ignore")) < max(1, int(FILE_RULES.get("min_js_size", 1))):
            return None
        if "<html" in content.lower() or "<!doctype" in content.lower():
            return None
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, get_safe_filename(url))
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
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

    Discovery is layered (see ``core.module_discovery``): exact
    import/require sources from the AST first, then bundler-specific asset
    signatures (Webpack chunk maps, Vite/Rollup/Next.js/Parcel assets), then
    the legacy regex layer for environments without a parser. Only script-like
    references are returned; arbitrary ``fetch``/API paths and JSON/CSS/font
    imports are never followed.
    """
    refs = set()

    # Layers 1+2: AST module understanding and bundler adapters.
    try:
        from core.module_discovery import discover_module_refs
        for ref in discover_module_refs(content):
            ref = ref.split("?")[0].split("#")[0]
            if _is_followable_ref(ref) or ref.startswith(("./", "../")):
                refs.add(ref)
    except Exception:
        pass

    # Fallback layer: regex coverage, kept as a safety net when the AST layer
    # is unavailable or cannot parse the dialect. Covers static imports,
    # dynamic import(...), CommonJS require, routed chunk files, /static/js
    # and assets bundles, and absolute script URLs.
    module_patterns = [
        r"""import\s*\(\s*['"]([^'"]+)['"]""",
        r"""require\s*\(\s*['"]([^'"]+)['"]""",
        r"""import\s+['"]([^'"]+)['"]""",
        r"""import\s+[^'"]+?\s+from\s*['"]([^'"]+)['"]""",
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


def _resolve_chunk(chunk_name, base_url, local_by_url=None, output_dir=None, timeout=20, cancel_check=None):
    """Resolve a module by exact URL, then fetch it safely.

    Never search the global output directory by basename: two sites commonly
    contain ``app.js`` and reusing the first one would mix scan data across
    targets.  ``local_by_url`` is populated by the current scan only.
    """
    chunk_name = str(chunk_name or "").split("?")[0]
    absolute = urljoin(base_url, chunk_name) if base_url else chunk_name
    canonical = absolute.split("#", 1)[0]
    if local_by_url and canonical in local_by_url:
        return local_by_url[canonical]
    if not base_url:
        return None
    candidates = (absolute,) if absolute.endswith((".js", ".mjs")) else (absolute, absolute + ".js")
    for candidate in candidates:
        path = _download_chunk(candidate, output_dir=output_dir, timeout=timeout, cancel_check=cancel_check)
        if path:
            if local_by_url is not None:
                local_by_url[candidate.split("#", 1)[0]] = path
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


def _attach_runtime(results, url, timeout=15, max_files=50, progress_callback=None, cancel_check=None, progress=None):
    """Load the page in a local headless browser and merge its evidence."""
    _check_cancel(cancel_check)

    def notify(phase, message, current=0, total=1):
        if progress is not None:
            progress.set_stage(phase, current=current, total=total)
            _notify(progress_callback, phase=phase, stage=progress.stage,
                    stages=progress.stage_states(), current=current, total=total,
                    percent=progress.percent, message=message)
        else:
            _notify(progress_callback, phase=phase, current=current, total=total, message=message)

    if not runtime_evidence_enabled():
        notify("verify", "Runtime evidence disabled", current=0, total=1)
        runtime = {
            "enabled": False,
            "available": False,
            "captured": False,
            "status": "disabled",
            "reason": "Runtime evidence is disabled by configuration.",
            "url": url,
        }
        return attach_runtime_evidence(results, runtime, target_url=url)

    notify("verify", "Executing page in local headless browser", current=0, total=1)
    runtime = capture_runtime_evidence(
        url,
        timeout_ms=max(2_000, int(float(timeout or 15) * 1000)),
        max_requests=max(60, min(max(50, int(max_files or 50) * 6), 600)),
    )
    _check_cancel(cancel_check)
    # Analyze script responses observed only after page execution (lazy chunks,
    # DOM-injected scripts, and route bundles).  Their source is local-only and
    # is removed from the runtime evidence object before serialization.
    runtime_scripts = runtime.pop("script_contents", {}) or {}
    seen = {str(item.get("content_sha256")) for item in results.values() if isinstance(item, dict)}
    for script_url, script_content in runtime_scripts.items():
        if not script_content:
            continue
        digest = hashlib.sha256(script_content.encode("utf-8", errors="ignore")).hexdigest()
        if digest in seen:
            continue
        path = f"runtime://{get_safe_filename(script_url)}"
        data = _scan_document(path, script_content, source_url=script_url)
        results[path] = data
        seen.add(digest)
    notify("verify", "Runtime evidence captured", current=1, total=1)
    if progress is not None:
        progress.complete_stage()
    return attach_runtime_evidence(results, runtime, target_url=url)


def analyze_url(
    url,
    max_depth=5,
    timeout=15,
    max_files=100,
    progress_callback=None,
    max_workers=None,
    cancel_check=None,
):
    """Discover, download, beautify and recursively analyze a web app's JS.

    The scan is a bounded-parallel breadth-first walk across module/chunk
    references rather than only the entry scripts. The worker pool is capped at
    ``max_workers`` (default from config, 6) so a 50+ bundle site is scanned
    quickly without exhausting the local machine.

    Every discoverable script is followed: static ``import``/``require``,
    dynamic ``import()``, ``chunk-*`` bundles, ``/static/js`` and ``assets``
    assets, modulepreload links and inline module scripts. When the configured
    file cap or a per-file limit is hit, the asset is reported through
    ``__scan_summary__`` instead of being silently dropped.
    """
    max_files = int(max_files or 1000)
    if max_files <= 0:
        max_files = 1000
    workers = max(1, min(int(max_workers or SCAN_MAX_WORKERS), 32))
    _check_cancel(cancel_check)
    if not os.environ.get("SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS"):
        valid, reason = validate_public_url(url)
        if not valid:
            raise ValueError(reason)

    # Every URL scan gets an isolated, automatically removed workspace.  Apart
    # from being cheaper to clean up, this prevents an old app.js from another
    # target being selected for a new scan.
    workspace_obj = tempfile.TemporaryDirectory(prefix="scriptsentry-scan-")
    workspace = workspace_obj.name
    scan_js_dir = os.path.join(workspace, "js")
    scan_beautify_dir = os.path.join(workspace, "beautified")
    os.makedirs(scan_js_dir, exist_ok=True)
    os.makedirs(scan_beautify_dir, exist_ok=True)
    results = {}
    os.makedirs(JS_DIR, exist_ok=True)
    os.makedirs(BEAUTIFY_DIR, exist_ok=True)

    state = {
        "skipped_files": 0,
        "skipped_reasons": set(),
        "path_to_url": {},
        "script_urls": [],
        "script_edges": [],
        "workspace": workspace,
        "workspace_obj": workspace_obj,
        "local_by_url": {},
    }
    lock = threading.Lock()
    seen_hashes = set()
    visited_urls = set()
    known_paths = set()

    # Weighted, monotonic progress across the pipeline stages. Without this the
    # bar is "files done / file cap", which sits at 3% for a small site and
    # makes any ETA derived from it meaningless.
    progress = ProgressModel(stage_plan(mode="url", runtime_enabled=runtime_evidence_enabled()))
    total_bytes = 0

    def notify(phase, message, current=None, total=None):
        progress.set_stage(phase,
                           current=0 if current is None else int(current),
                           total=0 if total is None else int(total))
        _notify(
            progress_callback,
            phase=phase,
            stage=progress.stage,
            stages=progress.stage_states(),
            current=progress.current,
            total=progress.total,
            percent=progress.percent,
            scanned_bytes=scanned_bytes(),
            total_bytes=max(1, total_bytes),
            message=message,
        )

    def record_skip(reason):
        with lock:
            state["skipped_files"] += 1
            state["skipped_reasons"].add(reason)

    def scanned_bytes():
        with lock:
            return sum(data.get("file_size", 0) for data in results.values())

    def scan_progress(phase, message):
        # `max_files` is a *cap*, not the expected work; dividing by it makes a
        # 4-script site report 4%. Estimate the real workload instead: at least
        # the entry scripts, at most the cap, and never below what is done.
        expected = max(len(initial_tasks), len(results), 1)
        notify(phase, message, current=len(results), total=min(int(max_files), expected))

    notify("recon", "Reading page and extracting script references", current=0, total=1)
    _check_cancel(cancel_check)
    # Keep the two compatibility entry points (older callers patch these),
    # while discovery itself reuses its bounded page fetch cache.
    if extract_js is _DISCOVERY_EXTRACT_JS and extract_inline_scripts is _DISCOVERY_EXTRACT_INLINE:
        js_links, inline_scripts, page_metadata = extract_page_assets(url, timeout=timeout)
    else:
        # Backward-compatible seam for embedders/tests that provide their own
        # page discovery implementation.
        js_links = extract_js(url)
        inline_scripts = extract_inline_scripts(url)
        page_metadata = {"page_fetch": "compatibility_discovery"}
    _check_cancel(cancel_check)
    state["page_metadata"] = page_metadata
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
            cancel_check=cancel_check,
            progress=progress,
        )

    state["script_urls"].extend(discovered[:max_files])
    state["script_edges"].extend(
        {"from": url, "to": link, "kind": "html_script", "depth": 0}
        for link in discovered[:max_files]
    )
    notify("discover",
           f"Discovered {len(discovered)} external scripts and {len(inline_scripts)} inline script(s)",
           current=0, total=len(discovered) or 1)
    notify("download", f"Downloading {len(discovered[:max_files])} script(s)",
           current=0, total=len(discovered[:max_files]) or 1)
    downloads = download_js(
        discovered[:max_files],
        progress_callback=progress_callback,
        output_dir=scan_js_dir,
        timeout=timeout,
        cancel_check=cancel_check,
    )
    _check_cancel(cancel_check)
    beautified = []
    if downloads:
        notify("normalize", "Normalizing downloaded bundles", current=0, total=len(downloads))
        beautified = beautify(downloads, output_dir=scan_beautify_dir)
        progress.complete_stage()

    _check_cancel(cancel_check)
    total_bytes = sum((os.path.getsize(path) if os.path.isfile(path) else 0) for path in beautified)
    total_bytes += sum(len(body.encode("utf-8", errors="ignore")) for body in inline_scripts)

    # Top-level downloads keep the URL-unique safe name, so we can restore the
    # per-file base URL before walking that bundle's nested imports.
    safe_name_to_url = {}
    for link in discovered[:max_files]:
        safe_name_to_url[get_safe_filename(link)] = link
        state["local_by_url"][link.split("#", 1)[0].split("?", 1)[0]] = os.path.join(scan_beautify_dir, get_safe_filename(link))

    # Seed the first round with inline scripts plus every beautified entry.
    initial_tasks = []
    for index, body in enumerate(inline_scripts):
        initial_tasks.append((f"inline-{index + 1}.js", url, body, "inline_scan", 1))
    for path in beautified:
        current_url = safe_name_to_url.get(os.path.basename(path)) or url
        initial_tasks.append((path, current_url, None, "scan", 1))

    if len(initial_tasks) > max_files:
        excess = len(initial_tasks) - max_files
        with lock:
            state["skipped_files"] += excess
            state["skipped_reasons"].add("scanned_files_limit")
        initial_tasks = initial_tasks[:max_files]

    for path, _, _, _, _ in initial_tasks:
        known_paths.add(path)

    def merge_document(path, base_url, content):
        """Thread-safe merge. Returns a skip reason, or None when added."""
        _check_cancel(cancel_check)
        content = content or ""
        if len(content.encode("utf-8", errors="ignore")) > FILE_RULES.get("max_js_size", 2_000_000):
            record_skip("oversized_script")
            return "oversized_script"
        digest = hashlib.md5(content.encode("utf-8", errors="ignore")).hexdigest()
        with lock:
            if digest in seen_hashes:
                state["skipped_files"] += 1
                state["skipped_reasons"].add("duplicate_content")
                return "duplicate_content"
            seen_hashes.add(digest)
        data = _scan_document(path, content, source_url=base_url)
        with lock:
            results[path] = data
            state["path_to_url"][path] = base_url
            state["script_urls"].append(base_url)
        return None

    def discover_tasks(content, base_url, depth):
        if depth >= max_depth:
            return []
        new_tasks = []
        for ref in extract_script_refs(content):
            with lock:
                at_cap = len(results) >= max_files
            if at_cap:
                record_skip("scanned_files_limit")
                return new_tasks
            absolute_url = urljoin(base_url, ref) if not ref.startswith(("http://", "https://")) else ref
            key = absolute_url.split("?")[0].split("#")[0]
            with lock:
                if key in visited_urls:
                    continue
                visited_urls.add(key)
            next_path = _resolve_chunk(
                ref,
                base_url,
                local_by_url=state["local_by_url"],
                output_dir=scan_beautify_dir,
                timeout=timeout,
                cancel_check=cancel_check,
            )
            if not next_path:
                continue
            with lock:
                if next_path in known_paths or len(results) + len(new_tasks) >= max_files:
                    continue
                known_paths.add(next_path)
                state["script_urls"].append(absolute_url)
            new_tasks.append((next_path, absolute_url, None, "recursive_scan", depth + 1))
            state["script_edges"].append({"from": base_url, "to": absolute_url, "kind": "module_reference", "depth": depth + 1})
        return new_tasks

    def process_task(task):
        _check_cancel(cancel_check)
        path, base_url, inline_content, phase, depth = task
        if inline_content is not None:
            content = inline_content
        else:
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception:
                record_skip("read_error")
                return []
        skipped = merge_document(path, base_url, content)
        if skipped:
            scan_progress(phase, f"Skipping {skipped.replace('_', ' ')} {os.path.basename(path)}")
            return []
        scan_progress(phase, f"Analyzing {os.path.basename(path)} ({len(results)}/{max_files})")
        return discover_tasks(content, base_url, depth)

    # Bounded-parallel BFS rounds. Each round scans current assets with a
    # worker pool, then hands discovered chunks to the next round.
    current_round = initial_tasks
    while current_round and len(results) < max_files:
        _check_cancel(cancel_check)
        next_round = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_map = {executor.submit(process_task, task): task for task in current_round}
            for future in as_completed(future_map):
                try:
                    next_round.extend(future.result() or [])
                except ScanCancelled:
                    raise
                except Exception:
                    record_skip("worker_error")
        current_round = next_round[: max(0, max_files - len(results))]

    results["__scan_summary__"] = {
        "total_discovered": len(discovered) + len(inline_scripts),
        "total_files": len(results),
        "skipped_files": state.get("skipped_files", 0),
        "skipped_reasons": sorted(state.get("skipped_reasons", [])),
        "bytes_scanned": scanned_bytes(),
        "total_bytes": max(1, total_bytes),
        "max_files": max_files,
        "max_workers": workers,
        "capped": state.get("skipped_files", 0) > 0,
        "script_urls": sorted(set(state.get("script_urls", []))),
        "script_edges": list(state.get("script_edges", []))[:200],
        "analysis_warnings": list(state.get("skipped_reasons", [])),
        "page": state.get("page_metadata", {}),
        # Local artifact path -> the URL it came from. Without this a report
        # names a temporary file that is deleted when the scan ends, and no
        # finding can be traced back to the asset that produced it.
        "path_to_url": dict(state.get("path_to_url", {})),
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
        cancel_check=cancel_check,
        progress=progress,
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
    cancel_check=None,
    progress=None,
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
        "script_edges": list(state.get("script_edges", []))[:200],
        "analysis_warnings": list(state.get("skipped_reasons", [])),
        "page": state.get("page_metadata", {}),
        "path_to_url": dict(state.get("path_to_url", {})),
    }
    results["__scan_summary__"] = summary

    if progress is not None:
        progress.complete_stage()
        progress.set_stage("report", current=1, total=1)
    _notify(
        progress_callback,
        phase="done",
        stage="report",
        stages=progress.stage_states() if progress is not None else None,
        current=len(results),
        total=len(results) or 1,
        percent=max(progress.percent if progress is not None else 0, 0),
        scanned_bytes=summary.get("bytes_scanned", 0),
        total_bytes=max(1, summary.get("total_bytes", 0)),
        message=f"Static analysis complete: {len(results)} unique script(s)",
    )
    runtime_results = _attach_runtime(
        results, url, timeout=timeout, max_files=max_files,
        progress_callback=progress_callback, cancel_check=cancel_check,
        progress=progress,
    )
    runtime = runtime_results.get("__runtime_evidence__") or {}
    runtime_summary = runtime_results.get("__scan_summary__") or summary
    runtime_summary["total_files"] = sum(1 for key in runtime_results if not str(key).startswith("__"))
    runtime_summary["bytes_scanned"] = sum(
        int(data.get("file_size", 0)) for key, data in runtime_results.items()
        if not str(key).startswith("__") and isinstance(data, dict)
    )
    runtime_summary["runtime_scripts_analyzed"] = sum(1 for key in runtime_results if str(key).startswith("runtime://"))
    runtime_summary["runtime_status"] = runtime.get("status", "not_run")
    runtime_summary["runtime_captured"] = bool(runtime.get("captured"))
    runtime_results["__scan_summary__"] = runtime_summary
    workspace_obj = state.get("workspace_obj")
    if workspace_obj is not None:
        try:
            workspace_obj.cleanup()
        except Exception:
            pass
    else:
        workspace = state.get("workspace")
        if workspace:
            try:
                shutil.rmtree(workspace, ignore_errors=True)
            except Exception:
                pass
    return runtime_results
