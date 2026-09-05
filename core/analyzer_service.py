"""High-level analysis orchestration used by the CLI and the Web dashboard."""
import contextlib
import hashlib
import os
import re
import shutil
import tempfile
import threading
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, ThreadPoolExecutor, as_completed, wait
from concurrent.futures.process import BrokenProcessPool
from pickle import PicklingError
from urllib.parse import urljoin, urlparse

try:
    import requests
except ImportError:  # allow pure-paste code analysis without network deps
    requests = None

from config import BEAUTIFY_DIR, FILE_RULES, JS_DIR, SCAN_MAX_WORKERS
from core.beautifier import beautify
from core.crypto import extract_crypto_material
from core.discovery import extract_inline_scripts, extract_js, extract_page_assets
from core.discovery import sitemap_pages
from core.downloader import download_js, get_safe_filename
from core.url_policy import read_response_text, safe_get, validate_public_url
from core.source_maps import load_source_map
from core.runtime_evidence import attach_runtime_evidence, capture_runtime_evidence, runtime_evidence_enabled
from core.pipeline import ProgressModel, stage_plan
from core.js_parser import clear_parse_cache
from core.scanner import HEARTBEAT_MIN_CHARS, ScanCancelled, scan_file

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


def _check_cancel(cancel_check):
    if cancel_check and cancel_check():
        raise ScanCancelled("Scan cancelled by user")


def analyze_engine():
    """Which engine runs the CPU-bound per-document analysis.

    ``process`` (default): each document is analyzed in a worker process, so
    the GIL no longer serializes tree-sitter parsing and the Python AST
    walks -- a 6-worker scan gets ~6 cores instead of ~1. ``thread`` opts
    back into the legacy in-process pool (also the automatic fallback when
    process pools are unavailable).
    """
    return (os.environ.get("SCRIPTSENTRY_ANALYZE_ENGINE") or "process").strip().lower()


# Source-map expansion: how much of a map's embedded original code we are
# willing to analyze per document. Original sources are usually small, but a
# hostile/oversized map must not triple the scan cost silently. All knobs are
# environment-tunable and the whole feature has a kill switch.
SOURCEMAP_MAX_SOURCES = 12       # per bundle
SOURCEMAP_MAX_SOURCE_CHARS = 400_000   # per source file
SOURCEMAP_TOTAL_CHAR_BUDGET = 3_000_000
SOURCEMAP_MAX_MERGED_FINDINGS = 40     # per bundle


def _sourcemap_analysis_enabled():
    return os.environ.get("SCRIPTSENTRY_SOURCEMAP_ANALYSIS", "1").strip().lower() not in ("0", "false", "no")


def _sourcemap_source_cap():
    try:
        return max(0, min(int(os.environ.get("SCRIPTSENTRY_SOURCEMAP_SOURCES", SOURCEMAP_MAX_SOURCES)), 50))
    except (TypeError, ValueError):
        return SOURCEMAP_MAX_SOURCES


def _expand_source_map_sources(data, map_metadata, contents, source_url, cancel_check=None,
                               progress_heartbeat=None):
    """Analyze a bundle's embedded original sources and merge the evidence.

    Original source analysis upgrades exactly what minification destroys:
    findings keep the real file names (``src/auth/config.ts``), and taint /
    secret evidence comes from code that was never mangled. Source findings
    are appended to the bundle's unified finding list, tagged ``via`` so the
    UI and exports can show where each one really lives; per-source records
    land in ``data["source_map"]["sources_analyzed"]``.

    Bounded by design: at most ``SOURCEMAP_MAX_SOURCES`` sources, each under
    ``SOURCEMAP_MAX_SOURCE_CHARS``, within a total character budget, with
    content-hash dedup against the bundle itself.
    """
    if not contents:
        return
    if not map_metadata.get("sources_content_count"):
        map_metadata["analysis_note"] = "Map lists sources but embeds no contents (sourcesContent empty)."
        return
    if not _sourcemap_analysis_enabled():
        map_metadata["analysis_note"] = "Source-map analysis disabled (SCRIPTSENTRY_SOURCEMAP_ANALYSIS=0)."
        return

    parent_hash = data.get("content_sha256", "")
    seen_hashes = {parent_hash} if parent_hash else set()
    budget = SOURCEMAP_TOTAL_CHAR_BUDGET
    cap = _sourcemap_source_cap()
    origin = str(source_url or data.get("url") or "")
    origin_label = f"{origin} (via source map)" if origin else "via source map"

    analyzed = []
    skip_reasons = []
    merged_findings = 0

    for display_name, source_text in contents:
        if len(analyzed) >= cap or merged_findings >= SOURCEMAP_MAX_MERGED_FINDINGS:
            skip_reasons.append("source_cap_reached")
            break
        if progress_heartbeat is not None:
            progress_heartbeat(f"source map: {os.path.basename(display_name)}")
        _check_cancel(cancel_check)
        if len(source_text) > SOURCEMAP_MAX_SOURCE_CHARS:
            skip_reasons.append(f"oversized_source:{display_name}")
            continue
        digest = hashlib.sha256(source_text.encode("utf-8", errors="ignore")).hexdigest()
        if digest in seen_hashes:
            skip_reasons.append(f"duplicate_source:{display_name}")
            continue
        if budget - len(source_text) < 0:
            skip_reasons.append("analysis_budget_exhausted")
            break
        budget -= len(source_text)
        seen_hashes.add(digest)

        source_data = scan_file(display_name, content=source_text, cancel_check=cancel_check)
        source_data.pop("source_map", None)
        severity_counts = {}
        for finding in source_data.get("findings", []):
            severity = str(finding.get("severity") or "MEDIUM").upper()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        analyzed.append({
            "name": display_name,
            "bytes": len(source_text),
            "findings": len(source_data.get("findings", []) or []),
            "credible_secrets": len(source_data.get("credible_secrets", []) or []),
            "severities": severity_counts,
            "score": source_data.get("score", 0),
        })

        for finding in source_data.get("findings", []) or []:
            if merged_findings >= SOURCEMAP_MAX_MERGED_FINDINGS:
                break
            record = dict(finding)
            record["file"] = display_name
            record["origin"] = origin_label
            record["via"] = "source_map"
            data["findings"].append(record)
            merged_findings += 1

    data["findings"] = data["findings"][:80 + SOURCEMAP_MAX_MERGED_FINDINGS]
    map_metadata["sources_analyzed"] = analyzed
    map_metadata["analyzed_sources"] = len(analyzed)
    map_metadata["sources_findings"] = sum(entry["findings"] for entry in analyzed)
    if skip_reasons:
        map_metadata["analysis_skipped"] = skip_reasons[:20]


def _scan_document_cpu(path, content, source_url="", cancel_check=None,
                       progress_heartbeat=None):
    """CPU-only half of _scan_document: scan_file + crypto fingerprinting.

    Everything here is pure computation over the content string with plain
    dict/list outputs, so it can run inside a process-pool worker (see
    _analyze_document_worker). Network work (source maps) stays in the
    caller's process.
    """
    content = content or ""
    data = scan_file(path, content=content, cancel_check=cancel_check,
                     progress_heartbeat=progress_heartbeat)
    data["content_sha256"] = hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()
    data["url"] = str(source_url or "")
    crypto = extract_crypto_material(content, filename=os.path.basename(path))
    data.update(crypto)
    data.setdefault("analysis_warnings", [])
    return data


def _expand_document_source_maps(data, content, source_url="", cancel_check=None,
                                 progress_heartbeat=None):
    """Fetch and analyze a bundle's source map when it references one (I/O)."""
    if not data.get("source_map", {}).get("present"):
        return
    try:
        map_metadata, map_contents = load_source_map(content, base_url=source_url, timeout=10)
        data["source_map"] = map_metadata
        if map_contents:
            _expand_source_map_sources(
                data, map_metadata, map_contents, source_url,
                cancel_check=cancel_check, progress_heartbeat=progress_heartbeat)
    except ScanCancelled:
        raise
    except Exception as exc:
        data.setdefault("analysis_warnings", []).append(f"source_map: {exc}")


def _scan_document(path, content, source_url="", cancel_check=None, progress_heartbeat=None):
    """Run all analyzers for one document and retain provenance.

    Provenance is essential for first/third-party classification and for
    manually verifying a finding.  A local artifact filename is not a URL and
    must never be used as a substitute for the script's actual origin.
    """
    content = content or ""
    data = _scan_document_cpu(path, content, source_url=source_url,
                              cancel_check=cancel_check,
                              progress_heartbeat=progress_heartbeat)
    _expand_document_source_maps(data, content, source_url=source_url,
                                 cancel_check=cancel_check,
                                 progress_heartbeat=progress_heartbeat)
    return data


def _analyze_document_worker(path, content, source_url="", heartbeat_queue=None, phase="analyze"):
    """Process-pool entry point: analyze one document in a worker process.

    Returns ``(data, script_refs)`` -- both plain picklable structures. The
    tree-sitter parse, the taint/attack-surface walks and module-reference
    discovery all share one parse *inside this process*, then the results
    cross the process boundary once. Mid-file heartbeats for large bundles
    travel back through ``heartbeat_queue`` as ``(phase, name, detail)``
    tuples so the dashboard keeps moving during long analyses.
    """
    content = content or ""
    heartbeat = None
    if heartbeat_queue is not None and len(content) >= HEARTBEAT_MIN_CHARS:
        name = os.path.basename(path) if path else "inline script"

        def heartbeat(detail, _phase=phase, _name=name, _q=heartbeat_queue):
            # A dead heartbeat queue must never take the scan down with it.
            with contextlib.suppress(Exception):
                _q.put((_phase, _name, str(detail)))

    data = _scan_document_cpu(path, content, source_url=source_url,
                              cancel_check=None, progress_heartbeat=heartbeat)
    refs = extract_script_refs(content)
    return data, refs


def _merge_into(results, path, content, seen_hashes=None, source_url="", cancel_check=None,
                progress_heartbeat=None):
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
    data = _scan_document(path, content, source_url=source_url, cancel_check=cancel_check,
                          progress_heartbeat=progress_heartbeat)
    results[path] = data
    return True


def analyze_content(code, filename="inline.js", progress_callback=None, cancel_check=None):
    """Analyze pasted JavaScript and return raw per-file results."""
    clear_parse_cache()
    _check_cancel(cancel_check)
    progress = ProgressModel(stage_plan(mode="code"))

    def notify(phase, message, current=None, total=None, total_bytes=None):
        progress.set_stage(phase, current=0 if current is None else current,
                           total=0 if total is None else total)
        _notify(progress_callback, phase=phase, stage=progress.stage,
                stages=progress.stage_states(), current=progress.current,
                total=progress.total, percent=progress.percent,
                total_bytes=total_bytes, message=message)

    notify("analyze", "Analyzing pasted JavaScript", current=0, total=1,
           total_bytes=len(code.encode("utf-8", errors="ignore")))

    def _heartbeat(detail):
        # A very large paste can occupy the engine for a while; keep the
        # dashboard's heartbeat and message moving during it.
        notify("analyze", f"Analyzing pasted JavaScript - {detail}")

    results = {}
    _merge_into(results, filename, code, cancel_check=cancel_check,
                progress_heartbeat=_heartbeat)
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
    clear_parse_cache()
    files = [f for f in (files or []) if isinstance(f, dict)]
    total = max(1, len(files))
    _check_cancel(cancel_check)
    progress = ProgressModel(stage_plan(mode="files"))

    def notify(phase, message, current=None, total=None, total_bytes=None):
        progress.set_stage(phase, current=0 if current is None else current,
                           total=0 if total is None else total)
        _notify(progress_callback, phase=phase, stage=progress.stage,
                stages=progress.stage_states(), current=progress.current,
                total=progress.total, percent=progress.percent,
                total_bytes=total_bytes, message=message)

    total_bytes = sum(len((item.get("code") or "").encode("utf-8", errors="ignore"))
                      for item in files if isinstance(item, dict))
    notify("analyze", "Analyzing uploaded files", current=0, total=total,
           total_bytes=total_bytes)
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
        heartbeat = None
        if len(code) >= HEARTBEAT_MIN_CHARS:
            def heartbeat(detail, _name=unique):
                notify("analyze", f"Analyzing {_name} - {detail}")
        _merge_into(results, unique, code, seen_hashes=seen_hashes, cancel_check=cancel_check,
                    progress_heartbeat=heartbeat)
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
        response = safe_get(url, timeout=timeout, headers=REQUEST_HEADERS, cancel_check=cancel_check)
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
    return bool(re.search(r"\.(?:js|mjs)$", ref)
                or "chunk-" in ref or "/static/js/" in ref or "assets/" in ref)


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
    cancel_check=None,
):
    if depth >= max_depth:
        return

    max_files = int(max_files or 1000)
    visited = set(visited or [])
    state = state if state is not None else {}
    skipped = state.setdefault("skipped_files", 0)
    for ref in extract_script_refs(content):
        _check_cancel(cancel_check)
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
        if not _merge_into(results, next_path, next_content, seen_hashes=seen_hashes, cancel_check=cancel_check):
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
            cancel_check=cancel_check,
        )


def _notify(callback, **kwargs):
    if callback:
        # Listener faults are never the scan's business.
        with contextlib.suppress(Exception):
            callback(**kwargs)


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
    # The capture is one long, event-free call; without a heartbeat the stage
    # looks frozen for its whole duration. A quiet side thread re-reports the
    # elapsed time every few seconds so the UI can show forward motion.
    capture_done = threading.Event()

    def _capture_heartbeat():
        seconds = 0
        while not capture_done.wait(5.0):
            seconds += 5
            notify("verify", f"Capturing runtime evidence… {seconds}s elapsed", current=0, total=1)

    beat = threading.Thread(target=_capture_heartbeat, name="scriptsentry-runtime-heartbeat", daemon=True)
    beat.start()
    try:
        runtime = capture_runtime_evidence(
            url,
            timeout_ms=max(2_000, int(float(timeout or 15) * 1000)),
            max_requests=max(60, min(max(50, int(max_files or 50) * 6), 600)),
        )
    finally:
        capture_done.set()
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
        data = _scan_document(path, script_content, source_url=script_url, cancel_check=cancel_check)
        results[path] = data
        seen.add(digest)
    # The verify stage is the one stage whose outcome is not guaranteed; report
    # what actually happened instead of claiming a capture that failed.
    status = runtime.get("status", "not_run")
    if runtime.get("captured"):
        notify("verify", "Runtime evidence captured", current=1, total=1)
    elif status in ("disabled", "missing_dependency"):
        notify("verify", f"Runtime evidence skipped ({status})", current=1, total=1)
    else:
        notify("verify", f"Runtime evidence unavailable ({status})", current=1, total=1)
    if progress is not None:
        progress.complete_stage()
    return attach_runtime_evidence(results, runtime, target_url=url)


def _fetch_target_script(url, timeout=15, cancel_check=None):
    """Download one JS document when the *target itself* is a script.

    Returns the source text, or None when the URL did not yield JavaScript
    (unreachable, non-200, empty, or an HTML page — a soft 404). Callers fall
    back to normal page discovery, so a wrapper page served at a ``.js`` URL
    still works.
    """
    if cancel_check and cancel_check():
        return None
    try:
        response = safe_get(url, timeout=timeout, headers=REQUEST_HEADERS, cancel_check=cancel_check)
        if response is None or response.status_code != 200:
            return None
        content = read_response_text(response, max_bytes=int(FILE_RULES.get("max_js_size", 2_000_000)))
        if not content:
            return None
        content = content.strip()
        if not content:
            return None
        # A JS asset should never be an HTML page; treat that as a miss.
        if "<html" in content.lower() or "<!doctype" in content.lower():
            return None
        return content
    except Exception:
        return None


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
    clear_parse_cache()
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
        # Workload discovered so far (entry scripts + nested chunks), used by
        # the ETA model. Grows as discovery finds more; never reported above
        # the user's file cap.
        "expected_files": 0,
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
            expected_files=state.get("expected_files", 0),
            message=message,
        )

    def record_skip(reason):
        with lock:
            state["skipped_files"] += 1
            state["skipped_reasons"].add(reason)

    def scanned_bytes():
        with lock:
            return sum(data.get("file_size", 0) for data in results.values())

    def scan_progress(phase, message, current=None, total=None):
        # `max_files` is a *cap*, not the expected work; dividing by it makes a
        # 4-script site report 4%. Estimate the real workload instead: at least
        # the entry scripts, at most the cap, and never below what is done.
        expected = max(len(initial_tasks), len(results), 1)
        if total is not None:
            expected = max(expected, int(total))
        notify(phase, message,
               current=len(results) if current is None else int(current),
               total=min(int(max_files), expected) if total is None else int(total))

    notify("recon", "Reading page and extracting script references", current=0, total=1)
    _check_cancel(cancel_check)

    # A direct .js/.mjs target IS the deliverable — analyze the document
    # itself and follow the module/chunk references inside it. The old path
    # treated every target as an HTML page, so scanning
    # ``https://example.com/app.js`` reported an empty "no JavaScript found"
    # result: a broken promise for a URL the input field explicitly suggests.
    direct_script = urlparse(url).path.lower().endswith((".js", ".mjs"))
    direct_script_body = _fetch_target_script(url, timeout=timeout, cancel_check=cancel_check) if direct_script else None

    # Keep the two compatibility entry points (older callers patch these),
    # while discovery itself reuses its bounded page fetch cache.
    if extract_js is _DISCOVERY_EXTRACT_JS and extract_inline_scripts is _DISCOVERY_EXTRACT_INLINE:
        js_links, inline_scripts, page_metadata = extract_page_assets(url, timeout=timeout, cancel_check=cancel_check)
        # Deeper discovery: pages the site declares in robots.txt/sitemap.xml
        # often lead to lazy chunks the landing page never references.
        # Strictly bounded (SCRIPTSENTRY_SITEMAP_DISCOVERY=0 disables).
        if os.environ.get("SCRIPTSENTRY_SITEMAP_DISCOVERY", "1").strip().lower() not in ("0", "false", "no", "off"):
            extra_pages, sitemap_meta = sitemap_pages(url, timeout=timeout, cancel_check=cancel_check)
            page_metadata["sitemap"] = sitemap_meta
            for page_url in extra_pages:
                _check_cancel(cancel_check)
                page_scripts, page_inline, _page_meta = extract_page_assets(
                    page_url, timeout=timeout, cancel_check=cancel_check)
                for script in page_scripts:
                    if script not in js_links:
                        js_links.append(script)
                state["script_edges"].extend(
                    {"from": page_url, "to": script, "kind": "sitemap_page", "depth": 0}
                    for script in page_scripts[:10])
                # A sitemap page's inline scripts are analyzed like the entry
                # page's, but bounded so a huge sitemap cannot explode work.
                if len(inline_scripts) < 12:
                    inline_scripts.extend(page_inline[: 12 - len(inline_scripts)])
    else:
        # Backward-compatible seam for embedders/tests that provide their own
        # page discovery implementation.
        js_links = extract_js(url)
        inline_scripts = extract_inline_scripts(url)
        page_metadata = {"page_fetch": "compatibility_discovery"}
    if direct_script_body is not None:
        js_links = []
        inline_scripts = [direct_script_body]
        page_metadata = {
            "page_fetch": "ok",
            "page_bytes": len(direct_script_body.encode("utf-8", errors="ignore")),
            "inline_count": 1,
            "direct_script": True,
        }
    _check_cancel(cancel_check)
    state["page_metadata"] = page_metadata
    discovered = list(dict.fromkeys(js_links))
    if not discovered and not inline_scripts:
        # A page that fetched fine but has no JS is a legitimate (empty)
        # result. A page we could not fetch at all is not: without this the
        # scan "completed" in seconds with an empty dashboard, which reads
        # exactly like success and hides a network/bot-protection problem.
        if (page_metadata or {}).get("page_fetch") == "failed":
            raise ValueError(
                f"Could not download the page at {url} — the site may be unreachable, "
                "rate-limiting non-browser requests, or the URL may be wrong. "
                "Check the address and your connection, then try again."
            )
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

    state["expected_files"] = min(max_files, len(discovered) + len(inline_scripts))
    state["script_urls"].extend(discovered[:max_files])
    if direct_script_body is not None:
        state["script_urls"].append(url)
    state["script_edges"].extend(
        {"from": url, "to": link, "kind": "html_script", "depth": 0}
        for link in discovered[:max_files]
    )
    if direct_script_body is not None:
        notify("discover", "Following the target script's module and chunk references",
               current=0, total=1)
    else:
        notify("discover",
               f"Discovered {len(discovered)} external scripts and {len(inline_scripts)} inline script(s)",
               current=0, total=len(discovered) or 1)
    if not discovered:
        # Nothing to fetch beyond the target itself (a direct .js target, or
        # an all-inline page): skip the download/normalize stages entirely
        # instead of announcing "Downloading 0 script(s)".
        downloads = []
    else:
        notify("download", f"Downloading {len(discovered[:max_files])} script(s)",
               current=0, total=len(discovered[:max_files]) or 1)
        # Route the downloader's raw per-file counters through ``notify`` so
        # they keep the weighted, monotonic percent (and the stage strip)
        # consistent. The downloader used to call the job callback directly
        # with only ``current``/``total``; the job then derived
        # percent = current/total, so the bar jumped to 100% on the last
        # download and snapped back afterwards.
        downloads = download_js(
            discovered[:max_files],
            progress_callback=lambda **kw: notify(
                "download",
                kw.get("message") or f"Downloading scripts {kw.get('current', 0)}/{kw.get('total', 1)}",
                current=kw.get("current"),
                total=kw.get("total"),
            ),
            output_dir=scan_js_dir,
            timeout=timeout,
            cancel_check=cancel_check,
        )
    _check_cancel(cancel_check)
    beautified = []
    if downloads:
        # ``beautify`` emits its own per-file start/finish events; they are
        # funnelled through ``notify`` so the weighted percent stays monotonic.
        beautified = beautify(
            downloads,
            output_dir=scan_beautify_dir,
            progress_callback=lambda **kw: notify(
                "normalize",
                kw.get("message") or "Normalizing downloaded bundles",
                current=kw.get("current"),
                total=kw.get("total"),
            ),
            cancel_check=cancel_check,
        )
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
        # A direct .js target keeps its real (URL-derived) name; genuine
        # inline page scripts get generic names.
        name = f"inline-{index + 1}.js"
        if direct_script and index == 0 and body is direct_script_body:
            name = get_safe_filename(url)
        initial_tasks.append((name, url, body, "inline_scan", 1))
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

    def _task_heartbeat(content, phase, path):
        if len(content or "") < HEARTBEAT_MIN_CHARS:
            # Announce progress *inside* a long single-file analysis. Without
            # this a 2 MB bundle is silent from "Scanning x..." to "Analyzed
            # x", which is the single longest quiet stretch of a scan.
            return None
        file_name = os.path.basename(path) if path else "inline script"

        def heartbeat(detail, _phase=phase, _name=file_name):
            scan_progress(_phase, f"Analyzing {_name} - {detail}")

        return heartbeat

    def _skip_message(phase, reason, name):
        scan_progress(phase, f"Skipping {reason.replace('_', ' ')} {name} ({len(results)}/{max_files})")

    def prepare_task(task):
        """Parent-side pre-analysis: announce, read, size/dedupe checks.

        Returns ``(path, base_url, content, phase, depth)`` or None when the
        task was skipped (reason already recorded/announced).
        """
        _check_cancel(cancel_check)
        path, base_url, inline_content, phase, depth = task
        name = os.path.basename(path) if path else "inline script"
        if inline_content is None:
            # Announce the work BEFORE it starts. The old code only spoke after
            # a file finished, so a big bundle silently monopolized a worker
            # for a minute or more while the UI showed nothing new -- the
            # single most "is it stuck?" moment of a scan.
            scan_progress(phase, f"Scanning {name}…")
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception:
                record_skip("read_error")
                scan_progress(phase, f"Could not read {name} — skipped")
                return None
        else:
            content = inline_content
        content = content or ""
        if len(content.encode("utf-8", errors="ignore")) > FILE_RULES.get("max_js_size", 2_000_000):
            record_skip("oversized_script")
            _skip_message(phase, "oversized_script", name)
            return None
        digest = hashlib.md5(content.encode("utf-8", errors="ignore")).hexdigest()
        with lock:
            if digest in seen_hashes:
                state["skipped_files"] += 1
                state["skipped_reasons"].add("duplicate_content")
                already_seen = True
            else:
                seen_hashes.add(digest)
                already_seen = False
        if already_seen:
            _skip_message(phase, "duplicate_content", name)
            return None
        return path, base_url, content, phase, depth

    def complete_task(prepared, data, refs):
        """Parent-side post-analysis: source maps, merge, progress, discovery."""
        path, base_url, content, phase, depth = prepared
        name = os.path.basename(path) if path else "inline script"
        _expand_document_source_maps(data, content, source_url=base_url,
                                     cancel_check=cancel_check)
        with lock:
            results[path] = data
            state["path_to_url"][path] = base_url
            state["script_urls"].append(base_url)
        scan_progress(phase, f"Analyzed {name} ({len(results)}/{max_files})")
        return discover_tasks(refs, base_url, depth)

    def analyze_inline(prepared):
        """Thread-engine analysis of one prepared task (also the fallback)."""
        path, base_url, content, phase, depth = prepared
        data = _scan_document(path, content, source_url=base_url,
                              cancel_check=cancel_check,
                              progress_heartbeat=_task_heartbeat(content, phase, path))
        return complete_task(prepared, data, extract_script_refs(content))

    def merge_document(path, base_url, content, phase="analyze"):
        """Thread-safe merge used by non-BFS callers. Returns a skip reason."""
        reason = None
        if len((content or "").encode("utf-8", errors="ignore")) > FILE_RULES.get("max_js_size", 2_000_000):
            record_skip("oversized_script")
            return "oversized_script"
        digest = hashlib.md5((content or "").encode("utf-8", errors="ignore")).hexdigest()
        with lock:
            if digest in seen_hashes:
                state["skipped_files"] += 1
                state["skipped_reasons"].add("duplicate_content")
                reason = "duplicate_content"
            else:
                seen_hashes.add(digest)
        if reason:
            return reason
        data = _scan_document(path, content, source_url=base_url, cancel_check=cancel_check,
                              progress_heartbeat=_task_heartbeat(content, phase, path))
        with lock:
            results[path] = data
            state["path_to_url"][path] = base_url
            state["script_urls"].append(base_url)
        return None

    def discover_tasks(refs, base_url, depth):
        """Resolve discovered module refs into follow-up scan tasks.

        ``refs`` are the raw module/bundler references (extracted inside the
        worker when the process engine is active, where the parse is already
        cached); this parent-side half does the URL joining, dedupe and the
        chunk downloads.
        """
        if depth >= max_depth:
            return []
        new_tasks = []
        for ref in refs:
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
                state["expected_files"] = min(max_files, max(
                    int(state.get("expected_files", 0)), len(known_paths)))
                state["script_urls"].append(absolute_url)
            new_tasks.append((next_path, absolute_url, None, "recursive_scan", depth + 1))
            state["script_edges"].append({"from": base_url, "to": absolute_url, "kind": "module_reference", "depth": depth + 1})
        return new_tasks

    def process_task(task):
        """Thread-engine round worker: prepare, analyze in-process, discover."""
        prepared = prepare_task(task)
        if prepared is None:
            return []
        try:
            return analyze_inline(prepared) or []
        except ScanCancelled:
            raise
        except Exception:
            record_skip("worker_error")
            return []

    # Bounded-parallel BFS rounds. Each round scans current assets with a
    # worker pool, then hands discovered chunks to the next round.
    #
    # Engine: the per-document analysis is CPU-bound (tree-sitter parse +
    # Python AST walks), so by default it runs in a PROCESS pool -- the GIL
    # would otherwise serialize all workers onto one core. The parent keeps
    # every I/O duty: file reads, dedupe, chunk downloads, source-map
    # fetching and all progress reporting (worker heartbeats arrive via a
    # queue and are re-emitted here). SCRIPTSENTRY_ANALYZE_ENGINE=thread
    # opts back into the legacy in-process pool, and a broken process pool
    # (e.g. spawn restrictions) degrades to it automatically.
    current_round = initial_tasks
    pool = None
    heartbeat_queue = None
    if analyze_engine() != "thread":
        try:
            import multiprocessing as _mp

            _ctx = _mp.get_context("spawn")
            _manager = _ctx.Manager()
            heartbeat_queue = _manager.Queue()
            pool = ProcessPoolExecutor(max_workers=workers, mp_context=_ctx)
        except Exception:
            pool = None
            heartbeat_queue = None

    def _drain_heartbeats():
        if heartbeat_queue is None:
            return
        while True:
            try:
                phase, name, detail = heartbeat_queue.get_nowait()
            except Exception:
                break
            scan_progress(phase, f"Analyzing {name} - {detail}")

    def _shutdown_pool(force=False):
        nonlocal pool
        if pool is None:
            return
        try:
            pool.shutdown(wait=False, cancel_futures=True)
            if force:
                for proc in list(getattr(pool, "_processes", {}).values() or []):
                    with contextlib.suppress(Exception):
                        proc.terminate()
        except Exception:
            pass
        pool = None

    def run_round_via_processes(tasks):
        """One BFS round on the process pool; returns the next round's tasks."""
        next_round = []
        submitted = {}
        for task in tasks:
            prepared = prepare_task(task)  # may raise ScanCancelled
            if prepared is None:
                continue
            path, base_url, content, phase, depth = prepared
            try:
                future = pool.submit(_analyze_document_worker, path, content,
                                     base_url, heartbeat_queue, phase)
                submitted[future] = prepared
            except Exception:
                record_skip("worker_error")
        pending = set(submitted)
        while pending:
            try:
                _check_cancel(cancel_check)
            except ScanCancelled:
                _shutdown_pool(force=True)
                raise
            done, pending = wait(pending, timeout=0.5, return_when=FIRST_COMPLETED)
            _drain_heartbeats()
            for future in done:
                prepared = submitted[future]
                try:
                    data, refs = future.result()
                except ScanCancelled:
                    raise
                except Exception:
                    if isinstance(future.exception(), (BrokenProcessPool, PicklingError)):
                        # Pool is unusable -- analyze this document in-process
                        # and let the outer loop fall back to threads.
                        _shutdown_pool(force=True)
                        try:
                            next_round.extend(analyze_inline(prepared) or [])
                        except ScanCancelled:
                            raise
                        except Exception:
                            record_skip("worker_error")
                        continue
                    record_skip("worker_error")
                    continue
                try:
                    next_round.extend(complete_task(prepared, data, refs) or [])
                except ScanCancelled:
                    _shutdown_pool(force=True)
                    raise
                except Exception:
                    record_skip("worker_error")
        return next_round

    try:
        while current_round and len(results) < max_files:
            _check_cancel(cancel_check)
            next_round = []
            if pool is not None:
                try:
                    next_round = run_round_via_processes(current_round)
                except ScanCancelled:
                    raise
                except Exception:
                    # Any other pool-level failure: degrade to threads.
                    _shutdown_pool(force=True)
                    record_skip("worker_error")
            if pool is None:
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
    except BaseException:
        _shutdown_pool(force=True)
        raise
    _shutdown_pool(force=False)

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
        with contextlib.suppress(Exception):
            workspace_obj.cleanup()
    else:
        workspace = state.get("workspace")
        if workspace:
            with contextlib.suppress(Exception):
                shutil.rmtree(workspace, ignore_errors=True)
    return runtime_results
