#!/usr/bin/env python3
"""ScriptSentry command-line entry point.

The CLI and web server intentionally share ``core.analyzer_service``.  Keeping
one scan lifecycle prevents the CLI from silently having different discovery,
source-map, taint, runtime, or deduplication behavior than the dashboard.

Targets may be public http(s) URLs *or* local paths: ``.js`` files and
directories (walked for JavaScript, skipping ``node_modules`` and VCS dirs).
Local targets go through the same ``analyze_files`` pipeline the dashboard
uses for uploads, so a CLI scan and a dashboard scan of the same code agree.

``--fail-on <severity>`` makes the process exit 1 when any *actionable*
finding (not an observation) is at or above that severity -- the hook CI
pipelines gate on. ``--output`` chooses the report directory.
"""
import argparse
import os
import sys

from config import DEFAULT_PROFILE, REPORT_FORMATS, SCAN_MAX_WORKERS, SCAN_PROFILES
from core.analyzer_service import analyze_files, analyze_url
from core.analysis_model import SEVERITY_RANK
from core.reporter import (
    generate_json_report,
    generate_csv_report,
    generate_html_report,
    generate_report,
    generate_sarif_report,
)
from ai.llm_engine import build_ai_summary

OUTPUT_DIR = "output"

# JavaScript-ish extensions collected when a directory target is given.
LOCAL_JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
# Directories never worth scanning: vendored code and tooling noise.
LOCAL_SKIP_DIRS = {"node_modules", ".git", ".hg", ".svn", "__pycache__", ".scriptsentry"}
# One build folder can hold thousands of chunks; beyond this the scan is
# almost certainly pointed at the wrong directory (node_modules is skipped,
# so a legit frontend build stays far under the cap).
LOCAL_MAX_FILES = 1000


def _save(path, content):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="" if path.endswith(".csv") else None) as handle:
        handle.write(content)


def save_openapi(results, metadata=None, output_dir=None):
    from core.reporter import generate_openapi_report
    path = os.path.join(output_dir or OUTPUT_DIR, "api-surface.openapi.json")
    _save(path, generate_openapi_report(results, metadata=metadata))
    print(f"  OpenAPI surface: {path}")


def save_json(results, ai_summary=None, metadata=None, output_dir=None):
    # generate_json_report returns the serialized JSON document itself.
    # json.dumps()-ing it again would double-encode the report on disk
    # (a JSON string containing JSON) -- the report file must be the
    # document, directly loadable.
    content = generate_json_report(results, ai_summary=ai_summary, metadata=metadata)
    path = os.path.join(output_dir or OUTPUT_DIR, "report.json")
    _save(path, content)
    print(f"[+] JSON report saved: {path}")


def is_url(target):
    return str(target).startswith(("http://", "https://"))


def collect_local_files(paths, max_files=LOCAL_MAX_FILES):
    """Expand local targets into ``{"filename", "code"}`` documents.

    A path may be a single file or a directory (walked for JavaScript-ish
    extensions, skipping vendored and VCS directories). Returns the document
    list plus the list of *rejected* paths (missing or unreadable) so the
    caller can fail loudly instead of silently scanning nothing.
    """
    files = []
    errors = []
    for raw in paths:
        path = os.path.abspath(os.path.expanduser(str(raw)))
        if os.path.isfile(path):
            candidates = [path]
            base_dir = os.path.dirname(path)
        elif os.path.isdir(path):
            candidates = []
            base_dir = path
            for root, dirs, names in os.walk(path):
                dirs[:] = sorted(d for d in dirs if d not in LOCAL_SKIP_DIRS)
                for name in sorted(names):
                    if os.path.splitext(name)[1].lower() in LOCAL_JS_EXTENSIONS:
                        candidates.append(os.path.join(root, name))
                if len(candidates) >= max_files:
                    break
            if not candidates:
                errors.append(f"{raw}: no JavaScript files found under this directory")
                continue
        else:
            errors.append(f"{raw}: no such file or directory")
            continue
        for candidate in candidates[: max(0, max_files - len(files))]:
            try:
                with open(candidate, encoding="utf-8", errors="replace") as handle:
                    code = handle.read()
            except OSError as exc:
                errors.append(f"{candidate}: cannot read ({exc.strerror or exc})")
                continue
            if not code.strip():
                continue
            # Report names relative to the target they came from, so a file
            # target shows "app.js" and a directory target shows "src/a.js".
            files.append({"filename": os.path.relpath(candidate, base_dir), "code": code})
        if len(files) >= max_files:
            print(f"[!] Local file cap reached ({max_files}); later targets skipped.", file=sys.stderr)
            break
    return files, errors


def worst_actionable_severity(results):
    """(rank, count) of the worst non-observation finding across all files.

    Observations (informational behavioural notes) never fail a build: only
    findings a human must triage do.
    """
    worst_rank, count = -1, 0
    for value in results.values():
        if not isinstance(value, dict):
            continue
        for finding in value.get("findings") or []:
            if not isinstance(finding, dict) or finding.get("observation"):
                continue
            rank = SEVERITY_RANK.get(str(finding.get("severity", "")).upper(), -1)
            if rank < 0:
                continue
            if rank > worst_rank:
                worst_rank, count = rank, 1
            elif rank == worst_rank:
                count += 1
    return worst_rank, count


def run(targets, max_depth=5, timeout=15, profile=DEFAULT_PROFILE, output_formats=None,
        ai_provider="disabled", model=None, ollama_url=None, openai_base_url=None,
        api_key=None, max_workers=SCAN_MAX_WORKERS, output_dir=None, progress=lambda **e: None):
    """Analyze URLs and/or local paths; write reports; return the results.

    ``output_dir`` defaults to ``output``. Returns the merged results dict
    (consumed by tests and by ``--fail-on`` in :func:`main`).
    """
    targets = [t for t in (targets or []) if str(t).strip()]
    if not targets:
        raise ValueError("At least one target (URL or local path) is required")
    out = output_dir or OUTPUT_DIR
    profile_cfg = SCAN_PROFILES.get(profile, SCAN_PROFILES[DEFAULT_PROFILE])
    urls = [t for t in targets if is_url(t)]
    local_paths = [t for t in targets if not is_url(t)]

    results = {}
    target_errors = []

    if local_paths:
        files, errors = collect_local_files(local_paths)
        for error in errors:
            print(f"[!] {error}", file=sys.stderr)
        target_errors.extend(errors)
        if not files and not urls:
            raise ValueError("No readable local JavaScript files in the given target(s)")
        if files:
            print(f"[+] Analyzing {len(files)} local file(s)")
            current = analyze_files(files, progress_callback=progress, trusted_names=True)
            for key, value in current.items():
                if str(key).startswith("__"):
                    results[key] = value
                else:
                    results[key] = value
            if urls:
                print("[+] Analyzing URL target(s) too; local results kept")

    for url in urls:
        print(f"[+] Analyzing {url}")
        try:
            current = analyze_url(
                url,
                max_depth=max_depth,
                timeout=timeout,
                max_files=profile_cfg["max_files"],
                max_workers=max_workers,
                progress_callback=progress,
            )
        except Exception as exc:  # noqa: BLE001 - one dead URL must not kill the scan
            print(f"[!] Target failed: {url} ({exc})", file=sys.stderr)
            target_errors.append(f"{url}: {exc}")
            continue
        # Preserve global runtime/summary blocks from the last target and keep
        # each target's files distinct by URL-scoped artifact path.
        for key, value in current.items():
            if str(key).startswith("__"):
                results[key] = value
            else:
                results[f"{url} :: {key}"] = value

    if target_errors and not any(True for k in results if not str(k).startswith("__")):
        raise ValueError("Every target failed: " + "; ".join(target_errors[:3]))

    mode = "url" if urls and not local_paths else ("files" if local_paths and not urls else "mixed")
    metadata = {"mode": mode, "source": ", ".join(str(t) for t in targets), "profile": profile}
    ai_summary = None
    if ai_provider != "disabled":
        files = {key: value for key, value in results.items() if not str(key).startswith("__")}
        ai_summary = build_ai_summary(
            files,
            provider=ai_provider,
            model=model,
            ollama_url=ollama_url,
            openai_base_url=openai_base_url,
            api_key=api_key,
        )

    formats = output_formats or ["all"]
    if "all" in formats or "txt" in formats:
        _save(os.path.join(out, "report.txt"), generate_report(results, ai_summary=ai_summary, metadata=metadata))
    if "all" in formats or "json" in formats:
        save_json(results, ai_summary=ai_summary, metadata=metadata, output_dir=out)
    if "all" in formats or "openapi" in formats:
        save_openapi(results, metadata=metadata, output_dir=out)
    if "all" in formats or "html" in formats:
        _save(os.path.join(out, "report.html"), generate_html_report(results, ai_summary=ai_summary, metadata=metadata))
    if "all" in formats or "csv" in formats:
        _save(os.path.join(out, "report.csv"), generate_csv_report(results, ai_summary=ai_summary, metadata=metadata))
    if "all" in formats or "sarif" in formats:
        _save(os.path.join(out, "report.sarif"), generate_sarif_report(results, ai_summary=ai_summary, metadata=metadata))
    print(generate_report(results, ai_summary=ai_summary, metadata=metadata))
    return results


def build_parser():
    """Argument parser for the CLI (separated for tests)."""
    parser = argparse.ArgumentParser(
        description="Inventory and analyze JavaScript behavior and security signals",
        epilog="Targets may be public http(s) URLs or local .js files/directories. "
               "Examples: main.py https://example.com | main.py ./dist bundle.js --fail-on high")
    parser.add_argument("--serve", action="store_true", help="Launch the visual web dashboard")
    parser.add_argument("--host", default=os.environ.get("SCRIPTSENTRY_HOST", "127.0.0.1"),
                        help="Dashboard bind address (loopback by default)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    parser.add_argument("targets", nargs="*",
                        help="Public http(s) target URLs and/or local .js files or directories")
    parser.add_argument("--max-depth", type=int, default=5)
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--workers", type=int, default=SCAN_MAX_WORKERS)
    parser.add_argument("--profile", choices=sorted(SCAN_PROFILES), default=DEFAULT_PROFILE)
    parser.add_argument("--format", choices=list(REPORT_FORMATS) + ["all"], default="all", nargs="+", metavar="FMT",
                        help="Report format(s) to write: txt json html csv sarif openapi, or 'all' "
                             "(repeat or space-separate for several: --format sarif txt)")
    parser.add_argument("--output", default=OUTPUT_DIR, metavar="DIR",
                        help=f"Directory for report files (default: {OUTPUT_DIR}/)")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"], default="none",
                        help="Exit with code 1 when any actionable finding (observations excluded) "
                             "is at or above this severity. 'none' (the default) always exits 0 -- "
                             "the hook CI pipelines gate on.")
    parser.add_argument("--ai", choices=["disabled", "ollama", "openai"], default="disabled",
                        help="Executive summary mode. 'ollama'/'openai' call LOCAL "
                             "model servers (code never leaves your machine): "
                             "Ollama, or any OpenAI-compatible server such as LM "
                             "Studio or llama.cpp. Falls back to the built-in "
                             "rule-based summary when the server is offline. "
                             "Hosted cloud providers remain unsupported on "
                             "purpose: sending scanned code to a third party "
                             "would break the privacy-first design.")
    parser.add_argument("--ollama-url", default="http://localhost:11434",
                        help="Local Ollama server base URL (used with --ai ollama)")
    parser.add_argument("--openai-base-url", default=None,
                        help="OpenAI-compatible LOCAL server base URL for --ai openai "
                             "(default: http://localhost:1234/v1, i.e. LM Studio)")
    parser.add_argument("--api-key", default=None,
                        help="Optional bearer token for --ai openai servers that require one")
    parser.add_argument("--model", default=None,
                        help="Model name for --ai ollama/--ai openai (default: llama3.2)")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.serve:
        import server
        srv = server.make_server(host=args.host, port=args.port)
        print(f"ScriptSentry dashboard listening on http://{args.host}:{args.port}")
        print(f"Engine pairing token: {server.API_TOKEN}")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down.")
        finally:
            srv.server_close()
        return 0

    if not args.targets:
        parser.error("provide at least one target (URL or local path) or use --serve")
    try:
        results = run(
            args.targets,
            max_depth=max(1, min(args.max_depth, 10)),
            timeout=max(2, min(args.timeout, 60)),
            profile=args.profile,
            output_formats=["all"] if "all" in args.format else list(args.format),
            ai_provider=args.ai,
            model=args.model,
            ollama_url=args.ollama_url,
            openai_base_url=args.openai_base_url,
            api_key=args.api_key,
            max_workers=max(1, min(args.workers, 32)),
            output_dir=args.output,
            progress=lambda **event: print(
                f"    [{event.get('phase', 'scan')}] {event.get('message', '')}", flush=True
            ),
        )
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    if args.fail_on != "none":
        threshold = SEVERITY_RANK[args.fail_on.upper()]
        worst_rank, count = worst_actionable_severity(results)
        if worst_rank >= threshold and count > 0:
            severity_name = next(name for name, rank in SEVERITY_RANK.items() if rank == worst_rank)
            print(f"[!] FAIL: {count} actionable finding(s) at {severity_name} "
                  f"(threshold: {args.fail_on.upper()})", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
