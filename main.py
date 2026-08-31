#!/usr/bin/env python3
"""ScriptSentry command-line entry point.

The CLI and web server intentionally share ``core.analyzer_service``.  Keeping
one scan lifecycle prevents the CLI from silently having different discovery,
source-map, taint, runtime, or deduplication behavior than the dashboard.
"""
import argparse
import json
import os
import sys

from config import DEFAULT_PROFILE, REPORT_FORMATS, SCAN_MAX_WORKERS, SCAN_PROFILES
from core.analyzer_service import analyze_url
from core.reporter import (
    build_dashboard_payload,
    build_report_model,
    generate_csv_report,
    generate_html_report,
    generate_report,
    generate_sarif_report,
)
from ai.llm_engine import build_ai_summary

OUTPUT_DIR = "output"


def _save(path, content):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="" if path.endswith(".csv") else None) as handle:
        handle.write(content)


def save_json(results, ai_summary=None, metadata=None):
    payload = {
        "metadata": metadata or {},
        "results": {key: value for key, value in results.items() if not str(key).startswith("__")},
        "runtime_evidence": results.get("__runtime_evidence__"),
        "runtime_findings": results.get("__runtime_findings__", []),
        "report_model": build_report_model(results, ai_summary=ai_summary, metadata=metadata),
        "dashboard": build_dashboard_payload(results, ai_summary=ai_summary, metadata=metadata),
        "ai_summary": ai_summary or {},
    }
    path = os.path.join(OUTPUT_DIR, "report.json")
    _save(path, json.dumps(payload, indent=2, ensure_ascii=False, default=str))
    print(f"[+] JSON report saved: {path}")


def run(urls, max_depth=5, timeout=15, profile=DEFAULT_PROFILE, output_formats=None,
        ai_provider="disabled", model=None, ollama_url=None, max_workers=SCAN_MAX_WORKERS):
    """Analyze one or more URLs through the same service used by the dashboard."""
    if not urls:
        raise ValueError("At least one target URL is required")
    profile_cfg = SCAN_PROFILES.get(profile, SCAN_PROFILES[DEFAULT_PROFILE])
    results = {}
    for url in urls:
        print(f"[+] Analyzing {url}")
        current = analyze_url(
            url,
            max_depth=max_depth,
            timeout=timeout,
            max_files=profile_cfg["max_files"],
            max_workers=max_workers,
            progress_callback=lambda **event: print(
                f"    [{event.get('phase', 'scan')}] {event.get('message', '')}", flush=True
            ),
        )
        # Preserve global runtime/summary blocks from the last target and keep
        # each target's files distinct by URL-scoped artifact path.
        for key, value in current.items():
            if str(key).startswith("__"):
                results[key] = value
            else:
                results[f"{url} :: {key}"] = value

    metadata = {"mode": "url", "source": ", ".join(urls), "profile": profile}
    ai_summary = None
    if ai_provider != "disabled":
        files = {key: value for key, value in results.items() if not str(key).startswith("__")}
        ai_summary = build_ai_summary(
            files,
            provider=ai_provider,
            model=model,
            ollama_url=ollama_url,
        )

    formats = output_formats or ["all"]
    if "all" in formats or "txt" in formats:
        _save(os.path.join(OUTPUT_DIR, "report.txt"), generate_report(results, ai_summary=ai_summary, metadata=metadata))
    if "all" in formats or "json" in formats:
        save_json(results, ai_summary=ai_summary, metadata=metadata)
    if "all" in formats or "html" in formats:
        _save(os.path.join(OUTPUT_DIR, "report.html"), generate_html_report(results, ai_summary=ai_summary, metadata=metadata))
    if "all" in formats or "csv" in formats:
        _save(os.path.join(OUTPUT_DIR, "report.csv"), generate_csv_report(results, ai_summary=ai_summary, metadata=metadata))
    if "all" in formats or "sarif" in formats:
        _save(os.path.join(OUTPUT_DIR, "report.sarif"), generate_sarif_report(results, ai_summary=ai_summary, metadata=metadata))
    print(generate_report(results, ai_summary=ai_summary, metadata=metadata))
    return results


def build_parser():
    """Argument parser for the CLI (separated for tests)."""
    parser = argparse.ArgumentParser(description="Inventory and analyze JavaScript behavior and security signals")
    parser.add_argument("--serve", action="store_true", help="Launch the visual web dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Dashboard bind address (loopback by default)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    parser.add_argument("urls", nargs="*", help="One or more public http(s) target URLs")
    parser.add_argument("--max-depth", type=int, default=5)
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--workers", type=int, default=SCAN_MAX_WORKERS)
    parser.add_argument("--profile", choices=sorted(SCAN_PROFILES), default=DEFAULT_PROFILE)
    parser.add_argument("--format", choices=REPORT_FORMATS, default="all")
    parser.add_argument("--ai", choices=["disabled", "ollama"], default="disabled",
                        help="Executive summary mode. 'ollama' calls a LOCAL "
                             "Ollama server (code never leaves your machine) "
                             "and falls back to the built-in rule-based "
                             "summary when Ollama is offline. Cloud "
                             "providers are intentionally not supported: "
                             "sending scanned code to a third party would "
                             "break the privacy-first design.")
    parser.add_argument("--ollama-url", default="http://localhost:11434",
                        help="Local Ollama server base URL (used with --ai ollama)")
    parser.add_argument("--model", default=None,
                        help="Ollama model name for --ai ollama (default: llama3.2)")
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

    if not args.urls:
        parser.error("provide at least one URL or use --serve")
    run(
        args.urls,
        max_depth=max(1, min(args.max_depth, 10)),
        timeout=max(2, min(args.timeout, 60)),
        profile=args.profile,
        output_formats=[args.format] if args.format != "all" else ["all"],
        ai_provider=args.ai,
        model=args.model,
        ollama_url=args.ollama_url,
        max_workers=max(1, min(args.workers, 32)),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
