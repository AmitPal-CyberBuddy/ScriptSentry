#!/usr/bin/env python3
"""ScriptSentry Web dashboard -- thin loopback bootstrap.

Run:
    python3 server.py

The secure default binds only to loopback.  Use ``--host 0.0.0.0`` only when a
reverse proxy or a development preview explicitly requires network exposure.

The request handling itself lives in the :mod:`api` package:

    api/settings.py         process settings: web root, limits, pairing token
    api/auth.py             pairing token + origin-trust checks
    api/cors.py             CORS headers + OPTIONS preflight
    api/http.py             stdlib handler base (JSON, bodies, static serving)
    api/analysis_routes.py  /api/health, /api/status, /api/result,
                            /api/history*, /api/cancel, /api/analyze
    api/report_routes.py    /api/report (txt/html/csv/sarif/json/openapi)
    api/handlers.py         the assembled DashboardHandler + dispatch

This module keeps the embedder contract of the old monolith: ``make_server``,
``main``, ``DashboardHandler``, ``API_TOKEN``, ``WEB_ROOT`` and ``jobs`` are
still importable from here, and ``python -m server``/``python server.py``
behave exactly as before.
"""
import argparse

from api import DashboardHandler, API_TOKEN, WEB_ROOT  # noqa: F401  (embedder contract)
from api.settings import (  # noqa: F401  (embedder contract)
    MAX_BODY,
    MAX_FILE_BYTES,
    MAX_UPLOAD_FILES,
    MAX_URL_LENGTH,
    ALLOWED_UPLOAD_EXT,
)
from core.jobs import jobs  # noqa: F401  (embedder contract)
from core.js_parser import parser_status
from core.version import is_dev_build
from http.server import ThreadingHTTPServer


def make_server(host="127.0.0.1", port=8000):
    handler = DashboardHandler
    return ThreadingHTTPServer((host, port), handler)


def main():
    parser = argparse.ArgumentParser(description="ScriptSentry Web dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(__import__("os").environ.get("PORT", "8000")))
    args = parser.parse_args()

    server = make_server(args.host, args.port)
    print(f"ScriptSentry dashboard listening on http://{args.host}:{args.port}", flush=True)
    if is_dev_build():
        print("⚠  UNDER DEVELOPMENT — pre-release build (not a published/stable release).", flush=True)
    print(f"Engine pairing token: {API_TOKEN}", flush=True)
    status = parser_status()
    if status.get("available"):
        print(f"AST parser: {status['name']} (full source-to-sink analysis)", flush=True)
    else:
        # Silent degradation was the bug: scans quietly ran in fallback mode.
        # Name the concrete cost so this is not mistaken for a minor notice.
        print(
            f"AST parser: UNAVAILABLE — running in {status.get('mode', 'regex_fallback')} mode. "
            "Source-to-sink flows will be capped at 'medium' confidence and some will be missed. "
            f"Install it for full analysis: {status.get('install_hint', 'pip install esprima')}",
            flush=True,
        )
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: non-loopback binding; protect the port with a firewall/reverse proxy.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.", flush=True)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
