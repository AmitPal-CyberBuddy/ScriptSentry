#!/usr/bin/env python3
"""ScriptSentry Web dashboard.

Run:
    python3 server.py

The secure default binds only to loopback.  Use ``--host 0.0.0.0`` only when a
reverse proxy or a development preview explicitly requires network exposure.

Maintainability note
--------------------
This file intentionally stays dependency-free (stdlib only) so the local engine
is trivial to run. It currently folds together static-UI serving, CORS,
pairing-token auth, API routing, report generation, async-job handling and
request validation. That is acceptable at the current size, but the planned
decomposition (when the surface grows further) is a small ``api/`` package::

    api/auth.py      pairing token, origin checks, hmac comparison
    api/cors.py      allow/origin handling
    api/handlers.py  request dispatch + body/URL validation
    api/analysis_routes.py  /api/analyze, /api/status, /api/result, /api/cancel
    api/report_routes.py    /api/report (txt/html/csv/sarif)

keeping ``server.py`` as the thin loopback server/bootstrap. The handlers are
already factored into discrete methods to make that split mechanical.
"""
import argparse
import hmac
import json
import os
import secrets
import threading
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from config import DEFAULT_PROFILE, SCAN_MAX_WORKERS, SCAN_PROFILES
from core.analyzer_service import analyze_content, analyze_files, analyze_url
from core.jobs import jobs
from core.js_parser import parser_status
from core.runtime_evidence import playwright_available, runtime_evidence_enabled
from core.url_policy import validate_public_url
from core.version import ENGINE_NAME, RELEASE_STATUS, __version__ as ENGINE_VERSION, is_dev_build
from core.reporter import (
    build_dashboard_payload,
    generate_csv_report,
    generate_html_report,
    generate_report,
    generate_sarif_report,
)

WEB_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "webui")
MAX_BODY = 16 * 1024 * 1024  # 16 MB (local, authenticated; uploads included)
MAX_URL_LENGTH = 2048
MAX_UPLOAD_FILES = 20
MAX_FILE_BYTES = 3 * 1024 * 1024  # per uploaded document
ALLOWED_UPLOAD_EXT = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".map", ".json", ".txt")
# A pairing token is deliberately process-scoped.  It is printed once at
# startup and never returned by health or included in a report response.
API_TOKEN = os.environ.get("SCRIPTSENTRY_API_TOKEN", "").strip() or secrets.token_urlsafe(32)


class DashboardHandler(SimpleHTTPRequestHandler):
    """Serves the single-page dashboard and answers analysis requests."""

    server_version = f"ScriptSentryDashboard/{ENGINE_VERSION}"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_ROOT, **kwargs)

    def log_message(self, fmt, *args):
        print(f"[webui] {self.address_string()} {fmt % args}", flush=True)

    def end_headers(self):
        # These headers apply to static UI responses as well as API responses.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=()")
        super().end_headers()

    def _send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        origin = self.headers.get("Origin", "")
        if origin and self._is_allowed_origin(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Private-Network", "true")
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, message, status=400):
        self._send_json({"ok": False, "error": message}, status=status)

    def _send_cors_headers(self):
        origin = self.headers.get("Origin", "")
        if origin and self._is_allowed_origin(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Private-Network", "true")

    @staticmethod
    def _is_allowed_origin(origin):
        """Check an exact browser origin; never use a prefix allowlist."""
        if not origin:
            return True
        if origin.lower() in ("null", "file://"):
            return True
        try:
            parsed = urlparse(origin)
            scheme = (parsed.scheme or "").lower()
            host = (parsed.hostname or "").lower().rstrip(".")
        except Exception:
            return False
        if scheme == "http" and host in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}:
            return True
        if scheme == "https" and host in {"127.0.0.1", "::1"}:
            return True
        # GitHub Pages is a deployment surface, not an authentication boundary:
        # it is allowed for CORS but still requires the pairing token below.
        if scheme == "https" and host.endswith(".github.io") and host != "github.io":
            return True
        configured = {
            value.strip().lower().rstrip("/")
            for value in os.environ.get("SCRIPTSENTRY_ALLOWED_ORIGINS", "").split(",")
            if value.strip()
        }
        return origin.lower().rstrip("/") in configured

    def _reject_untrusted_origin(self):
        origin = self.headers.get("Origin", "")
        if origin and not self._is_allowed_origin(origin):
            self._send_error_json("Origin not allowed by the local engine", 403)
            return True
        return False

    def _require_api_auth(self):
        presented = self.headers.get("X-ScriptSentry-Token", "")
        if not presented or not hmac.compare_digest(str(presented), API_TOKEN):
            self._send_error_json("Engine pairing token required", 401)
            return False
        return True

    def do_OPTIONS(self):
        if self._reject_untrusted_origin():
            return
        self.send_response(204)
        origin = self.headers.get("Origin", "")
        if origin and self._is_allowed_origin(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-ScriptSentry-Token")
        self.send_header("Access-Control-Max-Age", "300")
        self.end_headers()

    @staticmethod
    def _bounded_int(value, default, lower, upper):
        try:
            return max(lower, min(int(value), upper))
        except (TypeError, ValueError):
            return default

    def _query_param(self, parsed, key, default=""):
        if not parsed.query:
            return default
        import urllib.parse as _up
        values = dict(_up.parse_qsl(parsed.query))
        return values.get(key, default)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            if self._reject_untrusted_origin():
                return
            if parsed.path == "/api/health":
                self._send_json({
                    "ok": True,
                    "engine": ENGINE_NAME,
                    "version": ENGINE_VERSION,
                    "release_status": RELEASE_STATUS,
                    "dev_build": is_dev_build(),
                    "privacy": "local-only",
                    "auth_required": True,
                    "pairing": "Set X-ScriptSentry-Token to use analysis endpoints.",
                    "runtime_evidence": {
                        "enabled": runtime_evidence_enabled(),
                        "playwright": playwright_available(),
                    },
                    "ast_parser": parser_status(),
                })
                return
            if not self._require_api_auth():
                return
            if parsed.path == "/api/status":
                job_id = self._query_param(parsed, "job_id", "")
                status = jobs.status(job_id)
                if status is None:
                    self._send_error_json("Unknown job_id", 404)
                    return
                self._send_json({"ok": True, "job": status})
                return
            if parsed.path == "/api/result":
                job_id = self._query_param(parsed, "job_id", "")
                job = jobs.get(job_id)
                if job is None:
                    self._send_error_json("Unknown job_id", 404)
                    return
                if job.status != "done":
                    self._send_json({"ok": True, "job": job.snapshot(), "ready": False})
                    return
                raw = jobs.result(job_id)
                payload = self._payload(raw, metadata={"mode": job.mode, "source": job.source})
                self._send_json({"ok": True, "job": job.snapshot(), "ready": True, "payload": payload})
                return
            self._send_error_json("Not found", 404)
            return
        # Browsers probe /favicon.ico regardless of the <link rel="icon"> tag;
        # point it at the real brand asset instead of logging a 404.
        if parsed.path in ("/favicon.ico", "/favicon.png"):
            self.send_response(302)
            self.send_header("Location", "/assets/favicon.svg")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        # The dashboard is three pages: `home/index.html` (landing/overview),
        # `tool/index.html` (the analysis console) and `changelog/index.html`
        # (generated from CHANGELOG.md).  GitHub Pages serves the landing page
        # at `/home/`, but a local engine is almost always launched to *use* the
        # tool, so loopback visitors land straight on the console.
        if parsed.path == "/":
            self.path = "/tool/index.html"
        return super().do_GET()

    def send_error(self, code, message=None, explain=None):
        """Serve the site's own 404 page instead of Python's default.

        GitHub Pages already serves ``webui/404.html`` for a missing address,
        so the hosted site recovers a lost visitor with real navigation. The
        local server fell through to http.server's built-in "Error response"
        page, which is a dead end with no way back into the dashboard -- the
        same URL behaved completely differently depending on where the site
        was served from.
        """
        if code == 404:
            page = os.path.join(WEB_ROOT, "404.html")
            if os.path.isfile(page):
                try:
                    with open(page, "rb") as fh:
                        body = fh.read()
                except OSError:
                    body = None
                if body is not None:
                    self.send_response(404, message)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    # HEAD must not carry a body.
                    if self.command != "HEAD":
                        self.wfile.write(body)
                    return
        return super().send_error(code, message, explain)

    def list_directory(self, path):
        """Directories without an index page are 404, not a file listing.

        The static site is three pages plus assets; a directory listing would
        leak filenames and looks like an unfinished feature.  Only paths with
        an ``index.html`` (home/, tool/, changelog/) are served.
        """
        self.send_error(404, "Not found")
        return None

    def _read_json_body(self):
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type not in ("", "application/json"):
            self._send_error_json("Content-Type must be application/json", 415)
            return None
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            self._send_error_json("Invalid request size", 400)
            return None
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception as exc:
            self._send_error_json(f"Invalid JSON: {exc}", 400)
            return None
        if not isinstance(body, dict):
            self._send_error_json("Payload must be a JSON object", 400)
            return None
        return body

    def do_POST(self):
        parsed = urlparse(self.path)
        if self._reject_untrusted_origin():
            return
        if parsed.path.startswith("/api/") and not self._require_api_auth():
            return
        body = self._read_json_body()
        if body is None:
            return
        if parsed.path == "/api/cancel":
            job_id = str(body.get("job_id", "")).strip()
            job = jobs.get(job_id)
            if job is None:
                self._send_error_json("Unknown job_id", 404)
                return
            if job.status in ("done", "error", "canceled"):
                self._send_json({"ok": True, "job": job.snapshot()})
                return
            jobs.cancel(job_id)
            self._send_json({"ok": True, "job": job.snapshot()})
            return
        if parsed.path == "/api/report":
            self._handle_report(parsed, body)
            return
        if parsed.path != "/api/analyze":
            self._send_error_json("Unknown endpoint", 404)
            return

        mode = str(body.get("mode", "code")).strip().lower()
        if mode not in ("url", "code"):
            self._send_error_json("mode must be 'code' or 'url'", 400)
            return
        self._handle_async_analysis(body, mode)

    def _handle_report(self, parsed, body):
        report_format = ""
        query = {}
        if parsed.query:
            for part in parsed.query.split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    query[k] = v
        report_format = query.get("format", "html").lower()
        if report_format not in {"html", "txt", "csv", "sarif"}:
            self._send_error_json("format must be html, txt, csv, or sarif", 400)
            return
        try:
            job_id = str(body.get("job_id", "")).strip()
            if job_id:
                job = jobs.get(job_id)
                if job is None:
                    self._send_error_json("Unknown job_id", 404)
                    return
                if job.status == "done":
                    results = jobs.result(job_id) or {}
                elif job.status in ("queued", "running"):
                    self._send_error_json("Analysis is still running; wait for completion before exporting.", 409)
                    return
                else:
                    self._send_error_json(job.error or "Analysis failed.", 500)
                    return
            else:
                results = self._run_analysis(body)
        except Exception as exc:
            self._send_error_json(f"Analysis failed: {exc}", 500)
            return

        source = str(body.get("url", body.get("filename", "")))
        if not source and isinstance(body.get("files"), list) and body["files"]:
            source = f"{len(body['files'])} uploaded file(s)"
        metadata = {"mode": str(body.get("mode", "code")), "source": source}
        if report_format == "txt":
            text = generate_report(results, metadata=metadata)
            data = text.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=scriptsentry-report.txt")
            self.send_header("Content-Length", str(len(data)))
            self._send_cors_headers()
            self.send_header("Access-Control-Allow-Private-Network", "true")
            self.end_headers()
            self.wfile.write(data)
            return

        if report_format == "csv":
            text = generate_csv_report(results, metadata=metadata)
            data = text.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=scriptsentry-report.csv")
            self.send_header("Content-Length", str(len(data)))
            self._send_cors_headers()
            self.send_header("Access-Control-Allow-Private-Network", "true")
            self.end_headers()
            self.wfile.write(data)
            return

        if report_format == "sarif":
            text = generate_sarif_report(results, metadata=metadata)
            data = text.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/sarif+json; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=scriptsentry-report.sarif")
            self.send_header("Content-Length", str(len(data)))
            self._send_cors_headers()
            self.send_header("Access-Control-Allow-Private-Network", "true")
            self.end_headers()
            self.wfile.write(data)
            return

        html = generate_html_report(results, metadata=metadata)
        data = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Disposition", "attachment; filename=scriptsentry-report.html")
        self.send_header("Content-Length", str(len(data)))
        self._send_cors_headers()
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.end_headers()
        self.wfile.write(data)

    @staticmethod
    def _extract_uploads(body):
        """Validate the optional local file-upload list (read in the browser).

        Returns a list of {"filename", "code"} or raises ValueError. Files are
        supplied as text by the hosted/local UI and analyzed entirely by the
        local engine; nothing is sent to a cloud.
        """
        files = body.get("files")
        if files is None:
            return None
        if not isinstance(files, list) or not files:
            raise ValueError("No files were provided")
        if len(files) > MAX_UPLOAD_FILES:
            raise ValueError(f"Too many files (limit {MAX_UPLOAD_FILES})")
        cleaned = []
        for item in files:
            if not isinstance(item, dict):
                continue
            code = item.get("code")
            if not isinstance(code, str) or not code.strip():
                continue
            name = str(item.get("filename", "")).strip()
            if len(code.encode("utf-8", errors="ignore")) > MAX_FILE_BYTES:
                raise ValueError(f"File {name or '(unnamed)'} exceeds the {MAX_FILE_BYTES // (1024*1024)}-MB per-file limit")
            # Keep a JS-ish extension; unknown uploads are still analyzed as JS.
            if name and not name.lower().endswith(ALLOWED_UPLOAD_EXT):
                raise ValueError(f"Unsupported file type: {name}")
            cleaned.append({"filename": name or f"upload-{len(cleaned)+1}.js", "code": code})
        if not cleaned:
            raise ValueError("Uploaded files were empty")
        return cleaned

    def _run_analysis(self, body):
        mode = str(body.get("mode", "code")).strip().lower()
        if mode == "url":
            url = str(body.get("url", "")).strip()
            if len(url) > MAX_URL_LENGTH or not url.startswith(("http://", "https://")):
                raise ValueError("Enter a valid http(s) URL")
            if not os.environ.get("SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS"):
                valid, reason = validate_public_url(url)
                if not valid:
                    raise ValueError(reason)
            profile = str(body.get("profile", DEFAULT_PROFILE)).strip()
            profile_cfg = SCAN_PROFILES.get(profile, SCAN_PROFILES[DEFAULT_PROFILE])
            max_depth = self._bounded_int(body.get("max_depth", profile_cfg["max_depth"]), profile_cfg["max_depth"], 1, 10)
            timeout = self._bounded_int(body.get("timeout", profile_cfg["timeout"]), profile_cfg["timeout"], 2, 60)
            max_files = self._bounded_int(body.get("max_files", profile_cfg["max_files"]), profile_cfg["max_files"], 1, 1000)
            max_workers = self._bounded_int(body.get("max_workers", SCAN_MAX_WORKERS), SCAN_MAX_WORKERS, 1, 32)
            return analyze_url(
                url, max_depth=max_depth, timeout=timeout,
                max_files=max_files, max_workers=max_workers,
            )
        uploads = self._extract_uploads(body)
        if uploads:
            return analyze_files(uploads)
        code = body.get("code")
        if not isinstance(code, str) or not code.strip():
            raise ValueError("Paste some JavaScript to analyze")
        filename = str(body.get("filename", "inline.js")).strip() or "inline.js"
        return analyze_content(code, filename=filename)

    def _handle_async_analysis(self, body, mode):
        if mode == "url":
            url = str(body.get("url", "")).strip()
            if len(url) > MAX_URL_LENGTH or not url.startswith(("http://", "https://")):
                self._send_error_json("Enter a valid http(s) URL", 400)
                return
            if not os.environ.get("SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS"):
                valid, reason = validate_public_url(url)
                if not valid:
                    self._send_error_json(reason, 400)
                    return
            profile = str(body.get("profile", DEFAULT_PROFILE)).strip()
            profile_cfg = SCAN_PROFILES.get(profile, SCAN_PROFILES[DEFAULT_PROFILE])
            max_depth = self._bounded_int(body.get("max_depth", profile_cfg["max_depth"]), profile_cfg["max_depth"], 1, 10)
            timeout = self._bounded_int(body.get("timeout", profile_cfg["timeout"]), profile_cfg["timeout"], 2, 60)
            max_files = self._bounded_int(body.get("max_files", profile_cfg["max_files"]), profile_cfg["max_files"], 1, 1000)
            max_workers = self._bounded_int(body.get("max_workers", SCAN_MAX_WORKERS), SCAN_MAX_WORKERS, 1, 32)
            try:
                job = jobs.create(
                    mode="url", source=url, profile=profile,
                    max_files=max_files, max_depth=max_depth, timeout=timeout,
                )
            except RuntimeError as exc:
                self._send_error_json(str(exc), 429)
                return
            jobs.start(
                job.id,
                analyze_url,
                url,
                max_depth=max_depth,
                timeout=timeout,
                max_files=max_files,
                max_workers=max_workers,
                progress_callback=lambda **kw: job.update(**kw),
                cancel_check=job.cancel_event.is_set,
            )
        else:
            try:
                uploads = self._extract_uploads(body)
            except ValueError as exc:
                uploads = None
                upload_error = str(exc)
            else:
                upload_error = ""
            if uploads:
                try:
                    job = jobs.create(mode="code", source=f"{len(uploads)} file(s)", max_files=len(uploads))
                except RuntimeError as exc:
                    self._send_error_json(str(exc), 429)
                    return
                jobs.start(
                    job.id,
                    analyze_files,
                    uploads,
                    progress_callback=lambda **kw: job.update(**kw),
                    cancel_check=job.cancel_event.is_set,
                )
            else:
                code = body.get("code")
                if not isinstance(code, str) or not code.strip():
                    self._send_error_json(upload_error or "Paste some JavaScript to analyze", 400)
                    return
                if len(code.encode("utf-8", errors="ignore")) > MAX_FILE_BYTES:
                    self._send_error_json(f"JavaScript input is limited to {MAX_FILE_BYTES // (1024*1024)} MB", 413)
                    return
                filename = str(body.get("filename", "inline.js")).strip() or "inline.js"
                filename = filename.replace("\\x00", "")[:240]
                try:
                    job = jobs.create(mode="code", source=filename, max_files=1)
                except RuntimeError as exc:
                    self._send_error_json(str(exc), 429)
                    return
                jobs.start(
                    job.id,
                    analyze_content,
                    code,
                    filename=filename,
                    progress_callback=lambda **kw: job.update(**kw),
                    cancel_check=job.cancel_event.is_set,
                )

        self._send_json({"ok": True, "job_id": job.id, "job": job.snapshot()})

    @staticmethod
    def _payload(results, metadata=None):
        meta = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        if metadata:
            meta.update(metadata)
        return build_dashboard_payload(results, metadata=meta)


def make_server(host="127.0.0.1", port=8000):
    handler = DashboardHandler
    return ThreadingHTTPServer((host, port), handler)


def main():
    parser = argparse.ArgumentParser(description="ScriptSentry Web dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
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
