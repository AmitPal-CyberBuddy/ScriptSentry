#!/usr/bin/env python3
"""ScriptSentry Web dashboard.

Run:
    python3 server.py

Then open the printed preview URL. The server binds 0.0.0.0 so it is reachable
from the Arena live preview environment.
"""
import argparse
import json
import os
import sys
import threading
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from config import ALLOWED_ORIGINS, DEFAULT_PROFILE, SCAN_PROFILES
from core.analyzer_service import analyze_content, analyze_url
from core.jobs import jobs
from core.runtime_evidence import playwright_available, runtime_evidence_enabled
from core.reporter import (
    build_dashboard_payload,
    generate_csv_report,
    generate_html_report,
    generate_report,
    generate_sarif_report,
)

WEB_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "webui")
MAX_BODY = 4 * 1024 * 1024  # 4 MB


class DashboardHandler(SimpleHTTPRequestHandler):
    """Serves the single-page dashboard and answers analysis requests."""

    server_version = "ScriptSentryDashboard/2.0"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_ROOT, **kwargs)

    def log_message(self, fmt, *args):
        print(f"[webui] {self.address_string()} {fmt % args}", flush=True)

    def _send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, message, status=400):
        self._send_json({"ok": False, "error": message}, status=status)

    @staticmethod
    def _is_allowed_origin(origin):
        if not origin or origin in ("null", "file://"):
            return True
        low = origin.lower()
        if low.startswith("http://localhost:") or low == "http://localhost":
            return True
        if low.startswith("http://127.0.0.1:") or low == "http://127.0.0.1":
            return True
        if low.startswith("https://127.0.0.1:") or low.startswith("http://0.0.0.0:"):
            return True
        try:
            host = urlparse(low).hostname or ""
        except Exception:
            host = ""
        if host == "github.io" or host.endswith(".github.io"):
            return True
        # Allow a small deployment override for custom hosted domains.
        for extra in os.environ.get("SCRIPTSENTRY_ALLOWED_ORIGINS", "").split(","):
            extra = extra.strip().lower()
            if extra and (low == extra or low.startswith(extra + ":")):
                return True
        return False

    def _reject_untrusted_origin(self):
        origin = self.headers.get("Origin", "")
        if origin and not self._is_allowed_origin(origin):
            self._send_error_json("Origin not allowed by the local engine", 403)
            return True
        return False

    def do_OPTIONS(self):
        if self._reject_untrusted_origin():
            return
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.end_headers()

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
                    "engine": "ScriptSentry Analyzer",
                    "version": "2.0",
                    "privacy": "local-only",
                    "runtime_evidence": {
                        "enabled": runtime_evidence_enabled(),
                        "playwright": playwright_available(),
                    },
                })
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
        if parsed.path == "/":
            self.path = "/index.html"
        return super().do_GET()

    def _read_json_body(self):
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
        body = self._read_json_body()
        if body is None:
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

        metadata = {"mode": str(body.get("mode", "code")), "source": str(body.get("url", body.get("filename", "")))}
        if report_format == "txt":
            text = generate_report(results)
            data = text.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=scriptsentry-report.txt")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Private-Network", "true")
            self.end_headers()
            self.wfile.write(data)
            return

        if report_format == "csv":
            text = generate_csv_report(results)
            data = text.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=scriptsentry-report.csv")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Private-Network", "true")
            self.end_headers()
            self.wfile.write(data)
            return

        if report_format == "sarif":
            text = generate_sarif_report(results)
            data = text.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/sarif+json; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=scriptsentry-report.sarif")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Private-Network", "true")
            self.end_headers()
            self.wfile.write(data)
            return

        html = generate_html_report(results)
        data = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Disposition", "attachment; filename=scriptsentry-report.html")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.end_headers()
        self.wfile.write(data)

    def _run_analysis(self, body):
        mode = str(body.get("mode", "code")).strip().lower()
        if mode == "url":
            url = str(body.get("url", "")).strip()
            if not url.startswith(("http://", "https://")):
                raise ValueError("Enter a valid http(s) URL")
            profile = str(body.get("profile", DEFAULT_PROFILE)).strip()
            profile_cfg = SCAN_PROFILES.get(profile, SCAN_PROFILES[DEFAULT_PROFILE])
            max_depth = max(1, min(int(body.get("max_depth", profile_cfg["max_depth"])), 10))
            timeout = max(2, min(int(body.get("timeout", profile_cfg["timeout"])), 60))
            max_files = max(1, min(int(body.get("max_files", profile_cfg["max_files"])), 1000))
            return analyze_url(url, max_depth=max_depth, timeout=timeout, max_files=max_files)
        code = body.get("code")
        if not isinstance(code, str) or not code.strip():
            raise ValueError("Paste some JavaScript to analyze")
        filename = str(body.get("filename", "inline.js")).strip() or "inline.js"
        return analyze_content(code, filename=filename)

    def _handle_code_analysis(self, body):
        code = body.get("code")
        if not isinstance(code, str) or not code.strip():
            self._send_error_json("Paste some JavaScript to analyze", 400)
            return
        filename = str(body.get("filename", "inline.js")).strip() or "inline.js"
        try:
            results = analyze_content(code, filename=filename)
            payload = self._payload(results, metadata={"mode": "code", "source": filename})
            self._send_json({"ok": True, "type": "code", "payload": payload})
        except Exception as exc:
            self._send_error_json(f"Analysis failed: {exc}", 500)

    def _handle_async_analysis(self, body, mode):
        if mode == "url":
            url = str(body.get("url", "")).strip()
            if not url.startswith(("http://", "https://")):
                self._send_error_json("Enter a valid http(s) URL", 400)
                return
            profile = str(body.get("profile", DEFAULT_PROFILE)).strip()
            profile_cfg = SCAN_PROFILES.get(profile, SCAN_PROFILES[DEFAULT_PROFILE])
            max_depth = max(1, min(int(body.get("max_depth", profile_cfg["max_depth"])), 10))
            timeout = max(2, min(int(body.get("timeout", profile_cfg["timeout"])), 60))
            max_files = max(1, min(int(body.get("max_files", profile_cfg["max_files"])), 1000))
            job = jobs.create(
                mode="url", source=url, profile=profile,
                max_files=max_files, max_depth=max_depth, timeout=timeout,
            )
            jobs.start(
                job.id,
                analyze_url,
                url,
                max_depth=max_depth,
                timeout=timeout,
                max_files=max_files,
                progress_callback=lambda **kw: job.update(**kw),
            )
        else:
            code = body.get("code")
            if not isinstance(code, str) or not code.strip():
                self._send_error_json("Paste some JavaScript to analyze", 400)
                return
            filename = str(body.get("filename", "inline.js")).strip() or "inline.js"
            job = jobs.create(mode="code", source=filename, max_files=1)
            jobs.start(job.id, analyze_content, code, filename=filename)

        self._send_json({"ok": True, "job_id": job.id, "job": job.snapshot()})

    def _handle_url_analysis(self, body):
        url = str(body.get("url", "")).strip()
        if not url.startswith(("http://", "https://")):
            self._send_error_json("Enter a valid http(s) URL", 400)
            return
        profile = str(body.get("profile", DEFAULT_PROFILE)).strip()
        profile_cfg = SCAN_PROFILES.get(profile, SCAN_PROFILES[DEFAULT_PROFILE])
        max_depth = max(1, min(int(body.get("max_depth", profile_cfg["max_depth"])), 10))
        timeout = max(2, min(int(body.get("timeout", profile_cfg["timeout"])), 60))
        max_files = max(1, min(int(body.get("max_files", profile_cfg["max_files"])), 200))
        try:
            results = analyze_url(url, max_depth=max_depth, timeout=timeout, max_files=max_files)
            if not results:
                self._send_json({"ok": True, "type": "url", "payload": self._payload({}, metadata={"mode": "url", "source": url})})
                return
            payload = self._payload(results, metadata={"mode": "url", "source": url})
            self._send_json({"ok": True, "type": "url", "payload": payload})
        except Exception as exc:
            self._send_error_json(f"Remote analysis failed: {exc}", 500)

    @staticmethod
    def _payload(results, metadata=None):
        meta = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        if metadata:
            meta.update(metadata)
        return build_dashboard_payload(results, metadata=meta)


def make_server(host="0.0.0.0", port=8000):
    handler = DashboardHandler
    return ThreadingHTTPServer((host, port), handler)


def main():
    parser = argparse.ArgumentParser(description="ScriptSentry Web dashboard")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    args = parser.parse_args()

    server = make_server(args.host, args.port)
    print(f"ScriptSentry dashboard listening on http://{args.host}:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.", flush=True)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
