"""The stdlib HTTP handler base: JSON responses, bodies, static-UI serving.

Security/behavioral invariants kept here:

  * every response carries nosniff/referrer/frame/permissions headers;
  * successful /api/status and /api/health polls do not flood the log
    (they ARE the dashboard's heartbeat during a scan);
  * directories without an index page are 404, never a listing;
  * 404s serve the site's own page so a lost visitor recovers.
"""
import json
import os
from http.server import SimpleHTTPRequestHandler
from urllib.parse import urlparse

from api.settings import MAX_BODY, WEB_ROOT


class BaseHandler(SimpleHTTPRequestHandler):
    """Shared plumbing for the dashboard handler (routes live in mixins)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_ROOT, **kwargs)
        # Set by _send_json(): successful /api/status and /api/health polls
        # are the dashboard's heartbeat, arriving up to a few times per second
        # during a scan. Logging each one buried every useful line the server
        # prints, so they are recorded only when they fail.
        self._quiet_access_log = False

    def log_message(self, fmt, *args):
        if getattr(self, "_quiet_access_log", False):
            return
        print(f"[webui] {self.address_string()} {fmt % args}", flush=True)

    def end_headers(self):
        # These headers apply to static UI responses as well as API responses.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=()")
        # The engine serves files it owns from disk; a cached page that
        # pairs with a newer engine (or vice versa) reads as bugs. The
        # revalidation cost on localhost is negligible.
        self.send_header("Cache-Control", "no-cache")
        super().end_headers()

    def _send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        path = urlparse(self.path).path if self.path else ""
        self._quiet_access_log = (
            status == 200 and path in ("/api/status", "/api/health")
        )
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, message, status=400):
        self._send_json({"ok": False, "error": message}, status=status)

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
