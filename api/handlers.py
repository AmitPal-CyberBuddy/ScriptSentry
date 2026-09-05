"""The assembled dashboard request handler.

``DashboardHandler`` composes the mixins (routes, auth, CORS) over the
stdlib base and owns only the GET/POST *dispatch*: /api/ paths go to the
route mixins, everything else is static UI serving (with the loopback
visitor landing straight on the analysis console).
"""
from urllib.parse import urlparse

from api.analysis_routes import AnalysisRoutesMixin
from api.auth import AuthMixin
from api.cors import CorsMixin
from api.http import BaseHandler
from api.report_routes import ReportRoutesMixin


def _engine_version():
    from core.version import __version__

    return __version__


class DashboardHandler(AuthMixin, CorsMixin, ReportRoutesMixin, AnalysisRoutesMixin, BaseHandler):
    """Serves the single-page dashboard and answers analysis requests."""

    server_version = f"ScriptSentryDashboard/{_engine_version()}"

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            if self._reject_untrusted_origin():
                return
            if parsed.path == "/api/health":
                self._handle_health()
                return
            if self._handle_api_get(parsed):
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

    def do_POST(self):
        parsed = urlparse(self.path)
        if self._reject_untrusted_origin():
            return
        if not parsed.path.startswith("/api/"):
            self._send_error_json("Unknown endpoint", 404)
            return
        if not self._require_api_auth():
            return
        body = self._read_json_body()
        if body is None:
            return
        if parsed.path == "/api/report":
            self._handle_report(parsed, body)
            return
        if self._handle_api_post(parsed, body):
            return
        self._send_error_json("Unknown endpoint", 404)


def _engine_version():
    from core.version import __version__

    return __version__
