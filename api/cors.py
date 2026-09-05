"""CORS handling: headers on API/static responses plus the OPTIONS preflight.

The local dashboard is served from loopback, but the hosted GitHub Pages
site is an equally supported UI origin (it pairs with the engine via the
token), so cross-origin responses are allowed for *trusted* origins only —
see :mod:`api.auth` for the trust decision.
"""


class CorsMixin:
    """CORS headers and the preflight answer, mixed into the handler."""

    def _cors_header_values(self, origin):
        return [
            ("Access-Control-Allow-Origin", origin),
            ("Vary", "Origin"),
            ("Access-Control-Allow-Private-Network", "true"),
        ]

    def _request_origin(self):
        return self.headers.get("Origin", "")

    def _send_cors_headers(self):
        origin = self._request_origin()
        from api.auth import is_allowed_origin

        if origin and is_allowed_origin(origin):
            for name, value in self._cors_header_values(origin):
                self.send_header(name, value)

    def do_OPTIONS(self):
        from api.auth import is_allowed_origin

        if self._reject_untrusted_origin():
            return
        self.send_response(204)
        origin = self._request_origin()
        if origin and is_allowed_origin(origin):
            for name, value in self._cors_header_values(origin):
                self.send_header(name, value)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-ScriptSentry-Token")
        self.send_header("Access-Control-Max-Age", "300")
        self.end_headers()
