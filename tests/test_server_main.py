"""``server.main()`` bootstrap contract: prints the pairing token, names the
AST-parser mode honestly, warns on non-loopback binds, and shuts down cleanly.
"""
import io
import os
import sys
import unittest
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import server


class FakeServer:
    def __init__(self, address):
        self.address = address
        self.served = False
        self.closed = False

    def serve_forever(self):
        self.served = True
        raise KeyboardInterrupt

    def server_close(self):
        self.closed = True


def run_main(argv, parser_status, host="127.0.0.1"):
    fake = FakeServer((host, 8000))
    out = io.StringIO()
    with mock.patch.object(sys, "argv", ["server.py"] + argv), \
            mock.patch.object(server, "make_server", return_value=fake) as mk, \
            mock.patch.object(server, "parser_status", return_value=parser_status), \
            redirect_stdout(out):
        server.main()
    return out.getvalue(), fake, mk


class ServerMainTest(unittest.TestCase):
    def test_serves_and_prints_pairing_token(self):
        out, fake, mk = run_main(
            ["--port", "8443"],
            {"available": True, "name": "esprima", "mode": "ast"},
        )
        self.assertIn("listening on http://127.0.0.1:8443", out)
        self.assertIn("Engine pairing token:", out)
        self.assertIn("AST parser: esprima", out)
        self.assertIn("full source-to-sink analysis", out)
        self.assertNotIn("WARNING", out)
        self.assertTrue(fake.served and fake.closed, "KeyboardInterrupt must shut down cleanly")
        self.assertEqual(mk.call_args.args, ("127.0.0.1", 8443))

    def test_missing_ast_parser_names_the_cost(self):
        out, _, _ = run_main(
            [],
            {"available": False, "mode": "regex_fallback", "install_hint": "pip install esprima"},
        )
        self.assertIn("AST parser: UNAVAILABLE", out)
        self.assertIn("regex_fallback", out)
        self.assertIn("medium", out)  # the concrete confidence cost
        self.assertIn("pip install esprima", out)

    def test_non_loopback_bind_warns(self):
        out, fake, mk = run_main(
            ["--host", "0.0.0.0", "--port", "9000"],
            {"available": True, "name": "esprima", "mode": "ast"},
        )
        self.assertIn("WARNING: non-loopback binding", out)
        self.assertEqual(mk.call_args.args, ("0.0.0.0", 9000))

    def test_embedder_contract_survives_the_api_split(self):
        for name in ("make_server", "main", "DashboardHandler", "API_TOKEN", "WEB_ROOT",
                     "jobs", "MAX_BODY", "MAX_URL_LENGTH", "MAX_UPLOAD_FILES", "MAX_FILE_BYTES"):
            self.assertTrue(hasattr(server, name), f"server.{name} must stay importable")
        self.assertIs(server.DashboardHandler, __import__("api").DashboardHandler)


if __name__ == "__main__":
    unittest.main()
