"""Hosted-page hand-off, direct .js targets, and setup-guide contracts.

Four real user journeys broke in the hosted (github.io) flow:

  * the setup guide claimed the local dashboard is "already paired" — it is
    not; the pairing token must be pasted once (it is printed in the engine's
    terminal);
  * after being told to open http://127.0.0.1:8000, the user had to re-type
    the target URL and re-set every scan option there — the request now
    travels inside the hand-off link's #scan= fragment and the local page
    fills the form and starts the scan;
  * the setup-guide copy button copied shell comments along with the command;
  * hovering the "?" tooltips on left-column fields clipped their first words
    (the viewport nudge only ran for click/keyboard opens).

The engine side had its own broken promise: scanning a direct
``https://host/app.js`` URL treated the target as an HTML page and returned
an empty "no JavaScript found" report. A direct script target must be
analyzed itself, with its module/chunk references followed.
"""
import os
import re
import shutil
import tempfile
import threading
import unittest
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from core.analyzer_service import analyze_url

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WEBUI = os.path.join(ROOT, "webui")
APP_JS_PATH = os.path.join(WEBUI, "app.js")
TOOL_HTML_PATH = os.path.join(WEBUI, "tool", "index.html")
HOME_HTML_PATH = os.path.join(WEBUI, "home", "index.html")
STYLES_PATH = os.path.join(WEBUI, "styles.css")

APP_JS = open(APP_JS_PATH, encoding="utf-8").read()
TOOL_HTML = open(TOOL_HTML_PATH, encoding="utf-8").read()
HOME_HTML = open(HOME_HTML_PATH, encoding="utf-8").read()
STYLES = open(STYLES_PATH, encoding="utf-8").read()


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


@unittest.skipUnless(os.environ.get("SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS"),
                     "loopback scan targets need SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS=1")
class DirectScriptTargetTest(unittest.TestCase):
    """A direct .js/.mjs target is a deliverable, not a page to crawl."""

    def setUp(self):
        self.workdir = tempfile.mkdtemp(prefix="scriptsentry-direct-")
        js_dir = os.path.join(self.workdir, "js")
        os.makedirs(js_dir, exist_ok=True)
        with open(os.path.join(js_dir, "app.js"), "w", encoding="utf-8") as fh:
            fh.write('const entry = 1;\nimport("./chunk-a.js");\n' * 20)
        with open(os.path.join(js_dir, "chunk-a.js"), "w", encoding="utf-8") as fh:
            fh.write('const c = 2;\ndocument.title = location.hash;\n' * 10)
        with open(os.path.join(js_dir, "wrapped.js"), "w", encoding="utf-8") as fh:
            fh.write('<!doctype html><html><body><script src="/js/app.js"></script></body></html>')
        handler = partial(SimpleHTTPRequestHandler, directory=self.workdir)
        handler.log_message = lambda *a, **k: None
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.workdir, ignore_errors=True)

    def _url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def test_direct_js_target_is_analyzed_and_chunks_are_followed(self):
        results = analyze_url(self._url("/js/app.js"), max_depth=2, timeout=5,
                              max_files=10, max_workers=2)
        keys = [k for k in results if not str(k).startswith("__")]
        self.assertTrue(any(str(k).startswith("app-") for k in keys),
                        f"the target script itself must be analyzed, got {keys}")
        self.assertTrue(any("chunk-a" in str(k) for k in keys),
                        "module references inside the target must be followed")
        summary = results.get("__scan_summary__") or {}
        self.assertIn(self._url("/js/app.js"), summary.get("script_urls", []),
                      "the target URL must appear in the script inventory")
        self.assertTrue((summary.get("page") or {}).get("direct_script"))

    def test_missing_direct_target_raises_actionable_error(self):
        with self.assertRaises(ValueError) as ctx:
            analyze_url(self._url("/js/does-not-exist.js"), max_depth=1, timeout=3,
                        max_files=5, max_workers=1)
        self.assertIn("Could not download the page", str(ctx.exception),
                      "the error must say the target could not be fetched")

    def test_html_served_at_a_js_url_falls_back_to_page_discovery(self):
        # A soft-404 wrapper page at a .js URL must still find the scripts the
        # page references instead of erroring or returning an empty report.
        results = analyze_url(self._url("/js/wrapped.js"), max_depth=1, timeout=5,
                              max_files=10, max_workers=2)
        keys = [k for k in results if not str(k).startswith("__")]
        self.assertTrue(any("app-" in str(k) for k in keys),
                        f"page discovery behind the .js URL must find app.js, got {keys}")


class HostedHandoffContractTest(unittest.TestCase):
    """Literal contracts for the hosted-page → local-dashboard hand-off."""

    def test_no_page_claims_the_dashboard_is_already_paired(self):
        for name, text in (("app.js", APP_JS), ("tool", TOOL_HTML), ("home", HOME_HTML)):
            self.assertNotIn("already paired", text,
                             f"{name} still claims the local dashboard is pre-paired")

    def test_setup_steps_tell_the_user_to_paste_the_token(self):
        for name, text in (("tool", TOOL_HTML), ("home", HOME_HTML)):
            self.assertIn("Paste the pairing token", text,
                          f"{name} setup steps must say the token is pasted once")

    def test_setup_says_which_command_to_run(self):
        # Both entry points must make clear that scriptsentry.py and
        # server.py start the same engine — pick one, not both.
        for name, text in (("tool", TOOL_HTML), ("home", HOME_HTML)):
            self.assertIn("run <b>one</b> of the two", text,
                          f"{name} must disambiguate the launcher vs server.py")
            self.assertIn("python3 server.py --port 8000", text)

    def test_handoff_link_carries_the_scan_request(self):
        for needle in ("buildHandoffUrl", "#scan=", "toB64Url", "fromB64Url",
                       "sanitizeScanRequest", "parseScanTransfer",
                       "maybeRunPendingTransfer", "currentScanRequest"):
            self.assertIn(needle, APP_JS, f"app.js is missing hand-off piece: {needle}")

    def test_local_page_consumes_the_fragment_and_shows_a_note(self):
        self.assertIn('id="transfer-note"', TOOL_HTML)
        self.assertIn("parseScanTransfer()", APP_JS)
        self.assertIn("history.replaceState", APP_JS, "the fragment must be consumed once")
        self.assertIn("Scan carried over from the hosted page", APP_JS)

    def test_handoff_fragment_is_not_sent_to_any_server(self):
        # The transfer must live in the fragment (never a query string), which
        # browsers do not send to the server.
        self.assertIn("${base}#scan=", APP_JS)

    def test_oversize_transfer_never_fills_inputs_with_undefined(self):
        # A request that exceeded the link budget arrives without bodies
        # (tooLarge). The handler must stop before the mode branches, or the
        # console would end up scanning the literal string "undefined".
        self.assertRegex(
            APP_JS,
            r"maybeRunPendingTransfer[\s\S]{0,400}if \(req\.tooLarge\)",
        )

    def test_copy_buttons_strip_shell_comments(self):
        self.assertIn("filter((line) => !/^\\s*#/.test(line))", APP_JS)
        # Apply the same rule to the actual sample block shipped in the modal.
        match = re.search(r'<pre id="setup-code-easy-modal">(.*?)</pre>', TOOL_HTML, re.S)
        self.assertIsNotNone(match)
        raw = match.group(1).replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
        kept = [ln for ln in raw.split("\n") if not re.match(r"^\s*#", ln)]
        self.assertEqual(kept, ["python3 scriptsentry.py --port 8000"],
                         "copying the launcher sample must yield the bare command")

    def test_tooltip_nudge_runs_on_hover_and_focus(self):
        self.assertIn('tip.addEventListener("mouseenter", () => nudgeIntoView(tip))', APP_JS)
        self.assertIn('tip.addEventListener("focus", () => nudgeIntoView(tip))', APP_JS)
        self.assertIn("nudgeIntoView", APP_JS)

    def test_handoff_note_names_where_the_token_comes_from(self):
        self.assertIn("printed in the", APP_JS)
        self.assertIn("terminal", APP_JS)


class TransferNoteStyleContractTest(unittest.TestCase):
    def test_transfer_note_is_styled(self):
        self.assertIn(".transfer-note", STYLES)
        self.assertIn(".transfer-note[hidden]", STYLES)


if __name__ == "__main__":
    unittest.main()
