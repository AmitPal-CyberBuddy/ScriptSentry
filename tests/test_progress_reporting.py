"""Progress-reporting contracts for scans and the dashboard poll loop.

A URL scan used to have two failure modes that made it *feel* broken even
when it was working:

  * silent stretches — per-file events fired only after each file finished,
    beautifying reported nothing, and download events bypassed the weighted
    progress model (so the bar jumped to 100% and snapped back);
  * a hard 10-minute cap in ``pollJob`` that declared "Analysis timed out
    while waiting for the local engine" while the engine was still scanning.

The tests below pin the fixes: one parse per document (cache), per-file
events in download/normalize/analyze, a monotonic weighted percent, a job
heartbeat the UI can read, and a UI that keeps waiting as long as the engine
keeps answering.
"""
import http.server
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from functools import partial

from core.beautifier import beautify
from core.jobs import Job
from core.js_parser import esprima, parser_available
from core.analyzer_service import analyze_url

requires_ast_parser = unittest.skipUnless(
    parser_available(),
    "needs the optional esprima AST parser (pip install esprima)",
)

APP_JS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "webui", "app.js")
TOOL_HTML = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "webui", "tool", "index.html")
STYLES_CSS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "webui", "styles.css")

SMALL_JS = "const a = 1; export default a;"


class _ScanSiteHandler(http.server.SimpleHTTPRequestHandler):
    """Serves a tiny app: one entry bundle that imports one chunk."""

    def log_message(self, *args):  # keep test output clean
        pass


def _make_site(root):
    js_dir = os.path.join(root, "js")
    os.makedirs(js_dir, exist_ok=True)
    with open(os.path.join(js_dir, "app.js"), "w", encoding="utf-8") as fh:
        fh.write(
            "const entry = 1;\n"
            'import("./chunk-a.js");\n'
            'document.title = "entry";\n' * 40
        )
    with open(os.path.join(js_dir, "chunk-a.js"), "w", encoding="utf-8") as fh:
        fh.write("const chunk = 2;\nconst sink = document.getElementById(\"x\");\n" * 30)
    with open(os.path.join(root, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(
            "<!doctype html><html><body>"
            "<script src=\"/js/app.js\"></script>"
            "<script>var inline = 1;</script>"
            "</body></html>"
        )


class ProgressEventRecorder:
    """Collects progress events exactly like the job layer does."""

    def __init__(self):
        self.events = []

    def __call__(self, **kwargs):
        self.events.append(kwargs)

    def phases(self):
        return [e.get("phase") for e in self.events]

    def messages(self):
        return [str(e.get("message") or "") for e in self.events]


class ParseCacheTest(unittest.TestCase):
    """One scan of one document must parse it exactly once."""

    def setUp(self):
        if not parser_available():
            self.skipTest("needs the optional esprima AST parser")
        from core import js_parser
        with js_parser._CACHE_LOCK:
            js_parser._RAW_CACHE.clear()
            js_parser._FAILURE_CACHE.clear()

    def test_second_parse_of_same_content_is_cached(self):
        from core import js_parser
        calls = {"n": 0}
        real_parse = esprima.parseModule

        def counting(source, opts):
            calls["n"] += 1
            return real_parse(source, opts)

        content = "const token = 'a'; function f(x) { return x + token; } f(1);"
        esprima.parseModule = counting
        try:
            first = js_parser.parse_raw(content)
            second = js_parser.parse_raw(content)
        finally:
            esprima.parseModule = real_parse
        self.assertIsNotNone(first)
        self.assertEqual(calls["n"], 1, "same content must be parsed once, not once per consumer")
        self.assertIs(first, second, "cache should hand back the shared read-only tree")

    def test_parse_failures_are_cached_too(self):
        from core import js_parser
        calls = {"n": 0}
        real_parse = esprima.parseModule

        def counting(source, opts):
            calls["n"] += 1
            return real_parse(source, opts)

        content = "this is ((( not javascript"
        esprima.parseModule = counting
        try:
            first_tree, first_error = js_parser.parse_raw_with_error(content)
            second_tree, second_error = js_parser.parse_raw_with_error(content)
        finally:
            esprima.parseModule = real_parse
        self.assertIsNone(first_tree)
        self.assertEqual(first_error, second_error)
        self.assertEqual(calls["n"], 1, "a failed parse must not be retried per consumer")

    def test_oversize_content_bypasses_the_cache(self):
        from core import js_parser
        big = "const x = 1;\n" * 40_000  # > _RAW_CACHE_MAX_SOURCE_BYTES
        self.assertGreater(len(big.encode()), js_parser._RAW_CACHE_MAX_SOURCE_BYTES)
        tree = js_parser.parse_raw(big)
        self.assertIsNotNone(tree)
        key = js_parser._content_key(big)
        with js_parser._CACHE_LOCK:
            self.assertNotIn(key, js_parser._RAW_CACHE, "oversize trees must not be retained")


class BeautifyProgressTest(unittest.TestCase):
    def test_beautify_reports_per_file_events(self):
        workdir = tempfile.mkdtemp(prefix="scriptsentry-beautify-")
        try:
            paths = []
            for i in range(3):
                path = os.path.join(workdir, f"bundle{i}.js")
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write("function f(){return 1;}f();\n" * 20)
                paths.append(path)
            outdir = os.path.join(workdir, "out")
            recorder = ProgressEventRecorder()
            results = beautify(paths, output_dir=outdir, progress_callback=recorder)
            self.assertEqual(len(results), 3)
            normalize_events = [e for e in recorder.events if e.get("phase") == "normalize"]
            self.assertTrue(normalize_events, "beautify must emit normalize events")
            # The first event announces the stage; the rest report per-file completions.
            self.assertEqual(normalize_events[0].get("current"), 0)
            completions = [e for e in normalize_events if str(e.get("message", "")).startswith("Normalized ")]
            self.assertEqual(len(completions), 3)
            currents = [e.get("current") for e in completions]
            self.assertEqual(currents, [1, 2, 3])
            for event in completions:
                self.assertTrue(str(event.get("message")).endswith(f"({event.get('current')}/{event.get('total')})"))
        finally:
            shutil.rmtree(workdir, ignore_errors=True)


class JobHeartbeatTest(unittest.TestCase):
    def test_snapshot_reports_time_since_last_update(self):
        job = Job(mode="url", source="http://example.test/")
        self.assertIsNone(job.snapshot()["since_update_ms"])
        job.start()
        job.update(phase="recon", message="Reading page")
        snap = job.snapshot()
        self.assertIsNotNone(snap["since_update_ms"])
        first = snap["since_update_ms"]
        time.sleep(0.05)
        later = job.snapshot()["since_update_ms"]
        self.assertGreaterEqual(later, first)
        job.update(phase="analyze", message="Working")
        self.assertLessEqual(job.snapshot()["since_update_ms"], 50, "an update must refresh the heartbeat")

    def test_weighted_percent_wins_over_raw_ratio(self):
        job = Job(mode="url", source="http://example.test/")
        job.start()
        # Weighted events (as emitted by notify()) carry percent; the job must
        # keep it rather than deriving files/cap.
        job.update(phase="download", current=2, total=4, percent=22.4, message="Downloading scripts 2/4")
        self.assertEqual(job.snapshot()["percent"], 22.4)
        job.update(phase="download", current=4, total=4, percent=37.9, message="Downloading scripts 4/4")
        self.assertEqual(job.snapshot()["percent"], 37.9)
        self.assertNotEqual(job.snapshot()["percent"], 100.0)


@unittest.skipUnless(os.environ.get("SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS"),
                     "loopback scan targets need SCRIPTSENTRY_ALLOW_PRIVATE_TARGETS=1")
class AnalyzeUrlProgressTest(unittest.TestCase):
    """Full pipeline events against a local loopback site."""

    def setUp(self):
        self.workdir = tempfile.mkdtemp(prefix="scriptsentry-site-")
        _make_site(self.workdir)
        handler = partial(_ScanSiteHandler, directory=self.workdir)
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.workdir, ignore_errors=True)

    def test_events_are_continuous_weighted_and_named(self):
        recorder = ProgressEventRecorder()
        url = f"http://127.0.0.1:{self.port}/"
        analyze_url(url, max_depth=2, timeout=5, max_files=10, max_workers=2,
                    progress_callback=recorder)
        phases = recorder.phases()
        self.assertIn("recon", phases)
        self.assertIn("download", phases)
        self.assertIn("normalize", phases)

        # Every event must carry a weighted percent and the percent must
        # never move backwards.
        percents = [e.get("percent") for e in recorder.events]
        self.assertIsNotNone(percents[0])
        for i in range(1, len(percents)):
            self.assertIsNotNone(percents[i], f"event {i} lost its weighted percent")
            self.assertGreaterEqual(percents[i], percents[i - 1] - 1e-9,
                                    "progress must be monotonic")

        # Work must be announced before it completes, by name.
        messages = recorder.messages()
        scanning_starts = [i for i, m in enumerate(messages) if m.startswith("Scanning ")]
        analyzed = [i for i, m in enumerate(messages) if m.startswith("Analyzed ")]
        self.assertTrue(scanning_starts, "files in flight must be announced ('Scanning x…')")
        self.assertTrue(analyzed)
        self.assertLess(min(scanning_starts), max(analyzed))

        # Normalize reports per-file progress, not a single frozen event.
        normalize_msgs = [m for m in messages if m.startswith(("Normalizing", "Normalized "))]
        self.assertGreaterEqual(len(normalize_msgs), 2)

    def test_unreachable_target_raises_actionable_error(self):
        # Port 1 on loopback: nothing listens there, the page fetch fails and
        # the scan must say so instead of returning an empty report.
        with self.assertRaises(ValueError) as ctx:
            analyze_url("http://127.0.0.1:1/", max_depth=1, timeout=2, max_files=5, max_workers=1)
        self.assertIn("Could not download the page", str(ctx.exception))


class DashboardPollContractTest(unittest.TestCase):
    """The UI must keep waiting while the engine keeps answering.

    These are deliberately literal (there is no browser in CI): they read the
    shipped sources and fail on the exact patterns that caused the old
    "is it stuck?" spinner and the 10-minute timeout error.
    """

    def setUp(self):
        with open(APP_JS, encoding="utf-8") as fh:
            self.app = fh.read()
        with open(TOOL_HTML, encoding="utf-8") as fh:
            self.tool = fh.read()
        with open(STYLES_CSS, encoding="utf-8") as fh:
            self.css = fh.read()

    def test_no_fixed_iteration_cap_on_the_poll_loop(self):
        self.assertNotIn("i < 1200", self.app,
                         "pollJob must not give up after a fixed number of polls")
        self.assertNotIn("Analysis timed out while waiting for the local engine",
                         self.app, "the misleading blanket-timeout message is gone")

    def test_poll_loop_tolerates_transient_failures(self):
        for needle in ("POLL_FAILURE_GRACE_MS", "lastGoodPoll"):
            self.assertIn(needle, self.app)

    def test_progress_uses_the_engine_heartbeat(self):
        self.assertIn("since_update_ms", self.app)
        self.assertIn("QUIET_HINT_MS", self.app)

    def test_quiet_state_is_visible_and_explained(self):
        self.assertIn("progress-hint", self.tool, "tool page needs the hint element")
        self.assertIn("is-quiet", self.css, "stylesheet needs the quiet state")
        self.assertIn(".progress-hint", self.css)

    def test_cancel_is_not_styled_as_an_error(self):
        self.assertIn("neutral: canceled", self.app)
        self.assertIn(".field-error.is-neutral", self.css)


if __name__ == "__main__":
    unittest.main()
