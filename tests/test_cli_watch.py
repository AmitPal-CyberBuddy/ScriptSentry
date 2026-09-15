"""Watch mode: re-scan on an interval, report what changed between cycles.

The between-cycles comparison reuses the engine's line-independent finding
fingerprint (the identity shared by the history diff and baselines), so a
finding that moved lines is "still there", never "new + resolved".
"""
import os
import tempfile
import unittest
from unittest import mock

import main as cli


def _finding(fid, severity="HIGH", observation=False, line=1):
    return {"id": fid, "severity": severity, "observation": observation,
            "title": fid.replace("_", " ").title(), "sink": "s", "line": line,
            "evidence": ["src -> s"]}


def _results(*findings, name="app.js"):
    return {name: {"findings": list(findings)}, "__scan_summary__": {"files": 1}}


class WatchCycleDiffTest(unittest.TestCase):
    def test_new_and_resolved_findings(self):
        v1 = _results(_finding("secret"), _finding("redirect", severity="MEDIUM"))
        v2 = _results(_finding("secret"), _finding("eval_call"))
        diff = cli.watch_cycle_diff(v1, v2)
        counts = diff["counts"]
        self.assertEqual(counts["new"], 1)
        self.assertEqual(counts["resolved"], 1)
        self.assertEqual(counts["persisted"], 1)
        titles = {v["verdict"]: v["title"] for v in diff["verdicts"]}
        self.assertEqual(titles["new"], "Eval Call")
        self.assertEqual(titles["resolved"], "Redirect")

    def test_line_independence(self):
        # The same finding ten lines further down is still there, not new.
        v1 = _results(_finding("secret", line=4))
        v2 = _results(_finding("secret", line=14))
        diff = cli.watch_cycle_diff(v1, v2)
        self.assertEqual(diff["counts"]["persisted"], 1)
        self.assertEqual(diff["counts"]["new"], 0)
        self.assertEqual(diff["counts"]["resolved"], 0)

    def test_worsened_severity_is_called_out(self):
        v1 = _results(_finding("secret", severity="MEDIUM"))
        v2 = _results(_finding("secret", severity="CRITICAL"))
        diff = cli.watch_cycle_diff(v1, v2)
        self.assertEqual(diff["counts"]["worsened"], 1)
        verdict = next(v for v in diff["verdicts"] if v["verdict"] == "worsened")
        self.assertIn("MEDIUM->CRITICAL", verdict["change"])

    def test_count_actionable_excludes_observations(self):
        results = _results(_finding("real"), _finding("noise", observation=True))
        self.assertEqual(cli.count_actionable(results), 1)


class GateFailureTest(unittest.TestCase):
    """The gate helper is shared by the single run and watch loop."""

    def test_passes_below_threshold_and_without_findings(self):
        self.assertEqual(cli.gate_failure(_results(_finding("x", severity="LOW")),
                                          None, "high"), (None, None))
        self.assertEqual(cli.gate_failure(_results(), None, "low"), (None, None))

    def test_fails_at_threshold(self):
        code, message = cli.gate_failure(_results(_finding("x", severity="HIGH")),
                                         None, "medium")
        self.assertEqual(code, 1)
        self.assertIn("HIGH", message)

    def test_baseline_filters_known_findings(self):
        v1 = _results(_finding("x", severity="HIGH"))
        with tempfile.TemporaryDirectory(prefix="ss-w-") as tmp:
            path = os.path.join(tmp, "b.json")
            from core.baseline import load_baseline, write_baseline
            write_baseline(v1, path)
            baseline, _ = load_baseline(path)
            self.assertEqual(cli.gate_failure(v1, baseline, "low"), (None, None))
            worse = _results(_finding("x", severity="HIGH"), _finding("y", severity="LOW"))
            code, _ = cli.gate_failure(worse, baseline, "low")
            self.assertEqual(code, 1)

    def test_observations_never_fail_even_without_baseline(self):
        self.assertEqual(cli.gate_failure(_results(_finding("o", observation=True)),
                                          None, "low"), (None, None))


class WatchLoopTest(unittest.TestCase):
    @staticmethod
    def _args(**kw):
        args = mock.Mock()
        args.watch = kw.get("watch", 10)
        args.fail_on = kw.get("fail_on", "none")
        args.baseline = None
        args.save_baseline = None
        args.targets = ["app.js"]
        return args

    def _run_loop(self, results_sequence, **kw):
        """Drive watch_loop with canned scans; sleep advances the sequence."""
        state = {"index": 0}
        scans = list(results_sequence)

        def fake_run(**kwargs):
            scan = scans[min(state["index"], len(scans) - 1)]
            state["index"] += 1
            return scan

        def fake_sleep(_seconds):
            # End the watch after the last scan has been consumed.
            if state["index"] >= len(scans):
                raise KeyboardInterrupt

        with mock.patch("main.run", side_effect=fake_run), \
                mock.patch("time.sleep", side_effect=fake_sleep):
            return cli.watch_loop(self._args(**kw), dict(targets=["app.js"], quiet=True))

    def test_clean_watch_exits_zero_after_interrupt(self):
        code = self._run_loop([_results(_finding("secret"))])
        self.assertEqual(code, 0)

    def test_gate_failure_stops_the_watch(self):
        code = self._run_loop([_results(_finding("secret", severity="CRITICAL"))],
                              fail_on="high")
        self.assertEqual(code, 1)

    def test_operational_error_exits_two(self):
        def fake_run(**kwargs):
            raise ValueError("Every target failed: boom")
        with mock.patch("main.run", side_effect=fake_run):
            code = cli.watch_loop(self._args(), dict(targets=["app.js"]))
        self.assertEqual(code, 2)

    def test_no_changes_cycle_reports_stability(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            self._run_loop([_results(_finding("secret")), _results(_finding("secret"))])
        out = buf.getvalue()
        self.assertIn("(no changes since the previous cycle)", out)
        self.assertIn("cycle 2", out)


if __name__ == "__main__":
    unittest.main()
