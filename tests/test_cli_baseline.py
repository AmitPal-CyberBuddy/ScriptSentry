"""Baseline files: the CI gate counts what is new or worsened, not what is old.

Covers the full lifecycle: ``--save-baseline`` writes a deterministic snapshot
of a scan's finding fingerprints; ``--baseline`` filters the ``--fail-on`` gate
to findings that are new (fingerprint absent) or worsened (severity raised, or
an observation that came back actionable) since that snapshot. Known findings
stay in reports -- only the exit code changes.
"""
import json
import os
import tempfile
import unittest
from unittest import mock

import main as cli
from core.baseline import gate_view, load_baseline, write_baseline


def _finding(fid, severity="HIGH", observation=False, title="t", sink="s"):
    return {"id": fid, "severity": severity, "observation": observation,
            "title": title, "sink": sink, "evidence": [f"src -> {sink}"]}


def _results(*findings, name="app.js"):
    return {name: {"findings": list(findings)},
            "__scan_summary__": {"files": 1}}


class WriteBaselineTest(unittest.TestCase):
    def test_round_trip_and_determinism(self):
        results = _results(_finding("dom_injection"), _finding("secret", severity="MEDIUM"))
        with tempfile.TemporaryDirectory(prefix="ss-base-") as tmp:
            path = os.path.join(tmp, "baseline.json")
            first = write_baseline(results, path)
            self.assertEqual(first, 2)
            with open(path, encoding="utf-8") as fh:
                content = fh.read()
            # Same input -> byte-identical file (clean diffs in review).
            write_baseline(results, path)
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), content)
            payload = json.loads(content)
            self.assertEqual(payload["version"], 1)
            self.assertEqual(len(payload["findings"]), 2)
            self.assertEqual([f["fingerprint"] for f in payload["findings"]],
                             sorted(f["fingerprint"] for f in payload["findings"]))
            baseline, warnings = load_baseline(path)
            self.assertEqual(warnings, [])
            self.assertEqual(len(baseline), 2)

    def test_global_keys_and_observations_are_still_recorded(self):
        # Observations are stored in the baseline (they can *become* findings),
        # but the __-prefixed scan bookkeeping keys are not findings at all.
        results = _results(_finding("obs", observation=True))
        rows = write_baseline(results, os.path.join(tempfile.mkdtemp(prefix="ss-base-"), "b.json"))
        self.assertEqual(rows, 1)

    def test_empty_scan_writes_empty_baseline(self):
        with tempfile.TemporaryDirectory(prefix="ss-base-") as tmp:
            path = os.path.join(tmp, "baseline.json")
            self.assertEqual(write_baseline({"__scan_summary__": {}}, path), 0)
            baseline, _ = load_baseline(path)
            self.assertEqual(baseline, {})


class LoadBaselineTest(unittest.TestCase):
    def test_missing_file_is_an_empty_baseline_with_warning(self):
        baseline, warnings = load_baseline("/definitely/not/a/baseline.json")
        self.assertEqual(baseline, {})
        self.assertTrue(any("not found" in w for w in warnings))

    def test_corrupt_file_is_an_error(self):
        with tempfile.TemporaryDirectory(prefix="ss-base-") as tmp:
            path = os.path.join(tmp, "bad.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{not json")
            with self.assertRaises(ValueError):
                load_baseline(path)

    def test_wrong_shape_is_an_error(self):
        with tempfile.TemporaryDirectory(prefix="ss-base-") as tmp:
            path = os.path.join(tmp, "wrong.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"findings": "nope"}, fh)
            with self.assertRaises(ValueError):
                load_baseline(path)


class GateViewTest(unittest.TestCase):
    def test_known_findings_are_excluded_new_ones_count(self):
        original = _results(_finding("dom_injection"), _finding("secret", severity="MEDIUM"))
        with tempfile.TemporaryDirectory(prefix="ss-base-") as tmp:
            path = os.path.join(tmp, "baseline.json")
            write_baseline(original, path)
            baseline, _ = load_baseline(path)
            # Same scan again: everything known, gate view empty.
            view, stats = gate_view(original, baseline)
            self.assertEqual(stats, {"known": 2, "new": 0, "worsened": 0})
            self.assertEqual(cli.worst_actionable_severity(view), (-1, 0))
            # A new HIGH finding appears.
            changed = _results(_finding("dom_injection"), _finding("secret", severity="MEDIUM"),
                               _finding("new_eval", severity="HIGH"))
            view, stats = gate_view(changed, baseline)
            self.assertEqual(stats["new"], 1)
            rank, count = cli.worst_actionable_severity(view)
            self.assertEqual(cli.SEVERITY_RANK["HIGH"], rank)
            self.assertEqual(count, 1)

    def test_worsened_severity_counts_against_the_gate(self):
        original = _results(_finding("secret", severity="MEDIUM"))
        with tempfile.TemporaryDirectory(prefix="ss-base-") as tmp:
            path = os.path.join(tmp, "baseline.json")
            write_baseline(original, path)
            baseline, _ = load_baseline(path)
            worse = _results(_finding("secret", severity="CRITICAL"))
            view, stats = gate_view(worse, baseline)
            self.assertEqual(stats, {"known": 0, "new": 0, "worsened": 1})
            self.assertEqual(cli.worst_actionable_severity(view)[0], cli.SEVERITY_RANK["CRITICAL"])
            # Improved severity is NOT a gate failure.
            better = _results(_finding("secret", severity="LOW"))
            view, stats = gate_view(better, baseline)
            self.assertEqual(stats["worsened"], 0)
            self.assertEqual(stats["known"], 1)

    def test_observation_becoming_a_finding_is_worsened(self):
        original = _results(_finding("tracker", observation=True))
        with tempfile.TemporaryDirectory(prefix="ss-base-") as tmp:
            path = os.path.join(tmp, "baseline.json")
            write_baseline(original, path)
            baseline, _ = load_baseline(path)
            now_actionable = _results(_finding("tracker", observation=False))
            view, stats = gate_view(now_actionable, baseline)
            self.assertEqual(stats["worsened"], 1)
            self.assertEqual(view, {"app.js": {"findings": now_actionable["app.js"]["findings"]}})

    def test_observations_never_gate_even_when_new(self):
        results = _results(_finding("brand_new_obs", observation=True))
        view, stats = gate_view(results, {})
        self.assertEqual(stats["new"], 0)
        self.assertEqual(view, {})

    def test_empty_baseline_treats_everything_as_new(self):
        results = _results(_finding("one"), _finding("two"))
        view, stats = gate_view(results, {})
        self.assertEqual(stats, {"known": 0, "new": 2, "worsened": 0})
        self.assertEqual(len(view["app.js"]["findings"]), 2)


class MainBaselineIntegrationTest(unittest.TestCase):
    """Exit codes through main() with a patched scan (fast, deterministic)."""

    def _run(self, results, extra):
        with mock.patch("main.run", return_value=results), \
                tempfile.TemporaryDirectory(prefix="ss-main-") as tmp:
            return cli.main([*extra, "--format", "txt", "--output", tmp])

    def test_rolling_baseline_lifecycle(self):
        # 1. First run: save a baseline from a scan with findings.
        with tempfile.TemporaryDirectory(prefix="ss-life-") as tmp:
            baseline_path = os.path.join(tmp, "scriptsentry-baseline.json")
            results = _results(_finding("dom_injection"), _finding("secret", severity="MEDIUM"))
            code = self._run(results, ["app.js", "--fail-on", "low",
                                       "--save-baseline", baseline_path])
            self.assertEqual(code, 1, "without a baseline the gate still fires")
            # 2. Same findings again: known -> gate passes.
            code = self._run(results, ["app.js", "--fail-on", "low",
                                       "--baseline", baseline_path])
            self.assertEqual(code, 0)
            # 3. A new HIGH finding: gate fires again.
            worse = _results(_finding("dom_injection"), _finding("secret", severity="MEDIUM"),
                             _finding("eval_user", severity="HIGH"))
            code = self._run(worse, ["app.js", "--fail-on", "low",
                                     "--baseline", baseline_path])
            self.assertEqual(code, 1)
            # 4. Rolling update: accepting the new state is one flag away.
            code = self._run(worse, ["app.js", "--fail-on", "low",
                                     "--baseline", baseline_path,
                                     "--save-baseline", baseline_path])
            self.assertEqual(code, 1, "saving does not bypass this run's gate")
            code = self._run(worse, ["app.js", "--fail-on", "low",
                                     "--baseline", baseline_path])
            self.assertEqual(code, 0, "the updated baseline accepts the new finding")

    def test_missing_baseline_fails_like_no_baseline(self):
        results = _results(_finding("dom_injection"))
        code = self._run(results, ["app.js", "--fail-on", "low",
                                   "--baseline", "/no/such/baseline.json"])
        self.assertEqual(code, 1, "missing baseline = everything is new (safe direction)")

    def test_corrupt_baseline_is_operational_error(self):
        with tempfile.TemporaryDirectory(prefix="ss-bad-") as tmp:
            path = os.path.join(tmp, "b.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("}{")
            code = self._run(_results(_finding("x")), ["app.js", "--fail-on", "low",
                                                       "--baseline", path])
            self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
