"""Pipeline staging, progress/ETA behaviour and export-accuracy contracts."""
import json
import os
import tempfile
import time
import unittest
from unittest import mock

from core.analyzer_service import analyze_content
from core.eta import AVG_JS_BYTES, CostModel
from core.jobs import Job
from core.pipeline import ProgressModel, canonical_stage, stage_label, stage_plan
from core.reporter import (
    generate_csv_report,
    generate_report,
    generate_sarif_report,
    scan_reliability,
)


SAMPLE = (
    'const apiKey = "Ab3x9Kq1Zp7m";\n'
    'const q = new URLSearchParams(location.search).get("q");\n'
    'document.getElementById("x").innerHTML = q;\n'
    'fetch("/api/v1/orders", {headers:{Authorization:"Bearer x"}});\n'
)


class PipelineStageTest(unittest.TestCase):

    def test_legacy_phase_names_map_onto_stages(self):
        self.assertEqual(canonical_stage("inline_scan"), "analyze")
        self.assertEqual(canonical_stage("recursive_scan"), "analyze")
        self.assertEqual(canonical_stage("beautify"), "normalize")
        self.assertEqual(canonical_stage("runtime"), "verify")
        self.assertEqual(canonical_stage("done"), "report")

    def test_stage_labels_are_human_readable(self):
        for phase in ("recon", "discover", "download", "normalize", "analyze", "verify"):
            self.assertEqual(stage_label(phase), stage_label(phase).strip())
            self.assertFalse(stage_label(phase).islower())

    def test_plan_depends_on_the_mode(self):
        code_plan = [s.key for s in stage_plan(mode="code")]
        self.assertEqual(code_plan, ["analyze", "correlate", "report"])
        url_plan = [s.key for s in stage_plan(mode="url", runtime_enabled=False)]
        self.assertNotIn("verify", url_plan)
        self.assertEqual(url_plan[0], "recon")
        self.assertEqual(url_plan[-1], "report")


class ProgressModelTest(unittest.TestCase):

    def _model(self):
        return ProgressModel(stage_plan(mode="url", runtime_enabled=False))

    def test_progress_never_moves_backwards(self):
        model = self._model()
        model.set_stage("recon", current=0, total=1)
        model.set_stage("discover", current=4, total=10)
        first = model.fraction
        # A growing work estimate must stall the bar, never rewind it.
        model.update(current=2, total=100)
        self.assertGreaterEqual(model.fraction, first)

    def test_expensive_stages_move_the_bar_slower(self):
        analyse_only = ProgressModel(stage_plan(mode="code"))
        analyse_only.set_stage("analyze", current=1, total=2)
        half_of_a_code_scan = analyse_only.fraction

        full = self._model()
        full.set_stage("recon", current=1, total=1)
        full.set_stage("discover", current=1, total=1)
        self.assertLess(full.fraction, half_of_a_code_scan)

    def test_percent_is_bounded(self):
        model = self._model()
        for stage in ("recon", "discover", "download", "normalize", "analyze", "correlate", "report"):
            model.set_stage(stage, current=99, total=1)
        self.assertLessEqual(model.percent, 100.0)
        self.assertGreaterEqual(model.percent, 0.0)

    def test_stage_states_mark_done_active_pending(self):
        model = self._model()
        model.set_stage("recon", current=1, total=1)
        model.set_stage("download", current=0, total=4)
        states = {s["key"]: s["state"] for s in model.stage_states()}
        self.assertEqual(states["recon"], "done")
        self.assertEqual(states["download"], "active")
        self.assertEqual(states["report"], "pending")


class EtaTest(unittest.TestCase):

    def test_eta_is_none_before_any_progress(self):
        job = Job(max_files=10)
        job.start()
        job.update(phase="recon", current=0, total=1, percent=0)
        self.assertIsNone(job.snapshot()["eta_seconds"])

    def test_eta_tracks_a_steady_scan(self):
        job = Job(max_files=100)
        job.start()
        started = job.started_at
        # A 20 second scan sampled every 2.5%: the estimate must land close to
        # the truth once we have watched it for a while.
        for pct in range(5, 60, 5):
            job.started_at = started - (pct / 100.0) * 20.0
            job.update(percent=pct, current=pct, total=100)
        snap = job.snapshot()
        truth = (100 - 55) / 100.0 * 20.0
        self.assertIsNotNone(snap["eta_seconds"])
        self.assertLess(abs(snap["eta_seconds"] - truth), 4.0)

    def test_eta_confidence_grows_with_time_and_progress(self):
        job = Job(max_files=100)
        job.start()
        job.started_at = job.started_at - 1.0
        job.update(percent=40, current=40, total=100)
        early = job.snapshot()["eta_confidence"]
        job.started_at = job.started_at - 30.0
        job.update(percent=80, current=80, total=100)
        self.assertLess(early, job.snapshot()["eta_confidence"])

    def test_a_stall_cannot_explode_the_estimate(self):
        job = Job(max_files=100)
        job.start()
        job.started_at = job.started_at - 10.0
        job.update(percent=50, current=50, total=100)
        before = job.snapshot()["eta_seconds"]
        job.started_at = job.started_at - 5.0
        job.update(percent=50, current=50, total=100)  # no progress for 5s
        after = job.snapshot()["eta_seconds"]
        self.assertLessEqual(after, before * 1.6 + 3.0)


class WorkloadEtaTest(unittest.TestCase):
    """The estimate must come from the *discovered workload*, not just the clock.

    The old estimator extrapolated the observed percent velocity and nothing
    else: it knew neither how many files recon had found, nor how many bytes
    download had pulled, nor the worker count -- and it froze entirely while
    the engine was quiet, showing "eta ~2m left" next to "last update 28m
    ago".
    """

    STAGES = [{"key": s, "state": "pending"} for s in
              ("recon", "discover", "download", "normalize", "analyze",
               "correlate", "report")]

    def test_model_scales_with_discovered_files_and_bytes(self):
        small = CostModel(mode="url", max_files=50, timeout=15, workers=6)
        small.observe(stage="download", current=5, total=5, total_bytes=2_000_000,
                      stages=self.STAGES)
        big = CostModel(mode="url", max_files=50, timeout=15, workers=6)
        big.observe(stage="download", current=40, total=40, total_bytes=60_000_000,
                    stages=self.STAGES)
        self.assertGreater(big.remaining_seconds(), small.remaining_seconds(),
                           "more discovered bytes must mean a longer estimate")

    def test_model_scales_with_workers(self):
        few = CostModel(mode="url", max_files=20, timeout=15, workers=2)
        few.observe(stage="download", current=10, total=20, total_bytes=8_000_000,
                    stages=self.STAGES)
        many = CostModel(mode="url", max_files=20, timeout=15, workers=16)
        many.observe(stage="download", current=10, total=20, total_bytes=8_000_000,
                    stages=self.STAGES)
        self.assertLess(many.remaining_seconds(), few.remaining_seconds(),
                        "more workers must shrink the predicted remaining time")

    def test_model_confidence_grows_as_assumptions_become_measurements(self):
        model = CostModel(mode="url", max_files=50, timeout=15, workers=6)
        early = model.confidence()
        model.observe(stage="discover", current=12, total=12)
        mid = model.confidence()
        model.observe(stage="download", current=12, total=12,
                      total_bytes=12 * AVG_JS_BYTES)
        late = model.confidence()
        self.assertLess(early, mid)
        self.assertLess(mid, late)

    def test_job_eta_refuses_the_file_cap_as_workload(self):
        # A 6-script site scanned with a 500-file cap: the estimate must be
        # built from the 6 discovered scripts, not from the cap.
        job = Job(mode="url", max_files=500, timeout=15, max_workers=6)
        job.start()
        job.update(phase="analyze", stage="analyze", current=2, total=6,
                   percent=30.0, expected_files=6, total_bytes=1_500_000,
                   scanned_bytes=500_000, stages=self.STAGES)
        capped = Job(mode="url", max_files=500, timeout=15, max_workers=6)
        capped.start()
        capped.update(phase="analyze", stage="analyze", current=2, total=500,
                      percent=30.0, expected_files=500, total_bytes=125_000_000,
                      scanned_bytes=500_000, stages=self.STAGES)
        self.assertLess(job.snapshot()["eta_seconds"], capped.snapshot()["eta_seconds"])

    def test_eta_and_elapsed_stay_live_during_a_quiet_stage(self):
        job = Job(mode="url", max_files=50, timeout=15, max_workers=6)
        job.start()
        clock = [1_000_000.0]
        with mock.patch("core.jobs.time.time", lambda: clock[0]):
            job.update(phase="analyze", stage="analyze", current=10, total=23,
                       percent=55.0, expected_files=23,
                       total_bytes=10_000_000, scanned_bytes=4_000_000,
                       stages=self.STAGES)
            eta_then = job.snapshot()["eta_seconds"]
            elapsed_then = job.snapshot()["elapsed_ms"]
            # Five minutes of total silence: one huge bundle on one worker.
            clock[0] += 300.0
            snap = job.snapshot()
        self.assertIsNotNone(eta_then)
        # Elapsed must keep counting from the real start time...
        self.assertGreaterEqual(snap["elapsed_ms"], elapsed_then + 290_000)
        # ...and the estimate must hand priority to the workload model rather
        # than freeze (or keep claiming "2m left" while nothing moves).
        self.assertGreaterEqual(snap["eta_seconds"], eta_then - 1.0)
        self.assertLessEqual(snap["eta_seconds"], job._ETA_MAX_SECONDS * 2)

    def test_heartbeat_events_do_not_explode_the_estimate(self):
        job = Job(max_files=10)
        job.start()
        job.update(phase="analyze", stage="analyze", current=2, total=10,
                   percent=40.0)
        before = job.snapshot()["eta_seconds"]
        self.assertIsNotNone(before)
        for _ in range(8):
            time.sleep(0.04)
            # In-file heartbeat: the message changes, the fraction does not.
            job.update(message="Analyzing app.min.js - analyzer 3/10")
        after = job.snapshot()["eta_seconds"]
        self.assertIsNotNone(after)
        self.assertLessEqual(after, before * 2.0 + 5.0)

    def test_snapshot_exposes_the_estimate_inputs(self):
        job = Job(mode="url", max_files=50, timeout=15, max_workers=4)
        job.start()
        job.update(phase="download", stage="download", current=3, total=12,
                   percent=12.0, expected_files=12, total_bytes=3_000_000)
        snap = job.snapshot()
        self.assertEqual(snap["expected_files"], 12)
        self.assertEqual(snap["expected_bytes"], 3_000_000)
        self.assertTrue(snap["eta_basis"])


class AnalysisHeartbeatTest(unittest.TestCase):
    """Long single-file analyses must keep reporting liveness.

    The "28-minute silent analyze stage": a production minified bundle
    occupies one worker for minutes between the "Scanning x..." and
    "Analyzed x" events, and the dashboard could not tell that apart from a
    dead engine. Heavy passes inside scan_file now emit heartbeat events for
    large documents.
    """

    BIG_CONTENT = (
        "function f(a,b){var c=a+b;localStorage.setItem('k',a);"
        "document.getElementById('x').innerHTML=c;"
        "fetch('/api/v1/x',{headers:{Authorization:'Bearer abcdef123456789'}});}\n"
    ) * 1600  # ~200 KB, above HEARTBEAT_MIN_CHARS

    def test_large_documents_emit_pass_level_heartbeats(self):
        from core.scanner import HEARTBEAT_MIN_CHARS, scan_file
        self.assertGreaterEqual(len(self.BIG_CONTENT), HEARTBEAT_MIN_CHARS)
        events = []
        scan_file("app.min.js", content=self.BIG_CONTENT,
                  progress_heartbeat=events.append)
        self.assertTrue(any("analyzer" in e for e in events),
                        f"expected analyzer-pass heartbeats, got {events[:4]}")
        self.assertTrue(any("taint" in e for e in events))

    def test_small_documents_stay_quiet(self):
        events = []
        analyze_content(self.BIG_CONTENT[:500], filename="tiny.js",
                        progress_callback=lambda **kw: events.append(kw))
        messages = [str(c.get("message") or "") for c in events]
        self.assertFalse(any(m.startswith("Analyzing tiny.js - ") for m in messages),
                         "small files must not produce pass heartbeats")

    def test_large_pastes_surface_heartbeats_in_progress_events(self):
        calls = []
        analyze_content(self.BIG_CONTENT, filename="app.min.js",
                        progress_callback=lambda **kw: calls.append(kw))
        messages = [str(c.get("message") or "") for c in calls]
        self.assertTrue(any(m.startswith("Analyzing pasted JavaScript - ") for m in messages),
                        "heartbeat details must travel through the progress stream")
        # ...and the workload (byte size) must be reported for the ETA model.
        self.assertTrue(any(c.get("total_bytes", 0) > 0 for c in calls))


class StageEmissionTest(unittest.TestCase):

    def test_pasted_code_reports_stages(self):
        calls = []
        analyze_content(SAMPLE, filename="app.js",
                        progress_callback=lambda **kw: calls.append(kw))
        stages = [c.get("stage") for c in calls]
        self.assertIn("analyze", stages)
        self.assertIn("report", stages)
        # The phase contract used by existing consumers is preserved.
        self.assertIn("done", [c.get("phase") for c in calls])
        # Percent is supplied by the engine and never regresses.
        percents = [c.get("percent") for c in calls if c.get("percent") is not None]
        self.assertEqual(percents, sorted(percents))


class ReportAccuracyTest(unittest.TestCase):

    def _results(self):
        results = analyze_content(SAMPLE, filename="app.js")
        results["__scan_summary__"] = {
            "total_files": 1,
            "total_discovered": 4,
            "skipped_files": 3,
            "skipped_reasons": ["oversized_script", "duplicate_content"],
            "capped": True,
            "max_files": 1,
            "max_depth": 5,
            "bytes_scanned": len(SAMPLE),
            "total_bytes": len(SAMPLE),
            "path_to_url": {"app.js": "https://example.com/static/js/app.js"},
        }
        return results

    def test_findings_carry_their_origin_url(self):
        csv = generate_csv_report(self._results())
        self.assertIn("https://example.com/static/js/app.js", csv)

    def test_csv_has_no_python_reprs(self):
        for line in generate_csv_report(self._results()).splitlines():
            self.assertNotIn("['", line)
            self.assertNotIn("', '", line)

    def test_sarif_encodes_confidence_and_kind(self):
        sarif = json.loads(generate_sarif_report(self._results()))
        results = sarif["runs"][0]["results"]
        self.assertTrue(results)
        by_id = {r["ruleId"]: r for r in results}
        flow = by_id.get("dom_injection")
        self.assertIsNotNone(flow)
        self.assertEqual(flow["rank"], 75.0)          # high confidence
        self.assertEqual(flow["kind"], "open")
        self.assertEqual(flow["level"], "error")
        # An observation must not be exported as a failed check.
        observation = next((r for r in results if r["properties"].get("observation")), None)
        self.assertIsNotNone(observation)
        self.assertEqual(observation["level"], "note")
        self.assertEqual(observation["kind"], "informational")

    def test_sarif_points_at_the_origin_not_a_temp_path(self):
        sarif = json.loads(generate_sarif_report(self._results()))
        uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertTrue(uri.startswith("http"), uri)

    def test_reports_state_what_was_not_analyzed(self):
        model_report = generate_report(self._results())
        self.assertIn("SCAN COVERAGE & RELIABILITY", model_report)
        self.assertIn("1 of 4", model_report)
        self.assertIn("oversized script", model_report)
        self.assertIn("Confirmed proof", model_report)

    def test_reliability_rows_are_complete(self):
        from core.reporter import build_report_model
        model = build_report_model(self._results())
        rows = dict(scan_reliability(model, self._results()))
        self.assertIn("Coverage", rows)
        self.assertIn("Analysis engine", rows)
        self.assertIn("Runtime verification", rows)
        self.assertIn("Confidence mix", rows)


class ReportFileSafetyTest(unittest.TestCase):
    """Reports must never write outside the directory they were given."""

    def test_report_generation_does_not_touch_the_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            before = sorted(os.listdir(tmp))
            generate_report(self._results())
            generate_csv_report(self._results())
            generate_sarif_report(self._results())
            self.assertEqual(before, sorted(os.listdir(tmp)))

    def _results(self):
        return analyze_content(SAMPLE, filename="app.js")


if __name__ == "__main__":
    unittest.main()
