"""Self-tuning ETA calibration tests.

Pins the contract of core.eta_calibration (persisted per-machine correction
factors for the CPU-bound stage estimates) and its integration with
core.eta.CostModel and the Job recording hook:

  * observations fold into a bounded EWMA that CostModel applies;
  * ratios are clamped so one scan cannot wreck future estimates;
  * invalid samples (no files, tiny bytes, absurd durations) are rejected;
  * SCRIPTSENTRY_ETA_SELF_TUNING=0 disables recording and application;
  * a completed Job persists its measured stage durations exactly once.

Every test points SCRIPTSENTRY_STATE_DIR at its own temp directory so the
suite is hermetic and never reads a developer's real calibration.
"""
import json
import os
import tempfile
import unittest
from unittest import mock

from core import eta_calibration
from core.eta import CostModel
from core.jobs import Job

STAGES = [{"key": s, "state": "pending"} for s in
          ("recon", "discover", "download", "normalize", "analyze",
           "correlate", "report")]


class CalibrationBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="eta-cal-tests-")
        self.addCleanup(self._tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {"SCRIPTSENTRY_STATE_DIR": self._tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)

    def _model(self, **kw):
        model = CostModel(mode="url", max_files=50, timeout=15, workers=4, **kw)
        model.observe(stage="download", current=4, total=4, total_bytes=4_000_000,
                      expected_files=4, stages=STAGES)
        return model

    def _base_costs(self, model):
        return {stage: model._stage_cost(stage) for stage in ("analyze", "normalize")}


class RatioApplicationTest(CalibrationBase):
    def test_missing_file_means_untranslated_model(self):
        self.assertEqual(eta_calibration.ratio_for("analyze"), 1.0)
        model = self._model()
        base = self._base_costs(model)
        self.assertEqual(self._base_costs(self._model()), base)

    def test_observed_scan_adjusts_the_model(self):
        model = self._model()
        base = self._base_costs(model)
        # A machine 3x slower than the shipped calibration for analyze.
        recorded = eta_calibration.record_scan(
            {"analyze": base["analyze"] * 3.0},
            files_total=4, bytes_scanned=4_000_000, workers=4,
            base_cost=lambda stage: base[stage],
        )
        self.assertTrue(recorded)
        self.assertGreater(eta_calibration.ratio_for("analyze"), 1.0)
        warmed = self._base_costs(self._model())
        self.assertGreater(warmed["analyze"], base["analyze"])
        # ...and the correction moves toward, not past, the truth: one scan
        # applies a partial EWMA step.
        self.assertLess(warmed["analyze"], base["analyze"] * 3.0)

    def test_repeated_observations_converge(self):
        model = self._model()
        base = self._base_costs(model)
        for _ in range(6):
            eta_calibration.record_scan(
                {"analyze": base["analyze"] * 2.0},
                files_total=4, bytes_scanned=4_000_000, workers=4,
                base_cost=lambda stage: base[stage],
            )
        warmed = self._base_costs(self._model())
        self.assertAlmostEqual(warmed["analyze"] / base["analyze"], 2.0, delta=0.25)

    def test_ratios_are_clamped(self):
        model = self._model()
        base = self._base_costs(model)
        for _ in range(4):
            eta_calibration.record_scan(
                {"analyze": base["analyze"] * 1000.0},
                files_total=4, bytes_scanned=4_000_000, workers=4,
                base_cost=lambda stage: base[stage],
            )
        self.assertLessEqual(eta_calibration.ratio_for("analyze"), eta_calibration.RATIO_MAX)

    def test_engine_keyed_entries_are_independent(self):
        model = self._model()
        base = self._base_costs(model)
        eta_calibration.record_scan(
            {"analyze": base["analyze"] * 3.0},
            files_total=4, bytes_scanned=4_000_000, workers=4, engine="thread",
            base_cost=lambda stage: base[stage],
        )
        self.assertEqual(eta_calibration.ratio_for("analyze", engine="process"), 1.0)
        self.assertGreater(eta_calibration.ratio_for("analyze", engine="thread"), 1.0)


class SampleValidationTest(CalibrationBase):
    def test_trivial_workloads_are_not_recorded(self):
        model = self._model()
        base = self._base_costs(model)
        cases = [
            dict(stage_durations={"analyze": 5.0}, files_total=0,
                 bytes_scanned=4_000_000),
            dict(stage_durations={"analyze": 5.0}, files_total=4,
                 bytes_scanned=100.0),
            dict(stage_durations={"analyze": 0.05}, files_total=4,
                 bytes_scanned=4_000_000),
            dict(stage_durations={"analyze": 7200.0}, files_total=4,
                 bytes_scanned=4_000_000),
        ]
        for kwargs in cases:
            self.assertFalse(eta_calibration.record_scan(workers=4, base_cost=lambda s: base[s], **kwargs),
                             kwargs)
        self.assertEqual(self._base_costs(self._model()), base, "model must be untouched")

    def test_network_stages_are_never_tuned(self):
        model = self._model()
        base = self._base_costs(model)
        recorded = eta_calibration.record_scan(
            {"download": 999.0, "recon": 999.0},
            files_total=4, bytes_scanned=4_000_000, workers=4,
            base_cost=lambda stage: base.get(stage, 5.0),
        )
        self.assertFalse(recorded)
        self.assertFalse(os.path.exists(eta_calibration.state_path()))


class KillSwitchTest(CalibrationBase):
    def test_disabled_tuning_records_and_applies_nothing(self):
        model = self._model()
        base = self._base_costs(model)
        with mock.patch.dict(os.environ, {"SCRIPTSENTRY_ETA_SELF_TUNING": "0"}):
            recorded = eta_calibration.record_scan(
                {"analyze": base["analyze"] * 5.0},
                files_total=4, bytes_scanned=4_000_000, workers=4,
                base_cost=lambda stage: base[stage],
            )
            self.assertFalse(recorded)
            self.assertFalse(os.path.exists(eta_calibration.state_path()))
            self.assertEqual(eta_calibration.ratio_for("analyze"), 1.0)
        # A stored ratio still does not apply while the switch is off.
        os.makedirs(eta_calibration.state_path().rsplit("/", 1)[0], exist_ok=True)
        with open(eta_calibration.state_path(), "w", encoding="utf-8") as handle:
            json.dump({"version": 1,
                       "entries": {"analyze:process": {"ratio": 3.0, "samples": 2}}},
                      handle)
        with mock.patch.dict(os.environ, {"SCRIPTSENTRY_ETA_SELF_TUNING": "0"}):
            self.assertEqual(self._base_costs(self._model()), base)


class JobIntegrationTest(CalibrationBase):
    def test_completed_job_persists_stage_durations(self):
        job = Job(mode="url", max_files=50, timeout=15, max_workers=4)
        job.start()
        job.update(phase="analyze", stage="analyze", current=2, total=4,
                   percent=60.0, files_scanned=2, scanned_bytes=3_000_000,
                   total_bytes=4_000_000, stages=STAGES)
        # Backdate the stage start so the measured duration clears the
        # minimum-meaningful-work guard (a real analyze stage takes seconds).
        job._stage_started_ts["analyze"] -= 2.0
        job.complete({"__scan_summary__": {"total_files": 4, "bytes_scanned": 4_000_000}})
        self.assertTrue(os.path.exists(eta_calibration.state_path()))
        with open(eta_calibration.state_path(), encoding="utf-8") as handle:
            entries = json.load(handle)["entries"]
        self.assertTrue(any(key.startswith("analyze:") for key in entries), entries)

    def test_canceled_or_failed_jobs_record_nothing(self):
        job = Job(mode="url", max_files=50, timeout=15, max_workers=4)
        job.start()
        job.update(phase="analyze", stage="analyze", current=1, total=4,
                   percent=10.0, files_scanned=1, scanned_bytes=3_000_000,
                   total_bytes=4_000_000, stages=STAGES)
        job.fail("boom")
        self.assertFalse(os.path.exists(eta_calibration.state_path()))


if __name__ == "__main__":
    unittest.main()
