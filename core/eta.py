"""Workload-aware time-remaining estimates for scan jobs.

The old ETA measured nothing but the observed speed of the progress bar
(an EMA over ``fraction`` samples) and froze whenever the engine went quiet
-- which is exactly when a user stares at it, because a large minified
bundle can occupy one worker for minutes without emitting an event. It also
could not answer the obvious question ("what should this scan *cost*?"),
so a 23-file production bundle showed ``eta ~2m left`` alongside
``last update 28m ago``.

This module is the other half of the estimate: a **cost model** built from
what the earlier pipeline phases actually discovered --

  * how many files recon/discover found (bounded by the file cap),
  * how many bytes download pulled (or a per-file average before then),
  * the scan profile (timeouts, caps) and the worker count,

combined with throughput constants calibrated on real hardware (see
``CALIBRATION``). :class:`CostModel` answers "given this workload, how many
seconds of work are left?" and :meth:`CostModel.confidence` says how much
the model should be trusted. ``core.jobs.Job`` blends this with the
observed fraction velocity: the model leads early and during quiet stages,
the measurement takes over once enough real progress has been seen.

The constants are deliberately conservative (a slow laptop, not this
developer's machine) and can be tuned via environment variables without
touching code.
"""
import os

__all__ = ["CostModel", "AVG_JS_BYTES"]


def _env_float(name, default):
    try:
        value = float(os.environ.get(name, ""))
        return value if value > 0 else default
    except (TypeError, ValueError):
        return default


def _clamp(value, low, high):
    return max(low, min(high, value))


#: Typical minified bundle size assumed before the download stage reports
#: real byte counts. Deliberately on the large side of "marketing-site JS".
AVG_JS_BYTES = 300_000

# ---------------------------------------------------------------------------
# Calibration (single worker, mid-range laptop, CPython 3.11)
# ---------------------------------------------------------------------------
# Measured with core.scanner.scan_file over synthetic minified bundles:
#   0.27 MB -> ~2 s, 1.07 MB -> ~23 s  =>  seconds ~= 20 * MB^1.7 (superlinear:
# several passes scan the whole content, and minified content is few huge
# lines). With the optional AST parser the constant grows; the observed-rate
# half of the estimator corrects for machine differences either way.
ANALYZE_COEFF = _env_float("SCRIPTSENTRY_ETA_ANALYZE_COEFF", 20.0)
ANALYZE_EXPONENT = 1.7
#: Per-file scheduling/parse overhead that does not scale with bytes.
ANALYZE_FIXED_PER_FILE = _env_float("SCRIPTSENTRY_ETA_ANALYZE_FIXED", 0.35)
#: Beautifying measured ~380 MB/s; keep an order of magnitude of headroom.
NORMALIZE_MB_PER_SEC = 80.0
#: Effective parallel efficiency of the worker pool (GIL + I/O contention).
PARALLEL_EFFICIENCY = 0.8


class CostModel:
    """Estimate remaining scan seconds from the discovered workload.

    The model is fed the same progress events the job receives (stage,
    counters, stage states, byte totals) and keeps a small amount of state:

    ``files_expected``  workload discovered by recon/discover, capped by the
                        scan's file cap -- *not* the cap itself, which for a
                        4-script site would inflate the estimate 12x;
    ``bytes_expected``  real downloaded bytes once known, else
                        ``files_expected * AVG_JS_BYTES``;
    ``stage_fraction``  how far the active stage has progressed.

    :meth:`remaining_seconds` walks the stage plan (pending stages cost
    their full estimate, the active stage its unfinished share) and
    :meth:`confidence` rises as the workload becomes *measured* rather than
    assumed.
    """

    def __init__(self, mode="url", max_files=50, max_depth=5, timeout=15, workers=6):
        self.mode = str(mode or "url").lower()
        self.max_files = max(1, int(max_files or 50))
        self.max_depth = max(1, int(max_depth or 5))
        self.timeout = _clamp(float(timeout or 15), 2.0, 60.0)
        self.workers = max(1, int(workers or 1))
        self.files_expected = 1 if self.mode in ("code", "files", "upload") else 0
        self.bytes_expected = 0.0
        self.bytes_known = False
        self.bytes_done = 0.0
        self.stage = ""
        self.plan: list = []
        self.states: dict = {}
        self.stage_fraction: dict = {}
        self.files_done = 0

    # -- observation ------------------------------------------------------
    def observe(
        self,
        stage="",
        current=None,
        total=None,
        total_bytes=None,
        bytes_scanned=None,
        expected_files=None,
        stages=None,
    ):
        """Fold one progress event into the workload estimate."""
        if stages:
            # The engine's stage plan (with done/active/pending states) is the
            # authoritative pipeline shape -- it already knows whether the
            # runtime-verify stage is part of this scan.
            keys = []
            states = {}
            for entry in stages:
                if not isinstance(entry, dict):
                    continue
                key = str(entry.get("key") or "")
                if not key:
                    continue
                keys.append(key)
                states[key] = str(entry.get("state") or "pending")
            if keys:
                self.plan = keys
                self.states = states
        if stage:
            self.stage = str(stage)
        if total is not None and int(total) > 0 and self.stage in (
            "discover", "download", "normalize", "analyze",
        ):
            # Stage totals during these stages *are* the discovered workload
            # (the analyzer computes them from what was actually found).
            self.files_expected = max(self.files_expected, min(int(total), self.max_files))
        if expected_files is not None and int(expected_files) > 0:
            self.files_expected = max(self.files_expected, min(int(expected_files), self.max_files))
        if total_bytes is not None and float(total_bytes) > 1.0:
            self.bytes_expected = max(self.bytes_expected, float(total_bytes))
            self.bytes_known = True
        if bytes_scanned is not None and float(bytes_scanned) >= 0:
            self.bytes_done = max(self.bytes_done, float(bytes_scanned))
        if current is not None and int(current) > 0:
            self.files_done = max(self.files_done, int(current))
        if total is not None and int(total) > 0:
            self.stage_fraction[self.stage] = _clamp(int(current or 0) / float(total), 0.0, 1.0)

    # -- cost estimates ----------------------------------------------------
    def _bytes_estimate(self):
        if self.bytes_expected > 0:
            return self.bytes_expected
        if self.mode in ("code", "files", "upload"):
            return AVG_JS_BYTES
        return max(self.files_expected, 1) * AVG_JS_BYTES

    def _workers_for(self, files):
        """Parallel speedup is bounded by how many units of work exist."""
        return max(1.0, min(float(self.workers), max(1.0, float(files))) * PARALLEL_EFFICIENCY)

    def _stage_cost(self, key):
        """Expected wall-clock seconds for one stage of this scan."""
        files = max(1, self.files_expected)
        if key == "recon":
            # One page fetch (plus bot-protection latency), bounded by the
            # profile timeout.
            return _clamp(self.timeout * 0.6, 1.5, 15.0)
        if key == "discover":
            return 0.5 + 0.15 * files
        if key == "download":
            per_file = _clamp(self.timeout * 0.45, 0.75, 8.0)
            return per_file * files / self._workers_for(files)
        if key == "normalize":
            mb = self._bytes_estimate() / 1e6
            return 0.2 + mb / NORMALIZE_MB_PER_SEC / self._workers_for(files)
        if key == "analyze":
            mb = self._bytes_estimate() / 1e6
            # Superlinear in bundle size (whole-content passes over few huge
            # lines); parallel only across files.
            return (ANALYZE_FIXED_PER_FILE * files
                    + ANALYZE_COEFF * (mb ** ANALYZE_EXPONENT) / self._workers_for(files))
        if key == "correlate":
            return 0.4 + 0.02 * files
        if key == "verify":
            return self.timeout + 4.0
        if key == "report":
            return 0.3
        return 1.0

    def remaining_seconds(self):
        """Model-implied seconds of work left from here to the report."""
        plan = self.plan or self._default_plan()
        states = self.states or {}
        remaining = 0.0
        for key in plan:
            state = states.get(key, "pending")
            if state == "done":
                continue
            cost = self._stage_cost(key)
            if state == "active" or key == self.stage:
                fraction = self.stage_fraction.get(key)
                if fraction is None:
                    # Uncounted stage (e.g. recon with total=0): assume the
                    # half-way mark so the estimate does not stall at stage
                    # boundaries.
                    fraction = 0.5
                remaining += (1.0 - _clamp(fraction, 0.0, 1.0)) * cost
            else:
                remaining += cost
        return max(0.0, remaining)

    def _default_plan(self):
        if self.mode in ("code", "files", "upload"):
            return ["analyze", "correlate", "report"]
        return ["recon", "discover", "download", "normalize", "analyze", "correlate", "report"]

    def confidence(self):
        """0..1 trust in the model -- rises as assumptions become measurements."""
        if self.mode in ("code", "files", "upload"):
            # The workload is exactly what the user pasted/uploaded.
            conf = 0.55 if self.bytes_known else 0.35
            return _clamp(conf, 0.0, 0.85)
        conf = 0.2
        if self.files_expected > 0:
            conf += 0.25  # discovery reported a real file count
        if self.bytes_known:
            conf += 0.2   # download reported real bytes
        if self.stage in ("analyze", "correlate") and self.bytes_done > 0:
            conf += 0.2   # analysis is consuming measured bytes
        return _clamp(conf, 0.0, 0.85)
