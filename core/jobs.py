"""Background scan-job state used by the web dashboard.

A URL scan can take a while when a site emits dozens of entry bundles plus
nested chunks. Instead of holding the HTTP request open, the server returns a
``job_id`` immediately and keeps a thread-local progress state here. The UI
polls ``/api/status`` and finally fetches ``/api/result``.

Only metadata and progress counters are kept here; the raw result is retained
until the job is explicitly cleared so report exports can reuse a completed
scan without re-crawling the remote site.
"""
import threading
import time
import uuid
from datetime import datetime, timezone

from core.eta import CostModel


class Job:
    """Mutable progress record for one background analysis."""

    def __init__(self, mode="code", source="", profile="", max_files=50, max_depth=5, timeout=15,
                 max_workers=None):
        self.id = uuid.uuid4().hex
        self.mode = mode
        self.source = source
        self.profile = profile
        self.max_files = int(max_files or 50)
        self.max_depth = int(max_depth or 5)
        self.timeout = int(timeout or 15)
        self.max_workers = max(1, int(max_workers or 6))
        self.status = "queued"
        self.phase = "queued"
        self.message = "Queued"
        self.current = 0
        self.total = 0
        self.percent = 0.0
        self.files_scanned = 0
        self.bytes_scanned = 0
        self.total_bytes = 0
        self.expected_files = 0
        self.skipped_files = 0
        self.elapsed_ms = 0
        self.eta_seconds = None
        self.eta_confidence = 0.0
        self.stage = ""
        self.stages = []
        self.result = None
        self.error = ""
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.started_at = None
        self.finished_at = None
        # Heartbeat: wall-clock time of the last progress event. The UI uses
        # the age to tell "working quietly on a big bundle" apart from
        # "contact with the engine was lost".
        self.last_update_ts = None
        # Wall-clock time the user requested cancellation (None until then).
        # The UI uses this to show "Canceling…" immediately and measure how
        # long the worker has taken to wind down, instead of looking stuck.
        self.cancel_requested_at = None
        self._lock = threading.Lock()
        self.cancel_event = threading.Event()
        # ETA state: a bounded window of (timestamp, fraction) samples plus an
        # exponential moving average of the observed progress rate, blended
        # with the workload cost model (core.eta) built from what the early
        # pipeline phases discovered (file count, bytes) and the scan settings
        # (profile caps, workers).
        self._samples = []
        self._rate_ema = None
        self._last_advance_ts = None   # last time the fraction actually grew
        self.eta_basis = ""
        self.cost_model = CostModel(
            mode=mode, max_files=self.max_files, max_depth=self.max_depth,
            timeout=self.timeout, workers=self.max_workers,
        )

    # Progress is now a weighted, monotonic fraction (see core.pipeline), so
    # the ETA only has to estimate how fast that fraction is moving.
    _ETA_WINDOW_SECONDS = 12.0     # how much history the rate is measured over
    _ETA_MIN_SAMPLE_SECONDS = 1.5  # below this the rate is noise, not signal
    _ETA_ALPHA = 0.35              # EMA weight of the newest rate measurement
    _ETA_RISE_LIMIT = 1.6          # an ETA may grow at most 1.6x per update...
    _ETA_RISE_SLACK = 3.0          # ...plus 3s, so a stall cannot explode it
    _ETA_MAX_SECONDS = 15 * 60.0
    _ETA_CONFIDENT_AT = 0.35       # fraction of work seen before we trust it
    _ETA_CONFIDENT_SECONDS = 8.0   # ...and how long we must have watched it
    # How quickly the observed rate goes stale while the engine is quiet.
    # exp(-quiet/45s) is ~0.75 after 13s and ~0.26 after a minute: past about
    # a minute of silence the workload model is the better-informed half.
    _ETA_STALENESS_TAU = 45.0

    def _update_eta_locked(self, append_sample=True, now=None):
        """Blend a workload cost model with the observed progress rate.

        The pure rate-based estimate (the old behaviour) needed to *watch*
        real progress for many seconds before it meant anything, and it froze
        completely while the engine was quiet -- a 2 MB bundle analyzed by one
        worker emits no events for minutes, so the dashboard happily showed
        ``eta ~2m left`` next to ``last update 28m ago``.

        The estimate is now a blend of two sources:

        * **Workload model** (:class:`core.eta.CostModel`) -- expected seconds
          left, computed from the files recon/discover found, the bytes
          download pulled, the stage plan, the profile timeouts and the
          worker count. Available from the first event; its confidence grows
          as assumptions (average file size) become measurements (real bytes).
        * **Observed rate** -- the old sliding-window EMA over fraction
          samples. Trustworthy only after enough progress has been seen
          (``eta_confidence``), and only while it is fresh: during a quiet
          stretch it decays (``staleness``) toward the model.

        ``append_sample=False`` is used by :meth:`snapshot` to refresh the
        estimate on every UI poll *without* polluting the measurement window.
        """
        live_now = time.time() if now is None else now
        fraction = max(0.0, min(1.0, float(self.percent or 0.0) / 100.0))

        if self.started_at is None or fraction <= 0.0:
            self.eta_seconds = None
            self.eta_confidence = 0.0
            self.eta_basis = ""
            return

        if append_sample:
            last = self._samples[-1] if self._samples else None
            # Record a sample only when the fraction actually moved, or when
            # the window's baseline has aged out. Heartbeat events (message
            # refreshes with no fraction change) must not dilute the rate.
            if (last is None
                    or fraction > last[1] + 1e-6
                    or live_now - last[0] >= self._ETA_WINDOW_SECONDS):
                grew = not self._samples or fraction > self._samples[-1][1] + 1e-6
                self._samples.append((live_now, fraction))
                if grew:
                    self._last_advance_ts = live_now
            cutoff = live_now - self._ETA_WINDOW_SECONDS
            while len(self._samples) > 2 and self._samples[0][0] < cutoff:
                self._samples.pop(0)

        # --- observed half -------------------------------------------------
        obs_eta = None
        obs_conf = 0.0
        weight_model = 1.0
        if self._samples:
            t_first, f_first = self._samples[0]
            t_last, f_last = self._samples[-1]
            dt = t_last - t_first
            if dt >= self._ETA_MIN_SAMPLE_SECONDS and f_last > f_first:
                rate = (f_last - f_first) / dt
            else:
                # Too little (or no) measurable movement inside the window:
                # fall back to the average rate since the start instead of
                # dividing by a number close to zero.
                dt = max(live_now - self.started_at, 0.001)
                rate = f_last / dt
            rate = max(rate, 1e-6)
            self._rate_ema = rate if self._rate_ema is None else (
                self._rate_ema + self._ETA_ALPHA * (rate - self._rate_ema))
            obs_eta = max(0.0, 1.0 - fraction) / max(self._rate_ema, 1e-6)
            # Confidence needs both: enough work observed and enough time
            # watched. A rate measured over 200 ms is a guess, whatever the
            # percentage says.
            obs_conf = min(
                1.0,
                fraction / self._ETA_CONFIDENT_AT,
                (live_now - self.started_at) / self._ETA_CONFIDENT_SECONDS,
            )

        # --- model half ----------------------------------------------------
        model = self.cost_model
        model.observe(
            stage=self.stage,
            current=self.current,
            total=self.total,
            total_bytes=self.total_bytes,
            bytes_scanned=self.bytes_scanned,
            expected_files=self.expected_files,
            stages=self.stages if isinstance(self.stages, list) else None,
        )
        model_eta = model.remaining_seconds()
        model_conf = model.confidence()

        quiet = max(0.0, live_now - (self._last_advance_ts or self.started_at))
        staleness = pow(2.718281828, -quiet / self._ETA_STALENESS_TAU)

        if obs_eta is None:
            eta = model_eta
            weight_model = 1.0
        else:
            # The measurement leads when it is confident and fresh; the model
            # leads early on and during long quiet stretches.
            weight_model = model_conf * (1.0 - obs_conf * staleness)
            weight_model = max(0.05, min(0.95, weight_model))
            eta = (1.0 - weight_model) * obs_eta + weight_model * model_eta

        # A growing workload estimate (nested chunks keep being discovered)
        # may raise the estimate, but never explosively; how fast the number
        # may climb scales with how much the model trusts itself.
        if self.eta_seconds is not None and eta > self.eta_seconds:
            rise_limit = self._ETA_RISE_LIMIT + 1.2 * model_conf
            slack = self._ETA_RISE_SLACK + 30.0 * model_conf
            eta = min(eta, self.eta_seconds * rise_limit + slack)
        # The ceiling scales with the workload: a strict 500-file scan has a
        # legitimately longer horizon than the old flat 15-minute cap.
        cap = max(self._ETA_MAX_SECONDS, min(3.0 * model_eta + 60.0, 90 * 60.0))
        self.eta_seconds = max(0.0, min(eta, cap))
        self.eta_confidence = round(max(obs_conf * staleness, model_conf * 0.9) * 0.95, 2)
        if obs_eta is None or weight_model >= 0.7:
            self.eta_basis = "workload model"
        elif weight_model >= 0.35:
            self.eta_basis = "blended"
        else:
            self.eta_basis = "observed rate"

    def update(self, **kwargs):
        with self._lock:
            now = time.time()
            if self.started_at is not None:
                self.elapsed_ms = int((now - self.started_at) * 1000)
            self.last_update_ts = now

            # While a cancel is winding down, keep refreshing the heartbeat and
            # counters (the worker is still alive), but do not let a late
            # progress event overwrite the "Canceling…" state the user just
            # asked for.
            if self.cancel_event.is_set():
                for key in ("current", "total", "files_scanned", "bytes_scanned",
                            "total_bytes", "skipped_files", "stage", "stages"):
                    if key in kwargs:
                        setattr(self, key, kwargs[key])
                if kwargs.get("percent") is not None:
                    self.percent = max(0.0, min(100.0, float(kwargs["percent"])))
                return

            for key in ("phase", "message", "current", "total", "files_scanned",
                        "bytes_scanned", "total_bytes", "skipped_files", "percent",
                        "stage", "stages"):
                if key in kwargs:
                    setattr(self, key, kwargs[key])
            if kwargs.get("expected_files") is not None:
                self.expected_files = max(
                    self.expected_files, int(kwargs["expected_files"] or 0))

            if kwargs.get("current") is not None and "files_scanned" not in kwargs:
                self.files_scanned = max(self.files_scanned, int(kwargs["current"] or 0))
            if kwargs.get("scanned_bytes") is not None and "bytes_scanned" not in kwargs:
                self.bytes_scanned = max(self.bytes_scanned, int(kwargs["scanned_bytes"] or 0))

            if kwargs.get("total_bytes") is not None:
                self.total_bytes = max(self.total_bytes, int(kwargs["total_bytes"] or 0))
            if kwargs.get("skipped") is not None:
                self.skipped_files = int(kwargs["skipped"] or 0)

            total = int(self.total or 0)
            if kwargs.get("percent") is not None:
                self.percent = max(0.0, min(100.0, float(kwargs["percent"])))
            elif total > 0:
                self.percent = max(0.0, min(100.0, (self.current / total) * 100.0))

            self._update_eta_locked()

    def start(self):
        with self._lock:
            if self.cancel_event.is_set():
                self.status = "canceled"
                self.phase = "canceled"
                self.message = "Canceled"
                self.finished_at = time.time()
                return False
            self.status = "running"
            self.phase = self.phase or "running"
            self.started_at = time.time()
            self.last_update_ts = self.started_at
            self.message = self.message or "Working…"
            return True

    def complete(self, result):
        with self._lock:
            if self.cancel_event.is_set():
                self.status = "canceled"
                self.phase = "canceled"
                self.message = "Canceled"
                self.finished_at = time.time()
                return
            self.result = result
            self.status = "done"
            self.phase = "done"
            self.percent = 100.0
            self.message = "Complete"
            self.finished_at = time.time()
            if self.started_at is not None:
                self.elapsed_ms = int((self.finished_at - self.started_at) * 1000)
            self.eta_seconds = 0.0
            summary = (result or {}).get("__scan_summary__") or {}
            self.files_scanned = int(summary.get("total_files", len(result or {})))
            self.bytes_scanned = int(summary.get("bytes_scanned", 0))
            self.total_bytes = int(summary.get("total_bytes", 0))
            self.skipped_files = int(summary.get("skipped_files", 0))
            self.eta_confidence = 1.0
            self._samples = []
            self._rate_ema = None

    def fail(self, error):
        with self._lock:
            if self.cancel_event.is_set():
                self.status = "canceled"
                self.phase = "canceled"
                self.message = "Canceled"
                self.error = ""
                self.finished_at = time.time()
                return
            self.status = "error"
            self.phase = "error"
            self.error = str(error)[:1000]
            self.finished_at = time.time()
            if self.started_at is not None:
                self.elapsed_ms = int((self.finished_at - self.started_at) * 1000)
            self.eta_seconds = None
            self.eta_confidence = 0.0
            self.eta_basis = ""

    def cancel(self):
        """Request cooperative cancellation; in-flight work stops at the next check.

        The worker observes ``cancel_event`` between downloads, between files
        and inside each file's analysis passes (see ``core.scanner``), so the
        scan winds down promptly.  Network calls are aborted by the
        ``safe_get`` watcher the moment the flag flips.
        """
        self.cancel_event.set()
        with self._lock:
            self.cancel_requested_at = time.time()
            if self.status == "queued":
                self.status = "canceled"
                self.phase = "canceled"
                self.message = "Canceled"
                self.finished_at = time.time()
            elif self.status == "running":
                self.phase = "canceling"
                self.message = "Canceling…"

    def snapshot(self, include_result=False):
        with self._lock:
            now = time.time()
            # Keep the clocks honest between engine events: elapsed advances
            # from the real start time, and the ETA is refreshed against the
            # current wall clock, so a long quiet stage no longer freezes
            # either number (the old panel could show "elapsed 4m" next to
            # "last update 28m ago").
            if self.status == "running" and self.started_at is not None:
                self.elapsed_ms = int((now - self.started_at) * 1000)
                if self.percent and self.percent > 0:
                    self._update_eta_locked(append_sample=False)
            since_update_ms = None
            if self.last_update_ts is not None:
                since_update_ms = max(0, int((now - self.last_update_ts) * 1000))
            data = {
                "id": self.id,
                "mode": self.mode,
                "source": self.source,
                "profile": self.profile,
                "status": self.status,
                "phase": self.phase,
                "message": self.message,
                "current": self.current,
                "total": self.total,
                "percent": round(self.percent, 2),
                "files_scanned": self.files_scanned,
                "bytes_scanned": self.bytes_scanned,
                "total_bytes": self.total_bytes,
                "skipped_files": self.skipped_files,
                "elapsed_ms": self.elapsed_ms,
                "eta_seconds": round(self.eta_seconds, 1) if self.eta_seconds is not None else None,
                "eta_confidence": self.eta_confidence,
                "eta_basis": self.eta_basis,
                "expected_files": int(max(self.cost_model.files_expected, self.expected_files) or 0),
                "expected_bytes": int(self.cost_model.bytes_expected or self.cost_model._bytes_estimate()),
                "stage": self.stage,
                "stages": self.stages,
                "since_update_ms": since_update_ms,
                "canceling": self.cancel_event.is_set() and self.status not in ("canceled", "done", "error"),
                "cancel_requested_at": self.cancel_requested_at,
                "error": self.error,
                "created_at": self.created_at,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
            }
            if include_result:
                data["result"] = self.result
            return data


class JobManager:
    """Thread-safe registry for background jobs."""

    def __init__(self, max_jobs=64, retention_seconds=3600):
        self._jobs = {}
        self._lock = threading.Lock()
        self._max_jobs = max(1, int(max_jobs))
        self._retention_seconds = max(60, int(retention_seconds))

    def _prune_locked(self):
        now = time.time()
        terminal = [
            job for job in self._jobs.values()
            if job.status in ("done", "error", "canceled")
        ]
        for job in terminal:
            if isinstance(job.finished_at, (int, float)) and now - job.finished_at > self._retention_seconds:
                self._jobs.pop(job.id, None)
        if len(self._jobs) < self._max_jobs:
            return
        # If the registry is full, evict the oldest terminal records first.
        terminal = sorted(
            (job for job in self._jobs.values() if job.status in ("done", "error", "canceled")),
            key=lambda job: job.finished_at if isinstance(job.finished_at, (int, float)) else 0,
        )
        while len(self._jobs) >= self._max_jobs and terminal:
            self._jobs.pop(terminal.pop(0).id, None)

    def create(self, mode="code", source="", profile="", max_files=50, max_depth=5, timeout=15,
               max_workers=None):
        job = Job(
            mode=mode,
            source=source,
            profile=profile,
            max_files=max_files,
            max_depth=max_depth,
            timeout=timeout,
            max_workers=max_workers,
        )
        with self._lock:
            self._prune_locked()
            if len(self._jobs) >= self._max_jobs:
                raise RuntimeError("The local engine is at its concurrent job limit; try again shortly.")
            self._jobs[job.id] = job
        return job

    def start(self, job_id, target, *args, **kwargs):
        job = self.get(job_id)
        if job is None:
            return None

        def runner():
            try:
                if not job.start():
                    return
                result = target(*args, **kwargs)
                job.complete(result)
            except Exception as exc:  # noqa: BLE001 - surfaced to dashboard
                job.fail(exc)

        thread = threading.Thread(target=runner, name=f"scriptsentry-job-{job_id[:8]}", daemon=True)
        thread.start()
        return thread

    def get(self, job_id):
        with self._lock:
            return self._jobs.get(job_id)

    def status(self, job_id):
        job = self.get(job_id)
        return job.snapshot(include_result=False) if job else None

    def result(self, job_id):
        job = self.get(job_id)
        if job is None:
            return None
        snap = job.snapshot(include_result=True)
        return snap.get("result")

    def cancel(self, job_id):
        job = self.get(job_id)
        if job is None:
            return False
        job.cancel()
        return True

    def clear(self, job_id):
        with self._lock:
            self._jobs.pop(job_id, None)

    def clear_all(self):
        with self._lock:
            self._jobs.clear()


jobs = JobManager()
