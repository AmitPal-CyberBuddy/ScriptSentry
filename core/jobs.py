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


class Job:
    """Mutable progress record for one background analysis."""

    def __init__(self, mode="code", source="", profile="", max_files=50, max_depth=5, timeout=15):
        self.id = uuid.uuid4().hex
        self.mode = mode
        self.source = source
        self.profile = profile
        self.max_files = int(max_files or 50)
        self.max_depth = int(max_depth or 5)
        self.timeout = int(timeout or 15)
        self.status = "queued"
        self.phase = "queued"
        self.message = "Queued"
        self.current = 0
        self.total = 0
        self.percent = 0.0
        self.files_scanned = 0
        self.bytes_scanned = 0
        self.total_bytes = 0
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
        self._lock = threading.Lock()
        self.cancel_event = threading.Event()
        # ETA state: a bounded window of (timestamp, fraction) samples plus an
        # exponential moving average of the observed progress rate.
        self._samples = []
        self._rate_ema = None

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

    def _update_eta_locked(self):
        """Estimate the time remaining from the observed progress rate.

        The old calculation was ``elapsed * (100 - percent) / percent``. Two
        things made it useless in practice: ``percent`` used to be
        "files done / file cap" (a 4-script site reported 4% and therefore an
        ETA of 24x the elapsed time), and a single unsmoothed sample makes the
        number swing wildly between polls.

        This version measures progress over a sliding window, smooths the rate
        with an EMA, damps upward jumps, and reports how confident it is.
        """
        now = time.time()
        fraction = max(0.0, min(1.0, float(self.percent or 0.0) / 100.0))

        if self.started_at is None or fraction <= 0.0:
            self.eta_seconds = None
            self.eta_confidence = 0.0
            return

        self._samples.append((now, fraction))
        cutoff = now - self._ETA_WINDOW_SECONDS
        while len(self._samples) > 2 and self._samples[0][0] < cutoff:
            self._samples.pop(0)

        t_first, f_first = self._samples[0]
        t_last, f_last = self._samples[-1]
        dt = t_last - t_first
        if dt >= self._ETA_MIN_SAMPLE_SECONDS and f_last > f_first:
            rate = (f_last - f_first) / dt
        else:
            # Too little (or no) measurable movement inside the window: fall
            # back to the average rate since the start instead of dividing by
            # a number close to zero.
            dt = max(now - self.started_at, 0.001)
            rate = f_last / dt

        rate = max(rate, 1e-6)
        self._rate_ema = rate if self._rate_ema is None else (
            self._rate_ema + self._ETA_ALPHA * (rate - self._rate_ema))
        rate = max(self._rate_ema, 1e-6)

        eta = max(0.0, 1.0 - fraction) / rate
        if self.eta_seconds is not None and eta > self.eta_seconds:
            eta = min(eta, self.eta_seconds * self._ETA_RISE_LIMIT + self._ETA_RISE_SLACK)
        self.eta_seconds = max(0.0, min(eta, self._ETA_MAX_SECONDS))
        # Confidence needs both: enough work observed and enough time watched.
        # A rate measured over 200 ms is a guess, whatever the percentage says.
        self.eta_confidence = round(min(
            1.0,
            fraction / self._ETA_CONFIDENT_AT,
            (now - self.started_at) / self._ETA_CONFIDENT_SECONDS,
        ), 2)

    def update(self, **kwargs):
        if self.cancel_event.is_set():
            return
        with self._lock:
            now = time.time()
            if self.started_at is not None:
                self.elapsed_ms = int((now - self.started_at) * 1000)

            for key in ("phase", "message", "current", "total", "files_scanned",
                        "bytes_scanned", "total_bytes", "skipped_files", "percent",
                        "stage", "stages"):
                if key in kwargs:
                    setattr(self, key, kwargs[key])

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

    def cancel(self):
        """Request cooperative cancellation; active network calls finish at timeout."""
        self.cancel_event.set()
        with self._lock:
            if self.status == "queued":
                self.status = "canceled"
                self.phase = "canceled"
                self.message = "Canceled"
                self.finished_at = time.time()
            elif self.status == "running":
                self.message = "Canceling…"

    def snapshot(self, include_result=False):
        with self._lock:
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
                "stage": self.stage,
                "stages": self.stages,
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

    def create(self, mode="code", source="", profile="", max_files=50, max_depth=5, timeout=15):
        job = Job(
            mode=mode,
            source=source,
            profile=profile,
            max_files=max_files,
            max_depth=max_depth,
            timeout=timeout,
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
