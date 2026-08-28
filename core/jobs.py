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
        self.result = None
        self.error = ""
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.started_at = None
        self.finished_at = None
        self._lock = threading.Lock()

    def update(self, **kwargs):
        with self._lock:
            now = time.time()
            if self.started_at is not None:
                self.elapsed_ms = int((now - self.started_at) * 1000)

            for key in ("phase", "message", "current", "total", "files_scanned",
                        "bytes_scanned", "total_bytes", "skipped_files", "percent"):
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

            if self.percent > 0:
                # Use at least 1 ms so an immediate status update still yields
                # a meaningful (rather than None) first-pass ETA.
                elapsed = max(self.elapsed_ms, 1)
                self.eta_seconds = (elapsed * (100 - self.percent) / self.percent) / 1000.0
            else:
                self.eta_seconds = None

    def start(self):
        with self._lock:
            self.status = "running"
            self.phase = self.phase or "running"
            self.started_at = time.time()
            self.message = self.message or "Working…"

    def complete(self, result):
        with self._lock:
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

    def fail(self, error):
        with self._lock:
            self.status = "error"
            self.phase = "error"
            self.error = str(error)[:1000]
            self.finished_at = time.time()
            if self.started_at is not None:
                self.elapsed_ms = int((self.finished_at - self.started_at) * 1000)

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

    def __init__(self, max_jobs=200):
        self._jobs = {}
        self._lock = threading.Lock()
        self._max_jobs = max_jobs

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
            if len(self._jobs) >= self._max_jobs:
                # Drop the oldest finished job to keep the dashboard light.
                oldest = sorted(
                    (v for v in self._jobs.values() if v.status in ("done", "error")),
                    key=lambda j: j.created_at or "",
                )
                if oldest:
                    self._jobs.pop(oldest[0].id, None)
            self._jobs[job.id] = job
        return job

    def start(self, job_id, target, *args, **kwargs):
        job = self.get(job_id)
        if job is None:
            return None

        def runner():
            try:
                job.start()
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

    def clear(self, job_id):
        with self._lock:
            self._jobs.pop(job_id, None)

    def clear_all(self):
        with self._lock:
            self._jobs.clear()


jobs = JobManager()
