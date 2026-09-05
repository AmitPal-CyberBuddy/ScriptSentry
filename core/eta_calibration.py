"""Self-tuning ETA calibration, persisted per machine.

`core.eta`'s cost model ships with constants calibrated on one mid-range
laptop. Other machines (and the process engine) run the same scans at very
different speeds, so the estimator would start every scan with the same
systematic error. This module closes the loop: after each successful URL
scan the Job reports the *observed* wall-clock seconds of the CPU-bound
stages (analyze, normalize); we compare them with what the model predicted
for the same workload and fold the correction into a bounded EWMA that is
persisted to a small JSON file in the user's cache directory.

Design guards:

* only CPU-bound stages are tuned -- download/recon/verify times are
  network-bound and would teach the model about the wire, not the machine;
* every persisted ratio is clamped to ``[0.25, 4.0]`` so one pathological
  scan cannot wreck future estimates;
* a sample is only recorded for real work (>= 1 file, >= 50 KB, 0.5s..1h);
* ``SCRIPTSENTRY_ETA_SELF_TUNING=0`` disables recording and application.

State location: ``$SCRIPTSENTRY_STATE_DIR`` if set, else
``$XDG_CACHE_HOME/scriptsentry`` (default ``~/.cache/scriptsentry``).
"""
import json
import os
import tempfile
import time

__all__ = [
    "analyze_engine_name", "enabled", "ratio_for", "record_scan", "state_path",
]

#: Stages whose duration scales with machine speed (not the network).
TUNED_STAGES = ("analyze", "normalize")

RATIO_MIN = 0.25
RATIO_MAX = 4.0
EWMA_ALPHA = 0.35  # weight of each new correction; ~3 scans to converge

MIN_FILES = 1
MIN_BYTES = 50_000
MIN_SECONDS = 0.5
MAX_SECONDS = 3600.0


def _clamp(value, low, high):
    return max(low, min(high, value))


def enabled():
    return os.environ.get("SCRIPTSENTRY_ETA_SELF_TUNING", "1").strip().lower() \
        not in ("0", "false", "no", "off")


def analyze_engine_name():
    """The engine label calibration entries are keyed by."""
    return (os.environ.get("SCRIPTSENTRY_ANALYZE_ENGINE") or "process").strip().lower() or "process"


def state_path():
    override = os.environ.get("SCRIPTSENTRY_STATE_DIR")
    if override:
        return os.path.join(override, "eta_calibration.json")
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "scriptsentry", "eta_calibration.json")


def _load_entries():
    try:
        with open(state_path(), encoding="utf-8") as handle:
            raw = json.load(handle)
    except Exception:
        return {}
    entries = raw.get("entries") if isinstance(raw, dict) else None
    return entries if isinstance(entries, dict) else {}


def ratio_for(stage, engine=None):
    """Persisted multiplier for a stage's modeled duration (1.0 = untuned)."""
    if stage not in TUNED_STAGES or not enabled():
        return 1.0
    entry = _load_entries().get(f"{stage}:{engine or analyze_engine_name()}")
    if not isinstance(entry, dict):
        return 1.0
    try:
        return _clamp(float(entry["ratio"]), RATIO_MIN, RATIO_MAX)
    except (KeyError, TypeError, ValueError):
        return 1.0


def record_scan(stage_durations, files_total, bytes_scanned, workers, engine=None,
                base_cost=None):
    """Fold one completed scan's observed stage durations into the calibration.

    ``stage_durations`` maps stage key -> observed wall-clock seconds.
    ``base_cost(stage)`` must return the *uncalibrated* model seconds for the
    same workload, so corrections compose multiplicatively no matter what is
    already stored. Returns True when the state file was updated.
    """
    if not enabled():
        return False
    try:
        files_total = int(files_total or 0)
        bytes_scanned = float(bytes_scanned or 0)
        workers = max(1, int(workers or 1))
    except (TypeError, ValueError):
        return False
    if files_total < MIN_FILES or bytes_scanned < MIN_BYTES:
        return False

    engine = engine or analyze_engine_name()
    entries = _load_entries()
    updated = False
    for stage, observed in dict(stage_durations or {}).items():
        if stage not in TUNED_STAGES:
            continue
        try:
            observed = float(observed)
        except (TypeError, ValueError):
            continue
        if not (MIN_SECONDS <= observed <= MAX_SECONDS):
            continue
        try:
            base = float(base_cost(stage)) if base_cost is not None else 0.0
        except Exception:
            base = 0.0
        if base <= 0.05:  # too small a prediction to learn from
            continue

        key = f"{stage}:{engine}"
        entry = entries.get(key) if isinstance(entries.get(key), dict) else {}
        try:
            old_ratio = _clamp(float(entry.get("ratio", 1.0)), RATIO_MIN, RATIO_MAX)
        except (TypeError, ValueError):
            old_ratio = 1.0

        predicted = base * old_ratio
        correction = _clamp(observed / predicted, RATIO_MIN / 4.0, RATIO_MAX * 4.0)
        new_ratio = _clamp(old_ratio * (correction ** EWMA_ALPHA), RATIO_MIN, RATIO_MAX)
        entries[key] = {
            "ratio": round(new_ratio, 4),
            "samples": int(entry.get("samples", 0) or 0) + 1,
            "updated": round(time.time(), 3),
        }
        updated = True

    if not updated:
        return False
    try:
        directory = os.path.dirname(state_path())
        os.makedirs(directory, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".eta-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({"version": 1, "entries": entries}, handle)
        except Exception:
            os.unlink(tmp_path)
            return False
        os.replace(tmp_path, state_path())
        return True
    except Exception:
        return False
