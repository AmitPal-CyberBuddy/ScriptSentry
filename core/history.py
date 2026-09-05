"""Local scan history + diffing (SQLite), the monitoring half of ScriptSentry.

Every completed dashboard scan is recorded with its findings in a small
SQLite database under the shared state directory. Findings carry a
*cross-scan fingerprint* (finding id + document + sink/title -- deliberately
NOT the line number, which shifts with unrelated edits), so consecutive
scans of the same target can be answered with "3 new, 2 resolved since your
last scan".

Design notes:

* stdlib ``sqlite3`` with WAL; one file (``history.db``), no services.
* Recording never raises into the scan pipeline: a history failure must not
  turn a finished analysis into an error.
* ``SCRIPTSENTRY_HISTORY=0`` disables recording (diff/list still work).
* Retention: the newest ``SCRIPTSENTRY_HISTORY_MAX`` scans are kept
  (default 200); older rows are pruned after each insert.
* The full raw results of a scan are stored (capped) so a past scan can be
  re-rendered in the dashboard with the same code path as a live one.
"""
import contextlib
import hashlib
import json
import os
import sqlite3
import threading
import time

from core.state import state_dir

__all__ = [
    "diff_scans", "enabled", "fingerprint", "get_scan", "list_scans",
    "record_scan",
]

#: Findings/observations stored per scan; beyond this we keep the counts.
MAX_FINDINGS_PER_SCAN = 2000
#: Cap for the stored raw-results JSON (a hostile input cannot inflate the
#: database silently; past this only summary data is kept).
MAX_REPORT_BYTES = 16 * 1024 * 1024
NEW_LIST_CAP = 200

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    target TEXT NOT NULL,
    mode TEXT NOT NULL,
    duration_ms INTEGER,
    files_total INTEGER,
    bytes_total INTEGER,
    findings_total INTEGER,
    diff_json TEXT,
    report_json TEXT,
    report_stored INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS findings (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    finding_id TEXT,
    severity TEXT,
    confidence TEXT,
    title TEXT,
    file TEXT,
    detail TEXT,
    observation INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target, id);
"""

_LOCK = threading.Lock()
_LOCAL = threading.local()


def enabled():
    return os.environ.get("SCRIPTSENTRY_HISTORY", "1").strip().lower() \
        not in ("0", "false", "no", "off")


def db_path():
    return os.path.join(state_dir(), "history.db")


def _connect():
    conn = getattr(_LOCAL, "conn", None)
    path = db_path()
    if conn is not None and getattr(_LOCAL, "conn_path", None) != path:
        # The state dir moved (tests, env change): drop the old handle.
        with contextlib.suppress(Exception):
            conn.close()
        conn = None
    if conn is not None:
        return conn
    os.makedirs(state_dir(), exist_ok=True)
    conn = sqlite3.connect(path, timeout=5.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(_SCHEMA)
    _LOCAL.conn = conn
    _LOCAL.conn_path = path
    return conn


def fingerprint(finding):
    """Stable cross-scan identity of one finding.

    id + document + sink/title. Line numbers are excluded on purpose: an
    unrelated edit above the finding must not flip it to "new"/"resolved".
    """
    def part(value):
        return str(value or "").strip().lower()

    sink = ""
    source = ""
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), list) else []
    for item in evidence:
        if isinstance(item, str) and " -> " in item:
            left, _, right = item.partition(" -> ")
            source = source or left
            sink = sink or right
            break
    raw = "|".join((
        part(finding.get("id") or finding.get("type")),
        part(finding.get("file")),
        part(sink or finding.get("sink")),
        part(finding.get("title")),
        part(source or finding.get("source_label")),
    ))
    return hashlib.sha1(raw.encode("utf-8", errors="replace")).hexdigest()


def _finding_rows(results):
    """Flatten a raw results dict into (fingerprint, row) tuples."""
    rows = []
    for key, document in results.items():
        if key.startswith("__") or not isinstance(document, dict):
            continue
        doc_name = document.get("loc_id") or key
        for finding in document.get("findings", []) or []:
            if not isinstance(finding, dict):
                continue
            entry = dict(finding)
            entry.setdefault("file", doc_name)
            rows.append((
                fingerprint(entry),
                {
                    "finding_id": str(entry.get("id") or entry.get("type") or "")[:120],
                    "severity": str(entry.get("severity") or "")[:12],
                    "confidence": str(entry.get("confidence") or "")[:12],
                    "title": str(entry.get("title") or entry.get("type") or "")[:200],
                    "file": str(entry.get("file") or "")[:200],
                    "detail": str(entry.get("sink") or (entry.get("evidence") or [""])[0]
                               if isinstance(entry.get("evidence"), list) and entry.get("evidence")
                               else entry.get("sink") or "")[:200],
                    "observation": 1 if entry.get("observation") else 0,
                },
            ))
            if len(rows) >= MAX_FINDINGS_PER_SCAN:
                return rows
    return rows


def record_scan(results, mode="url", target="", duration_ms=None):
    """Store a completed scan; returns the history info dict (or None).

    The returned dict is attached to the scan results as ``__history__`` and
    carries the diff against the previous scan of the same target.
    """
    if not enabled() or not isinstance(results, dict):
        return None
    summary = results.get("__scan_summary__") or {}
    try:
        duration_ms = int(duration_ms) if duration_ms is not None else None
    except (TypeError, ValueError):
        duration_ms = None

    rows = _finding_rows(results)
    try:
        report_json = json.dumps(results, ensure_ascii=False, default=str)
    except Exception:
        report_json = ""
    report_stored = 1 if len(report_json) <= MAX_REPORT_BYTES else 0
    if not report_stored:
        report_json = ""

    with _LOCK:
        try:
            conn = _connect()
            cur = conn.cursor()
            cur.execute("SELECT id FROM scans WHERE target = ? ORDER BY id DESC LIMIT 1",
                        (str(target or ""),))
            previous = cur.fetchone()
            previous_id = previous[0] if previous else None
            previous_fp = set()
            if previous_id is not None:
                previous_fp = {
                    row[0] for row in cur.execute(
                        "SELECT fingerprint FROM findings WHERE scan_id = ?",
                        (previous_id,))
                }
            current_fp = {fp for fp, _ in rows}
            new_fp = current_fp - previous_fp
            resolved_fp = previous_fp - current_fp
            unchanged = len(current_fp & previous_fp)
            diff = {
                "previous_scan_id": previous_id,
                "new": sorted(new_fp)[:NEW_LIST_CAP],
                "resolved": sorted(resolved_fp)[:NEW_LIST_CAP],
                "new_count": len(new_fp),
                "resolved_count": len(resolved_fp),
                "unchanged_count": unchanged,
            }
            cur.execute(
                "INSERT INTO scans (created_at, target, mode, duration_ms, files_total,"
                " bytes_total, findings_total, diff_json, report_json, report_stored)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (time.time(), str(target or ""), str(mode or "url"), duration_ms,
                 int(summary.get("total_files", len([k for k in results if not k.startswith("__")])) or 0),
                 int(summary.get("bytes_scanned", 0) or 0),
                 len(rows), json.dumps(diff), report_json, report_stored))
            scan_id = cur.lastrowid
            conn.executemany(
                "INSERT INTO findings (scan_id, fingerprint, finding_id, severity,"
                " confidence, title, file, detail, observation)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [(scan_id, fp, row["finding_id"], row["severity"], row["confidence"],
                  row["title"], row["file"], row["detail"], row["observation"])
                 for fp, row in rows])
            cur.execute("UPDATE scans SET diff_json = ? WHERE id = ?",
                        (json.dumps({**diff, "scan_id": scan_id}), scan_id))
            conn.commit()
            _prune_locked(cur, conn)
            return {"scan_id": scan_id, "target": str(target or ""), **diff}
        except Exception:
            return None


def _prune_locked(cur, conn):
    try:
        keep = max(10, int(os.environ.get("SCRIPTSENTRY_HISTORY_MAX", "200")))
    except (TypeError, ValueError):
        keep = 200
    cur.execute(
        "DELETE FROM scans WHERE id NOT IN"
        " (SELECT id FROM scans ORDER BY id DESC LIMIT ?)", (keep,))
    conn.commit()


def list_scans(limit=50, target=None):
    """Newest-first scan summaries (no report bodies)."""
    try:
        limit = max(1, min(int(limit or 50), 200))
    except (TypeError, ValueError):
        limit = 50
    with _LOCK:
        try:
            conn = _connect()
            if target:
                cur = conn.execute(
                    "SELECT id, created_at, target, mode, duration_ms, files_total,"
                    " bytes_total, findings_total, diff_json FROM scans"
                    " WHERE target = ? ORDER BY id DESC LIMIT ?",
                    (str(target), limit))
            else:
                cur = conn.execute(
                    "SELECT id, created_at, target, mode, duration_ms, files_total,"
                    " bytes_total, findings_total, diff_json FROM scans"
                    " ORDER BY id DESC LIMIT ?", (limit,))
            out = []
            for row in cur.fetchall():
                entry = dict(zip(
                    ("scan_id", "created_at", "target", "mode", "duration_ms",
                     "files_total", "bytes_total", "findings_total"), row[:8], strict=False))
                try:
                    entry["diff"] = json.loads(row[8] or "null")
                except Exception:
                    entry["diff"] = None
                out.append(entry)
            return out
        except Exception:
            return []


def get_scan(scan_id, include_report=False):
    """One scan's summary; with ``include_report`` also its raw results."""
    try:
        scan_id = int(scan_id)
    except (TypeError, ValueError):
        return None
    with _LOCK:
        try:
            conn = _connect()
            cur = conn.execute(
                "SELECT id, created_at, target, mode, duration_ms, files_total,"
                " bytes_total, findings_total, diff_json, report_json, report_stored"
                " FROM scans WHERE id = ?", (scan_id,))
            row = cur.fetchone()
            if row is None:
                return None
            entry = dict(zip(
                ("scan_id", "created_at", "target", "mode", "duration_ms",
                 "files_total", "bytes_total", "findings_total"), row[:8], strict=False))
            try:
                entry["diff"] = json.loads(row[8] or "null")
            except Exception:
                entry["diff"] = None
            entry["report_stored"] = bool(row[10])
            if include_report and row[10]:
                try:
                    entry["report"] = json.loads(row[9] or "null")
                except Exception:
                    entry["report"] = None
            return entry
        except Exception:
            return None


def diff_scans(from_id, to_id):
    """Compare two stored scans by fingerprint (order-independent ids)."""
    try:
        from_id, to_id = int(from_id), int(to_id)
    except (TypeError, ValueError):
        return None
    with _LOCK:
        try:
            conn = _connect()
            def _fps(scan_id):
                return {row[0] for row in conn.execute(
                    "SELECT fingerprint FROM findings WHERE scan_id = ?", (scan_id,))}
            old, new = _fps(from_id), _fps(to_id)
            return {
                "from_scan_id": from_id,
                "to_scan_id": to_id,
                "new_count": len(new - old),
                "resolved_count": len(old - new),
                "unchanged_count": len(old & new),
                "new": sorted(new - old)[:NEW_LIST_CAP],
                "resolved": sorted(old - new)[:NEW_LIST_CAP],
            }
        except Exception:
            return None
