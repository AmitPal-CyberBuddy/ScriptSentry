"""Server-side triage: a decision follows a finding across scans.

The dashboard already let users cycle a finding's triage status, but the
decision lived in the *browser's* localStorage under a line-dependent key
(``id|file|line|sink``): move the finding one line and the decision was gone,
exports never saw it, and the "Your data" storage panel could not inspect or
delete it. This module moves triage server-side into the history database,
keyed by the engine's **line-independent finding fingerprint** -- the same
identity the history diff and baselines use -- so a decision follows the
finding across scans, line edits and machines that share the state dir.

Statuses match the vocabulary the UI already cycles:
``open`` / ``needs_review`` / ``confirmed`` / ``false_positive`` /
``informational``. They annotate reports (CSV column, SARIF property, TXT/HTML
marker); a ``false_positive`` additionally becomes a SARIF suppression, which
GitHub code scanning shows as a dismissed alert. Triage deliberately does
NOT change the ``--fail-on`` exit code -- gating is the baseline file's job
(a committed, reviewable artifact), and a local database on one machine
silently changing CI results would be a nasty surprise.
"""
import time

from core import history
from core.history import fingerprint

__all__ = [
    "TRIAGE_STATUSES", "annotate_findings", "clear_triage", "set_triage",
    "triage_map", "triage_count",
]

#: The exact vocabulary the UI's status cycle uses (10-findings.js).
TRIAGE_STATUSES = ("open", "needs_review", "confirmed", "false_positive", "informational")

#: Cap for the free-text note: it ships in every export that carries the
#: decision, so it cannot become an unbounded blob.
MAX_NOTE_LENGTH = 500


def _validated(status):
    value = str(status or "").strip().lower()
    if value not in TRIAGE_STATUSES:
        raise ValueError(
            f"triage status must be one of: {', '.join(TRIAGE_STATUSES)} (got {status!r})")
    return value


def triage_map():
    """All decisions as ``{fingerprint: {status, note, updated_at}}``.

    Read-only discipline (like ``storage_info``): never creates the database.
    """
    if not history.enabled() or not _db_exists():
        return {}
    with history.db_lock():
        try:
            rows = history.connection().execute(
                "SELECT fingerprint, status, note, updated_at FROM triage"
            ).fetchall()
        except Exception:
            return {}
    return {
        str(row[0]): {"status": row[1], "note": row[2] or "",
                      "updated_at": row[3]} for row in rows
    }


def triage_count():
    """Number of stored decisions (for the storage trust panel)."""
    if not _db_exists():
        return 0
    with history.db_lock():
        try:
            return int(history.connection().execute(
                "SELECT COUNT(*) FROM triage").fetchone()[0])
        except Exception:
            return 0


def set_triage(fingerprint_value, status, note=None):
    """Record (or replace) the decision for one finding fingerprint.

    Creating the DB here is correct (the user just made a real decision) --
    but never when history is disabled: that switch promises "store nothing".
    """
    if not history.enabled():
        raise ValueError("history is disabled on this engine (SCRIPTSENTRY_HISTORY=0); "
                         "triage decisions cannot be stored")
    key = str(fingerprint_value or "").strip()
    if not key or len(key) > 128:
        raise ValueError("a finding fingerprint is required (1-128 chars)")
    value = _validated(status)
    clean_note = ("" if note is None else str(note).strip())[:MAX_NOTE_LENGTH]
    with history.db_lock():
        history.connection().execute(
            "INSERT INTO triage (fingerprint, status, note, updated_at)"
            " VALUES (?, ?, ?, ?)"
            " ON CONFLICT(fingerprint) DO UPDATE SET"
            " status = excluded.status, note = excluded.note,"
            " updated_at = excluded.updated_at",
            (key, value, clean_note, time.time()),
        )
        history.connection().commit()
    return {"fingerprint": key, "status": value, "note": clean_note}


def clear_triage(fingerprint_value):
    """Remove the decision for one fingerprint; True if a row was deleted."""
    if not history.enabled() or not _db_exists():
        return False
    key = str(fingerprint_value or "").strip()
    if not key:
        raise ValueError("a finding fingerprint is required")
    with history.db_lock():
        cursor = history.connection().execute(
            "DELETE FROM triage WHERE fingerprint = ?", (key,))
        history.connection().commit()
        return cursor.rowcount > 0


def annotate_findings(findings, triage=None):
    """Stamp a finding list with its triage state (in place).

    Every dict finding gains ``triage_fp`` (the engine fingerprint, so the UI
    can address decisions), and — when a decision exists — ``triage_status``
    and ``triage_note``. Runs even with an empty map: the UI needs the
    fingerprint to POST a first decision.
    """
    decisions = triage if triage is not None else {}
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        try:
            key = fingerprint(finding)
        except Exception:
            continue
        finding["triage_fp"] = key
        entry = decisions.get(key)
        if entry:
            finding["triage_status"] = entry.get("status", "")
            finding["triage_note"] = entry.get("note", "") or ""
    return findings


def _db_exists():
    import os
    return os.path.isfile(history.db_path())
