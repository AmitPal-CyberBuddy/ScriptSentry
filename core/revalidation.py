"""Finding revalidation: what happened to the initial findings on re-scan.

A plain count diff ("+3 new / −2 resolved") answers almost nothing a security
team actually asks:

* which of the *initial* findings are still there?
* did any of them get worse (or better) while persisting?
* is "resolved" really fixed, or did the scan simply not see that file again?

This module joins two stored scans on the history **fingerprint** (finding id
+ document + sink/title — deliberately line-independent, so an unrelated edit
above a finding does not flip it to "new"/"resolved") and produces per-finding
verdicts plus a plain-language summary. Verdict vocabulary:

* ``persisted``   — same finding is detected again (sub-classified as
                    ``worsened`` / ``improved`` / ``unchanged`` by severity,
                    confidence and finding-vs-observation transitions);
* ``resolved``    — no longer detected. Stated honestly as "no longer
                    detected", never "fixed": static analysis can only report
                    what it can see;
* ``new``         — first seen in the newer scan.

Coverage honesty: when the newer scan saw only some of the previously analyzed
files (different page set, crawl cap, partial deploy), "resolved" would be a
lie by omission — the summary says so explicitly and the comparison is marked
``partial``.

Everything here is deterministic and pure over history rows, so it is trivial
to test and cheap to call from the diff API.
"""
from typing import Any, Dict, List, Optional

from core.analysis_model import CONFIDENCE_RANK, SEVERITY_RANK

__all__ = ["revalidate_rows", "summarize_revalidation"]

# Verdicts, in the order the UI renders them.
VERDICT_ORDER = ("worsened", "persisted", "new", "improved", "resolved")


def _rank_severity(value) -> int:
    return SEVERITY_RANK.get(str(value or "").upper(), 1)


def _rank_confidence(value) -> int:
    return CONFIDENCE_RANK.get(str(value or "").lower(), 0)


def revalidate_rows(old_rows: List[Dict[str, Any]], new_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compare two scans' finding rows (as stored in history).

    Each row is a dict with at least ``fingerprint``; ``severity``,
    ``confidence``, ``title``, ``file``, ``finding_id``, ``observation`` and
    ``detail`` are used when present. Returns verdict lists + counters.
    """
    old_by_fp = {row["fingerprint"]: row for row in old_rows if isinstance(row, dict) and row.get("fingerprint")}
    new_by_fp = {row["fingerprint"]: row for row in new_rows if isinstance(row, dict) and row.get("fingerprint")}

    verdicts: List[Dict[str, Any]] = []
    counts = {"persisted": 0, "worsened": 0, "improved": 0, "resolved": 0, "new": 0}

    def _base(row, verdict):
        return {
            "verdict": verdict,
            "finding_id": str(row.get("finding_id") or row.get("id") or "finding"),
            "title": str(row.get("title") or row.get("finding_id") or "Finding"),
            "file": str(row.get("file") or ""),
            "severity": str(row.get("severity") or "MEDIUM").upper(),
            "confidence": str(row.get("confidence") or "low").lower(),
            "observation": bool(row.get("observation")),
            "detail": str(row.get("detail") or "")[:160],
        }

    # Findings present in both: persisted, sub-classified by what changed.
    for fp, new_row in new_by_fp.items():
        old_row = old_by_fp.get(fp)
        if old_row is None:
            counts["new"] += 1
            verdicts.append(_base(new_row, "new"))
            continue
        entry = _base(new_row, "persisted")
        entry["previous_severity"] = str(old_row.get("severity") or "MEDIUM").upper()
        entry["previous_confidence"] = str(old_row.get("confidence") or "low").lower()
        sev_delta = _rank_severity(new_row.get("severity")) - _rank_severity(old_row.get("severity"))
        conf_delta = _rank_confidence(new_row.get("confidence")) - _rank_confidence(old_row.get("confidence"))
        was_observation = bool(old_row.get("observation"))
        is_observation = bool(new_row.get("observation"))
        # Say *what* moved: a verdict without its reason is a black box.
        changes = []
        if sev_delta:
            changes.append(f"severity {entry['previous_severity']}->{entry['severity']}")
        if conf_delta:
            changes.append(f"confidence {entry['previous_confidence']}->{entry['confidence']}")
        if was_observation and not is_observation:
            changes.append("upgraded from observation to actionable finding")
        if not was_observation and is_observation:
            changes.append("downgraded from actionable finding to observation")
        entry["change"] = "; ".join(changes)
        if sev_delta > 0 or (was_observation and not is_observation) or conf_delta > 0:
            entry["verdict"] = "worsened"
            counts["worsened"] += 1
        elif sev_delta < 0 or (not was_observation and is_observation) or conf_delta < 0:
            entry["verdict"] = "improved"
            counts["improved"] += 1
        else:
            counts["persisted"] += 1
        verdicts.append(entry)

    # Findings only in the old scan: no longer detected.
    for fp, old_row in old_by_fp.items():
        if fp not in new_by_fp:
            counts["resolved"] += 1
            entry = _base(old_row, "resolved")
            entry["detail"] = f"No longer detected in the newer scan. {entry['detail']}".strip()
            verdicts.append(entry)

    order = {name: i for i, name in enumerate(VERDICT_ORDER)}
    verdicts.sort(key=lambda v: (
        -_rank_severity(v.get("severity")),
        order.get(v.get("verdict"), 9),
        str(v.get("file", "")),
    ))

    # Coverage: which previously-seen files did the newer scan see again?
    old_files = {str(r.get("file") or "") for r in old_by_fp.values() if r.get("file")}
    new_files = {str(r.get("file") or "") for r in new_by_fp.values() if r.get("file")}
    seen_again = old_files & new_files
    coverage = {
        "previous_files": len(old_files),
        "seen_again": len(seen_again),
        "partial": bool(old_files) and len(seen_again) < len(old_files),
        "missing_files": sorted(old_files - new_files)[:20],
    }
    return {"verdicts": verdicts, "counts": counts, "coverage": coverage}


def _severity_mix(rows) -> str:
    counts: Dict[str, int] = {}
    for row in rows or []:
        sev = str(row.get("severity") or "MEDIUM").upper()
        counts[sev] = counts.get(sev, 0) + 1
    if not counts:
        return "no findings"
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    return ", ".join(f"{counts[s]} {s.lower()}" for s in order if counts.get(s))


def summarize_revalidation(comparison: Dict[str, Any], old_rows, new_rows,
                           previous_scan_id=None, scan_id=None) -> Dict[str, Any]:
    """Wrap :func:`revalidate_rows` output in the payload the API returns.

    Keeps the legacy count keys (``new_count`` / ``resolved_count`` /
    ``unchanged_count``) so existing consumers keep working, and adds the
    verdict list, coverage honesty and a plain-language summary.
    """
    counts = comparison["counts"]
    coverage = comparison["coverage"]
    verdicts = comparison["verdicts"]

    initial_total = counts["persisted"] + counts["worsened"] + counts["improved"] + counts["resolved"]
    still_present = counts["persisted"] + counts["worsened"] + counts["improved"]

    lines = []
    if initial_total == 0 and counts["new"] == 0:
        lines.append("No findings were recorded in either scan — nothing to revalidate.")
    else:
        if initial_total:
            parts = [f"{still_present} of the {initial_total} initial finding(s) are still present"]
            if counts["worsened"]:
                parts.append(f"{counts['worsened']} got worse")
            if counts["improved"]:
                parts.append(f"{counts['improved']} improved")
            lines.append(", ".join(parts[:-1]) + (" and " + parts[-1] if len(parts) > 1 else parts[0]) + ".")
        else:
            lines.append("The previous scan recorded no findings.")
        if counts["resolved"]:
            lines.append(f"{counts['resolved']} initial finding(s) are no longer detected — most likely fixed, "
                         "but see the coverage note before calling them fixed.")
        if counts["new"]:
            lines.append(f"{counts['new']} finding(s) appear for the first time in the newer scan.")
        lines.append(f"Severity mix was {_severity_mix(old_rows)}; it is now {_severity_mix(new_rows)}.")
    if coverage["partial"]:
        lines.append(f"Comparison is partial: the newer scan saw {coverage['seen_again']} of the "
                     f"{coverage['previous_files']} file(s) that carried findings last time "
                     "(different page set, crawl cap or partial deploy) — treat 'no longer detected' "
                     "for those files as unknown, not fixed.")

    return {
        "previous_scan_id": previous_scan_id,
        "scan_id": scan_id,
        # Legacy keys (existing UI/exports consume these).
        "new_count": counts["new"],
        "resolved_count": counts["resolved"],
        "unchanged_count": counts["persisted"] + counts["worsened"] + counts["improved"],
        # New, richer contract.
        "counts": counts,
        "coverage": coverage,
        "verdicts": verdicts[:100],
        "summary": " ".join(lines),
        "summary_lines": lines,
    }


def revalidate_scans(from_id, to_id) -> Optional[Dict[str, Any]]:
    """Revalidate findings between two stored scans (history DB).

    Returns the full revalidation payload, or ``None`` when either scan id is
    unknown.
    """
    try:
        from core import history
        old_rows = history.finding_rows(from_id)
        new_rows = history.finding_rows(to_id)
    except Exception:  # noqa: BLE001 - unknown ids / storage problems degrade to None
        return None
    if old_rows is None or new_rows is None:
        return None
    comparison = revalidate_rows(old_rows, new_rows)
    return summarize_revalidation(comparison, old_rows, new_rows,
                                  previous_scan_id=from_id, scan_id=to_id)
