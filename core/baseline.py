"""Baseline files: gate CI on what is actually *new*.

``--fail-on`` alone answers "are there findings?", which is the wrong question
for a codebase that has always had findings: the gate fires on every run and
gets muted. A baseline answers the question CI actually needs -- "is this run
worse than the accepted state?" -- the same way a test snapshot does:

* ``--save-baseline FILE`` writes this scan's finding fingerprints to a small,
  deterministic JSON file (sorted, no timestamps -- it diffs cleanly in a PR);
* ``--baseline FILE`` runs the ``--fail-on`` gate over only the findings that
  are **new** or **worsened** since that file. Known findings stay in every
  report (they are real; the report never lies), they just do not fail the
  build. Updating the baseline is a visible, reviewable act: commit the file.

Identity is the *history fingerprint* (finding id + document + sink/title,
deliberately line-independent -- see :mod:`core.history`), so a baseline, a
stored history row and a revalidation diff all agree on what "the same
finding" means. A finding that was an observation and came back actionable, or
came back at a higher severity, counts as *worsened* -- accepting a baseline
never accepts escalation.
"""
import json
import os
from typing import Any, Dict, List, Tuple

from core.analysis_model import SEVERITY_RANK
from core.history import _finding_rows, fingerprint

__all__ = ["write_baseline", "load_baseline", "gate_view", "BASELINE_VERSION"]

BASELINE_VERSION = 1


def write_baseline(results, path) -> int:
    """Write ``results``' finding fingerprints to ``path``; return the count.

    The file is deterministic (entries sorted by fingerprint, no timestamps)
    so two scans of identical code produce byte-identical baselines and a
    committed baseline shows clean diffs in review.
    """
    rows = sorted(_finding_rows(results), key=lambda pair: pair[0])
    payload = {
        "version": BASELINE_VERSION,
        "tool": "ScriptSentry",
        "findings": [
            {
                "fingerprint": fp,
                "id": row["finding_id"],
                "severity": row["severity"],
                "observation": bool(row["observation"]),
                "title": row["title"],
                "file": row["file"],
            }
            for fp, row in rows
        ],
    }
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return len(rows)


def load_baseline(path) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    """Read a baseline file into ``{fingerprint: row}`` plus any warnings.

    A missing file returns an empty mapping with a warning (not an error):
    the natural adoption flow is adding ``--baseline`` to CI before the file
    exists, and an empty baseline fails *harder* (every finding is new), so
    the safe direction is preserved. Unreadable/corrupt files are errors --
    silently ignoring a baseline someone tried to install would be the one
    dishonest outcome.
    """
    warnings: List[str] = []
    if not os.path.exists(path):
        return {}, [f"baseline file not found: {path} -- treating every finding as new "
                    f"(create one with --save-baseline {path})"]
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read baseline file {path}: {exc}") from exc
    findings = payload.get("findings") if isinstance(payload, dict) else None
    if not isinstance(findings, list):
        raise ValueError(f"baseline file {path} has no 'findings' list -- "
                         f"was it written by --save-baseline?")
    if payload.get("version") != BASELINE_VERSION:
        warnings.append(f"baseline file {path} has version {payload.get('version')!r}, "
                        f"expected {BASELINE_VERSION} -- attempting to read it anyway")
    baseline: Dict[str, Dict[str, Any]] = {}
    for entry in findings:
        if isinstance(entry, dict) and entry.get("fingerprint"):
            baseline[str(entry["fingerprint"])] = entry
    return baseline, warnings


def gate_view(results, baseline: Dict[str, Dict[str, Any]]):
    """Filter ``results`` to the findings that should count against the gate.

    Returns ``(view, stats)`` where ``view`` mirrors the results shape but
    keeps only actionable findings that are new (fingerprint absent from the
    baseline) or worsened (severity raised, or an observation that came back
    as a finding). ``worst_actionable_severity(view)`` then behaves exactly
    like the no-baseline gate. Known unchanged findings stay out of the view
    (and out of the gate) but, importantly, remain in the full report.
    """
    stats = {"known": 0, "new": 0, "worsened": 0}
    view: Dict[str, Any] = {}
    for key, document in results.items():
        if str(key).startswith("__") or not isinstance(document, dict):
            continue
        kept: List[dict] = []
        for finding in document.get("findings") or []:
            if not isinstance(finding, dict) or finding.get("observation"):
                continue  # observations never gate, with or without a baseline
            entry = dict(finding)
            entry.setdefault("file", document.get("loc_id") or key)
            fp = fingerprint(entry)  # same identity as history/diff
            known = baseline.get(fp)
            if known is None:
                stats["new"] += 1
                kept.append(finding)
                continue
            old_rank = SEVERITY_RANK.get(str(known.get("severity", "")).upper(), -1)
            new_rank = SEVERITY_RANK.get(str(finding.get("severity", "")).upper(), -1)
            if known.get("observation") or new_rank > old_rank:
                stats["worsened"] += 1
                kept.append(finding)
            else:
                stats["known"] += 1
        if kept:
            view[key] = {"findings": kept}
    return view, stats
