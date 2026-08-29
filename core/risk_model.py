"""Explainable, evidence-weighted overall risk score.

The old dashboard score was an unbounded count of signal categories with no
way to answer "why is this number 78?".  This module produces a bounded
0-100 score from **weighted, evidence-tiered contributors** and returns the
full contribution list so the dashboard and reports can explain the score.

Weights reflect the review's priority ordering:

  * demonstrated/strong evidence (source->sink flows, runtime effects) weighs
    far more than a regex signal;
  * third-party scripts reading sensitive data and sending it externally is a
    top contributor;
  * capability/inventory observations (API surface, obfuscation) weigh least.

Everything here is deterministic and pure, so it is trivially testable.
"""
from typing import Any, Dict, List, Optional

from core.analysis_model import (
    CONFIDENCE_RANK,
    SEVERITY_RANK,
    canonical_confidence,
    canonical_status,
    is_observation,
)


def _finding_tier(finding: Dict[str, Any]) -> int:
    """Return 0..3 for how proven a finding is (higher = more certain)."""
    conf = CONFIDENCE_RANK.get(canonical_confidence(finding.get("confidence")), 0)
    evidence = str(finding.get("evidence_type", ""))
    status = canonical_status(finding.get("status"))
    if status == "confirmed" or evidence == "runtime_effect" or conf >= CONFIDENCE_RANK["confirmed"]:
        return 3
    if evidence == "runtime_browser" or conf >= CONFIDENCE_RANK["high"]:
        return 2
    if conf >= CONFIDENCE_RANK["medium"]:
        return 1
    return 0


def _finding_severity_weight(finding: Dict[str, Any]) -> int:
    sev = SEVERITY_RANK.get(str(finding.get("severity", "")).upper(), 1)
    return {0: 1, 1: 2, 2: 4, 3: 7, 4: 10}.get(sev, 2)


# Per-finding risk contribution by evidence tier and severity impact.
# Rows are evidence tiers (proven -> heuristic), columns-ish by severity via
# _finding_severity_weight. This keeps "strong evidence of a bad thing" >>
# "weak hint of a mild thing".
_TIER_MULTIPLIER = {3: 1.0, 2: 0.75, 1: 0.45, 0: 0.2}


def overall_risk(
    findings: Optional[List[Dict[str, Any]]] = None,
    script_inventory: Optional[List[Dict[str, Any]]] = None,
    runtime: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return ``{score, label, contributors, counts}`` for a full scan.

    ``contributors`` is a sorted list of ``{label, points, count, tier}`` so
    callers can render a "+25 High-confidence source-to-sink flow" breakdown.
    """
    findings = findings or []
    script_inventory = script_inventory or []
    runtime = runtime or {}

    contributions: Dict[str, Dict[str, Any]] = {}

    def add(label, points, count=1, tier=0):
        bucket = contributions.setdefault(label, {"label": label, "points": 0, "count": 0, "tier": tier})
        bucket["points"] += points
        bucket["count"] += count
        bucket["tier"] = max(bucket["tier"], tier)

    counts = {
        "confirmed": 0,
        "high_confidence_flows": 0,
        "findings": 0,
        "observations": 0,
        "third_party_risky": 0,
        "third_party_exfil": 0,
        "runtime_effects": 0,
    }

    # ---- Per-finding contributions ------------------------------------
    seen = set()
    for f in findings:
        if not isinstance(f, dict):
            continue
        # Avoid double counting the same finding shape from two export paths.
        ident = (f.get("id"), f.get("file"), f.get("line"), str(f.get("sink", ""))[:80], str(f.get("source", ""))[:80])
        if ident in seen:
            continue
        seen.add(ident)

        observation = is_observation(f)
        tier = _finding_tier(f)
        sev_weight = _finding_severity_weight(f)
        evidence = str(f.get("evidence_type", ""))
        fid = str(f.get("id", ""))
        status = canonical_status(f.get("status"))

        if observation:
            counts["observations"] += 1
            # Observations contribute a small capped amount: they inform
            # posture but are not vulnerabilities.
            add("Security observations (API surface, obfuscation, inventory)", 1, tier=0)
            continue

        counts["findings"] += 1
        base = sev_weight * _TIER_MULTIPLIER.get(tier, 0.2) * 2.0

        if status == "confirmed" or evidence == "runtime_effect":
            counts["confirmed"] += 1
            counts["runtime_effects"] += 1 if "runtime" in evidence else 0
            add("Confirmed/demonstrated dangerous behavior", int(round(base)) + 6, tier=3)
        elif tier >= 2:
            if fid in ("dom_injection", "open_redirect", "data_exfiltration_flow", "dangerous_dynamic_code") or evidence == "source_to_sink":
                counts["high_confidence_flows"] += 1
                add("High-confidence source-to-sink flow", int(round(base)) + 4, tier=2)
            elif "runtime" in evidence:
                add("High-confidence runtime observation", int(round(base)) + 2, tier=2)
            else:
                add("High-confidence finding", int(round(base)) + 2, tier=2)
        elif fid in ("data_exfiltration_candidate",) or evidence == "behavioral_correlation":
            add("Sensitive data → external destination correlation", int(round(base)) + 3, tier=1)
        elif tier == 1:
            add("Needs-review finding (medium confidence)", int(round(base)) + 1, tier=1)
        else:
            add("Low-confidence signal on a high-impact pattern", max(2, int(round(base))), tier=0)

    # ---- Script intelligence contributions -----------------------------
    for script in script_inventory:
        if not isinstance(script, dict):
            continue
        risk = script.get("risk", {}) or {}
        score = int(risk.get("score", 0) or 0)
        caps = script.get("capabilities", {}) or {}
        party = script.get("party")
        reads = caps.get("reads", []) or []
        external = caps.get("external_destinations", []) or []
        if party == "third_party" and reads and external:
            counts["third_party_exfil"] += 1
            add("Third-party script reads sensitive data and sends data externally", min(18, 6 + score // 6), tier=1)
        elif party == "third_party" and score >= 40:
            counts["third_party_risky"] += 1
            add("High-risk third-party script", min(12, 4 + score // 10), tier=1)

    # ---- Runtime contributions ------------------------------------------
    if runtime.get("captured"):
        if runtime.get("eval_calls"):
            add("Runtime eval / dynamic execution observed", 8, count=len(runtime.get("eval_calls", [])), tier=3)
        if runtime.get("dom_sinks"):
            add("Runtime DOM sink writes observed", 5, count=len(runtime.get("dom_sinks", [])), tier=2)

    # ---- Assemble & normalize ------------------------------------------
    contributors = sorted(contributions.values(), key=lambda c: c["points"], reverse=True)
    raw = sum(c["points"] for c in contributors)
    score = max(0, min(100, int(round(raw))))

    if score >= 75 or counts["confirmed"] >= 2:
        label = "CRITICAL"
    elif score >= 55 or counts["confirmed"] >= 1:
        label = "HIGH"
    elif score >= 30 or counts["high_confidence_flows"] >= 1 or counts["findings"] >= 3:
        label = "MEDIUM"
    else:
        label = "LOW"

    return {
        "score": score,
        "label": label,
        "contributors": contributors,
        "counts": counts,
    }


def top_priorities(findings: List[Dict[str, Any]], script_inventory: Optional[List[Dict[str, Any]]] = None, limit: int = 5) -> List[Dict[str, Any]]:
    """Return the most important things an analyst should investigate first.

    Answers the dashboard's core question: "what should I investigate first?"
    """
    ranked = []
    for f in findings or []:
        if not isinstance(f, dict) or is_observation(f):
            continue
        tier = _finding_tier(f)
        sev = SEVERITY_RANK.get(str(f.get("severity", "")).upper(), 1)
        rank = tier * 10 + sev
        ranked.append((rank, f))
    ranked.sort(key=lambda x: x[0], reverse=True)

    priorities = []
    for _, f in ranked[:limit]:
        where = f.get("file", "") or ""
        line = f.get("line", 0)
        location = f"{where}:{line}" if line else where
        priorities.append({
            "type": f.get("type") or f.get("id") or "Finding",
            "severity": f.get("severity", "MEDIUM"),
            "confidence": canonical_confidence(f.get("confidence")),
            "status": canonical_status(f.get("status")),
            "location": location,
            "source": f.get("source", ""),
            "sink": f.get("sink", ""),
            "evidence_type": f.get("evidence_type", ""),
            "limitations": f.get("limitations", []) or [],
        })
    return priorities
