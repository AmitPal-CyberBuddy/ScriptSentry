"""Shared analysis model and correlation helpers.

This module is deliberately small. It contains the vocabulary used by every
detector (severity, confidence, status) and the correlation/deduplication logic
that turns raw detector output into a clean, tester-facing finding list.

Keeping this in one place makes it easy to:
  * keep severity/confidence semantics consistent between scanners, reports and
    the dashboard,
  * deduplicate overlapping evidence (source-to-sink flows, framework rules,
    coarse risk signals),
  * preserve structured evidence for manual verification.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
STATUS_RANK = {"informational": 0, "potential": 1, "needs_review": 2, "confirmed": 3}


@dataclass
class Finding:
    """Minimal internal representation of a correlated finding."""

    id: str
    type: str
    severity: str = "MEDIUM"
    confidence: str = "medium"
    status: str = "potential"
    file: str = ""
    line: int = 0
    source: str = ""
    sink: str = ""
    flow: List[str] = field(default_factory=list)
    evidence: Any = ""
    sanitization_detected: bool = False
    framework: str = ""
    evidence_type: str = "static_pattern"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "severity": self.severity,
            "confidence": self.confidence,
            "status": self.status,
            "file": self.file,
            "line": self.line,
            "source": self.source,
            "sink": self.sink,
            "flow": list(self.flow or []),
            "evidence": self.evidence,
            "sanitization_detected": bool(self.sanitization_detected),
            "framework": self.framework,
            "evidence_type": self.evidence_type,
        }


def _confidence_for_severity(severity: str) -> str:
    severity = str(severity or "MEDIUM").upper()
    return "high" if severity in ("CRITICAL", "HIGH") else ("medium" if severity == "MEDIUM" else "low")


def _status_for_confidence(confidence: str) -> str:
    return "confirmed" if confidence == "high" else ("potential" if confidence == "medium" else "informational")


def normalize_finding(
    finding: Dict[str, Any],
    fallback_file: str = "",
    default_evidence_type: str = "static_pattern",
) -> Dict[str, Any]:
    """Return a finding with all fields present and a predictable shape."""
    out = dict(finding or {})
    out.setdefault("id", str(out.get("type") or out.get("name") or "finding"))
    out.setdefault("type", out.get("id", "finding"))
    out.setdefault("severity", "MEDIUM")
    out.setdefault("confidence", _confidence_for_severity(out["severity"]))
    out.setdefault("status", _status_for_confidence(out["confidence"]))
    out.setdefault("file", fallback_file)
    out.setdefault("line", 0)
    out.setdefault("source", "")
    out.setdefault("sink", "")
    out.setdefault("flow", [])
    out.setdefault("evidence", "")
    out.setdefault("sanitization_detected", False)
    out.setdefault("framework", "")
    out.setdefault("evidence_type", default_evidence_type)
    out["file"] = out.get("file") or fallback_file
    if not isinstance(out.get("flow", []), list):
        out["flow"] = [out["flow"]]
    return out


def finding_key(finding: Dict[str, Any]) -> tuple:
    f = normalize_finding(finding)
    sink = str(f.get("sink") or f.get("evidence") or "")[:160]
    return (f.get("id"), f.get("file"), int(f.get("line") or 0), sink)


def _merge_list(current, incoming):
    if not isinstance(current, list):
        current = [str(current)]
    if not isinstance(incoming, list):
        incoming = [str(incoming)]
    merged = list(current)
    for item in incoming:
        if str(item) not in merged:
            merged.append(str(item))
    return merged


def deduplicate_findings(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate findings and merge overlapping evidence.

    When two records describe the same issue we keep the higher confidence /
    severity record and blend the flow/evidence lists so the tester sees the
    richest evidence instead of repeated rows.
    """
    out: List[Dict[str, Any]] = []
    index: Dict[tuple, int] = {}

    for raw in findings or []:
        if not isinstance(raw, dict):
            continue
        f = normalize_finding(raw)
        key = finding_key(f)
        existing_idx = index.get(key)
        if existing_idx is None:
            index[key] = len(out)
            out.append(f)
            continue

        existing = out[existing_idx]
        cur_conf = CONFIDENCE_RANK.get(str(existing.get("confidence", "")).lower(), 0)
        new_conf = CONFIDENCE_RANK.get(str(f.get("confidence", "")).lower(), 0)
        cur_sev = SEVERITY_RANK.get(str(existing.get("severity", "")).upper(), 0)
        new_sev = SEVERITY_RANK.get(str(f.get("severity", "")).upper(), 0)

        if new_conf > cur_conf or (new_conf == cur_conf and new_sev > cur_sev):
            existing.update(f)

        # Blend evidence regardless of which record won.
        existing["flow"] = _merge_list(existing.get("flow", []), f.get("flow", []))
        existing["evidence"] = _merge_list(existing.get("evidence", ""), f.get("evidence", "")) if isinstance(existing.get("evidence"), list) or isinstance(f.get("evidence"), list) else (existing.get("evidence") or f.get("evidence"))
        if not existing.get("source"):
            existing["source"] = f.get("source", "")
        if f.get("sanitization_detected"):
            existing["sanitization_detected"] = True

    return out


def _risk_signal_to_finding(sig: Dict[str, Any], filename: str) -> Dict[str, Any]:
    level = str(sig.get("severity", "MEDIUM")).upper()
    confidence = _confidence_for_severity(level)
    evidence = sig.get("evidence", []) or []
    if isinstance(evidence, list):
        evidence_text = " ".join(str(x) for x in evidence[:2])[:240]
    else:
        evidence_text = str(evidence)[:240]
    return normalize_finding(
        {
            "id": sig.get("id"),
            "type": sig.get("title", sig.get("id", "")),
            "severity": level,
            "confidence": confidence,
            "status": _status_for_confidence(confidence),
            "file": filename,
            "line": 0,
            "source": "",
            "sink": evidence_text[:120],
            "flow": [],
            "sanitization_detected": False,
            "evidence": evidence_text,
        },
        fallback_file=filename,
        default_evidence_type="static_pattern",
    )


def correlate_findings(
    dataflows: Iterable[Dict[str, Any]],
    framework_findings: Iterable[Dict[str, Any]],
    risk_signals: Iterable[Dict[str, Any]],
    filename: str = "inline.js",
) -> List[Dict[str, Any]]:
    """Build the unified, de-duplicated finding list.

    Order of precedence:
      1. source-to-sink data flows (highest evidence)
      2. framework-specific rules
      3. coarse static risk signals (only if not already represented)
    """
    raw: List[Dict[str, Any]] = []
    for flow in dataflows or []:
        if isinstance(flow, dict):
            raw.append(normalize_finding(flow, fallback_file=filename, default_evidence_type="source_to_sink"))
    for fw in framework_findings or []:
        if isinstance(fw, dict):
            raw.append(normalize_finding(fw, fallback_file=filename, default_evidence_type="framework_pattern"))

    # Coarse signals that duplicate a flow/framework id are dropped.
    existing_ids = {f.get("id") for f in raw if f.get("id")}
    for sig in risk_signals or []:
        if not isinstance(sig, dict) or sig.get("id") in existing_ids:
            continue
        raw.append(_risk_signal_to_finding(sig, filename))

    return deduplicate_findings(raw)


def merge_attack_surface(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge per-file attack-surface lists into distinct keys, keeping first line."""
    out = []
    seen = set()
    for item in items or []:
        if not isinstance(item, dict):
            continue
        sig = (
            item.get("url") or item.get("operation") or item.get("type") or "",
            item.get("method") or item.get("kind") or "",
            item.get("line") or 0,
        )
        if sig in seen:
            continue
        seen.add(sig)
        out.append(item)
    return out[:120]
