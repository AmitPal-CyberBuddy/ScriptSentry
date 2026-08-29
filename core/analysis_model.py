"""Shared analysis model and correlation helpers.

This module is deliberately small. It contains the vocabulary used by every
detector --- severity, confidence, triage status, analysis quality --- and the
correlation/deduplication logic that turns raw detector output into a clean,
tester-facing finding list.

Severity, confidence and triage status are **independent axes** on purpose:

  * Severity    = "How bad is the impact *if this is real*?"
  * Confidence  = "How certain are we that the finding is real?"
  * Status      = "What is the analyst triage state?"
  * Quality     = "How much of the analysis machinery resolved cleanly?"

A HIGH severity DOM-XSS candidate built on a single regex is still LOW
confidence, and confidence is therefore never derived from severity.  The
``confirmed`` triage status is reserved for deterministic proof, an unsafe
runtime effect, or explicit analyst confirmation --- never for a bare
source-to-sink path.

Keeping this in one place makes it easy to:
  * keep severity/confidence/status semantics consistent between scanners,
    reports and the dashboard,
  * deduplicate overlapping evidence (source-to-sink flows, framework rules,
    coarse risk signals),
  * preserve structured evidence for manual verification.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Evidence confidence. ``confirmed`` means the engine has deterministic proof
# (e.g. it observed the unsafe effect execute in the live browser); it is a
# property of the *evidence*, not of the impact.
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2, "confirmed": 3}
VALID_CONFIDENCE = ("low", "medium", "high", "confirmed")

# Analyst triage states. ``open`` means "actionable, investigate"; these are
# deliberately distinct from confidence so a high-confidence finding can still
# be triaged as a false positive by the analyst.
TRIAGE_STATUS_RANK = {
    "informational": 0,
    "false_positive": 1,
    "potential": 2,  # backwards-compatible alias for needs_review
    "needs_review": 2,
    "open": 3,
    "confirmed": 4,
}
VALID_STATUS = ("open", "needs_review", "confirmed", "false_positive", "informational", "potential")
VALID_ANALYSIS_QUALITY = ("high", "medium", "low", "heuristic")

# Default confidence by *evidence type* --- never by severity.  A source-to-
# sink path is strong evidence that data can reach a sink; a regex risk signal
# is only an observation.
_CONFIDENCE_BY_EVIDENCE = {
    "runtime_browser": "high",
    "runtime_effect": "confirmed",
    "source_to_sink": "high",
    "framework_pattern": "medium",
    "behavioral_correlation": "medium",
    "static_pattern": "low",
    "heuristic": "low",
}

# Evidence types that constitute deterministic/unsafe-effect proof.  Nothing
# static (not even a source-to-sink path) may reach ``confirmed`` on its own:
# the browser may encode, sanitize or never reach the sink.
_PROOF_EVIDENCE_TYPES = {"runtime_effect"}

# Sanitized flows are not vulnerabilities: they become informational
# observations instead of action items.
_STATUS_FOR_SANITIZED = "informational"


@dataclass
class Finding:
    """Minimal internal representation of a correlated finding."""

    id: str
    type: str
    severity: str = "MEDIUM"
    confidence: str = "medium"
    status: str = "needs_review"
    file: str = ""
    line: int = 0
    source: str = ""
    sink: str = ""
    flow: List[str] = field(default_factory=list)
    evidence: Any = ""
    sanitization_detected: bool = False
    framework: str = ""
    evidence_type: str = "static_pattern"
    analysis_quality: str = "medium"
    limitations: List[str] = field(default_factory=list)
    observation: bool = False

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
            "analysis_quality": self.analysis_quality,
            "limitations": list(self.limitations or []),
            "observation": bool(self.observation),
        }


def canonical_confidence(value: str) -> str:
    """Normalize a confidence label to the controlled vocabulary."""
    v = str(value or "").lower().strip()
    if v in CONFIDENCE_RANK:
        return v
    # Tolerate legacy vocabulary.
    if v in ("conf", "certain", "proven", "verified"):
        return "confirmed"
    return "low"


def canonical_status(value: str) -> str:
    """Normalize a triage status to the controlled vocabulary."""
    v = str(value or "").lower().strip().replace("-", "_").replace(" ", "_")
    if v in VALID_STATUS:
        return v
    if v in ("info", "informative", "observation"):
        return "informational"
    if v in ("falsepositive", "fp", "false alarm"):
        return "false_positive"
    if v in ("review", "triage"):
        return "needs_review"
    return "needs_review"


def canonical_analysis_quality(value: str) -> str:
    v = str(value or "").lower().strip()
    return v if v in VALID_ANALYSIS_QUALITY else "medium"


def confidence_for_evidence(evidence_type: str, explicit: Optional[str] = None) -> str:
    """Return evidence-based confidence, independent of severity.

    Callers that have a more precise confidence (e.g. the taint engine tracks
    propagation strength) may pass ``explicit`` and it is honored.
    """
    if explicit:
        return canonical_confidence(explicit)
    return _CONFIDENCE_BY_EVIDENCE.get(str(evidence_type or "static_pattern"), "low")


def status_for_evidence(
    confidence: str,
    evidence_type: str,
    sanitized: bool = False,
    severity: str = "MEDIUM",
    observation: bool = False,
) -> str:
    """Derive the *initial* triage status from evidence quality.

    Rules, in order:
      * sanitized flow           -> informational (not a vulnerability)
      * explicit observation flag-> informational
      * deterministic proof      -> confirmed
      * high/confirmed confidence-> open (actionable, still needs triage)
      * medium confidence        -> needs_review
      * low confidence           -> needs_review (high impact) / informational
    """
    confidence = canonical_confidence(confidence)
    if sanitized:
        return _STATUS_FOR_SANITIZED
    if observation:
        return "informational"
    if evidence_type in _PROOF_EVIDENCE_TYPES or confidence == "confirmed":
        return "confirmed"
    if confidence == "high":
        return "open"
    if confidence == "medium":
        return "needs_review"
    # low confidence regex/heuristic signals: only high-impact ones deserve a
    # triage queue slot; the rest are observations.
    return "needs_review" if SEVERITY_RANK.get(str(severity or "").upper(), 0) >= SEVERITY_RANK["HIGH"] else "informational"


def is_observation(finding: Dict[str, Any]) -> bool:
    """A finding is an *observation* when it is interesting behavior rather
    than a vulnerability requiring remediation."""
    if finding.get("observation"):
        return True
    status = canonical_status(finding.get("status"))
    if status in ("informational", "false_positive"):
        return True
    if finding.get("sanitization_detected"):
        return True
    if str(finding.get("evidence_type", "")) == "static_pattern" and not finding.get("flow"):
        # Coarse regex signals without a flow are inventory observations.
        sev = str(finding.get("severity", "")).upper()
        if sev not in ("CRITICAL", "HIGH"):
            return True
    return False


def normalize_finding(
    finding: Dict[str, Any],
    fallback_file: str = "",
    default_evidence_type: str = "static_pattern",
) -> Dict[str, Any]:
    """Return a finding with all fields present and a predictable shape.

    Confidence is derived from the *evidence type* (not the severity) and the
    status is derived from evidence quality; callers that pre-computed either
    value keep it.
    """
    out = dict(finding or {})
    out.setdefault("id", str(out.get("type") or out.get("name") or "finding"))
    out.setdefault("type", out.get("id", "finding"))
    out.setdefault("severity", "MEDIUM")
    out["severity"] = str(out["severity"] or "MEDIUM").upper()
    if out["severity"] not in SEVERITY_RANK:
        out["severity"] = "MEDIUM"

    evidence_type = str(out.get("evidence_type") or default_evidence_type or "static_pattern")
    out["evidence_type"] = evidence_type
    out.setdefault("confidence", confidence_for_evidence(evidence_type, out.get("confidence")))
    out["confidence"] = canonical_confidence(out.get("confidence"))

    sanitized = bool(out.get("sanitization_detected"))
    observation = bool(out.get("observation"))
    if "status" in out and out.get("status"):
        out["status"] = canonical_status(out.get("status"))
    else:
        out["status"] = status_for_evidence(
            out["confidence"], evidence_type, sanitized=sanitized,
            severity=out["severity"], observation=observation,
        )

    out.setdefault("file", fallback_file)
    out.setdefault("line", 0)
    out.setdefault("source", "")
    out.setdefault("sink", "")
    out.setdefault("flow", [])
    out.setdefault("evidence", "")
    out.setdefault("sanitization_detected", False)
    out.setdefault("framework", "")
    out.setdefault("analysis_quality", "medium")
    out["analysis_quality"] = canonical_analysis_quality(out.get("analysis_quality"))
    out.setdefault("limitations", [])
    out.setdefault("observation", observation)
    out["file"] = out.get("file") or fallback_file
    out["line"] = int(out.get("line") or 0)
    if not isinstance(out.get("flow", []), list):
        out["flow"] = [out["flow"]]
    if not isinstance(out.get("limitations", []), list):
        out["limitations"] = [out["limitations"]]
    out["observation"] = bool(is_observation(out))
    return out


def _flow_signature(flow: Iterable[str]) -> str:
    """Compact, order-insensitive signature of a propagation path."""
    steps = [str(s).strip().lower() for s in (flow or []) if str(s).strip()]
    return "|".join(sorted(dict.fromkeys(steps)))[:200]


def finding_identity(finding: Dict[str, Any]) -> Tuple[str, str, str, str, int, str]:
    """Stronger identity than the old ``(id, file, line, sink)`` tuple.

    Two distinct untrusted sources reaching the same sink on the same line
    must remain distinguishable, so the identity also folds in the canonical
    source and a normalized flow signature.
    """
    f = normalize_finding(finding)
    source = str(f.get("source") or "").strip().lower()[:160]
    sink = str(f.get("sink") or f.get("evidence") or "").strip().lower()[:160]
    # Strip volatile punctuation so `innerHTML = q` and `innerHTML=q` merge.
    sink_sig = "".join(ch for ch in sink if ch.isalnum() or ch == ".")[:120]
    flow_sig = _flow_signature(f.get("flow", []))
    return (
        str(f.get("id") or f.get("type") or "finding"),
        str(f.get("file") or ""),
        source,
        sink_sig,
        int(f.get("line") or 0),
        flow_sig,
    )


def finding_key(finding: Dict[str, Any]) -> tuple:
    """Backwards-compatible key used by callers that only need coarseness."""
    return finding_identity(finding)


def _merge_list(current, incoming):
    if not isinstance(current, list):
        current = [str(current)] if current not in (None, "") else []
    if not isinstance(incoming, list):
        incoming = [str(incoming)] if incoming not in (None, "") else []
    merged = list(current)
    for item in incoming:
        if str(item) not in merged:
            merged.append(str(item))
    return merged


def _merge_limitations(existing, incoming):
    out = list(existing or [])
    for item in incoming or []:
        text = str(item)
        if text and text not in out:
            out.append(text)
    return out


def _merge_findings(existing: Dict[str, Any], new: Dict[str, Any]) -> None:
    """Blend a duplicate record into the surviving one, keeping the strongest
    confidence/severity and the richest evidence."""
    cur_conf = CONFIDENCE_RANK.get(canonical_confidence(existing.get("confidence")), 0)
    new_conf = CONFIDENCE_RANK.get(canonical_confidence(new.get("confidence")), 0)
    cur_sev = SEVERITY_RANK.get(str(existing.get("severity", "")).upper(), 0)
    new_sev = SEVERITY_RANK.get(str(new.get("severity", "")).upper(), 0)

    if new_conf > cur_conf or (new_conf == cur_conf and new_sev > cur_sev):
        # Carry over fields the new record knows more about.
        for field in ("confidence", "status", "severity", "evidence_type",
                      "analysis_quality", "framework", "source"):
            if new.get(field):
                existing[field] = new[field]

    # Blend evidence regardless of which record won.
    existing["flow"] = _merge_list(existing.get("flow", []), new.get("flow", []))
    ev_existing, ev_new = existing.get("evidence"), new.get("evidence")
    if isinstance(ev_existing, list) or isinstance(ev_new, list):
        merged_ev = _merge_list(ev_existing or [], ev_new or [])
        existing["evidence"] = merged_ev
    else:
        existing["evidence"] = ev_existing or ev_new
    existing["limitations"] = _merge_limitations(existing.get("limitations"), new.get("limitations"))
    if not existing.get("source") and new.get("source"):
        existing["source"] = new["source"]
    if not existing.get("sink") and new.get("sink"):
        existing["sink"] = new["sink"]
    if new.get("sanitization_detected"):
        existing["sanitization_detected"] = True
    # Re-derive status only when neither side was analyst-confirmed.
    if canonical_status(existing.get("status")) != "confirmed":
        existing["status"] = status_for_evidence(
            existing.get("confidence"), existing.get("evidence_type"),
            sanitized=bool(existing.get("sanitization_detected")),
            severity=existing.get("severity"),
            observation=bool(existing.get("observation")),
        )
    existing["confidence"] = canonical_confidence(existing.get("confidence"))
    existing["analysis_quality"] = canonical_analysis_quality(existing.get("analysis_quality"))
    existing["observation"] = bool(is_observation(existing))


def deduplicate_findings(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate findings and merge overlapping evidence.

    When two records describe the same issue (same type/source/sink/line/flow)
    we keep the higher confidence / severity record and blend the flow and
    evidence lists so the tester sees the richest evidence instead of repeated
    rows.  Distinct sources reaching the same sink stay separate.
    """
    out: List[Dict[str, Any]] = []
    index: Dict[tuple, int] = {}

    for raw in findings or []:
        if not isinstance(raw, dict):
            continue
        f = normalize_finding(raw)
        key = finding_identity(f)
        existing_idx = index.get(key)
        if existing_idx is None:
            index[key] = len(out)
            out.append(f)
            continue
        _merge_findings(out[existing_idx], f)

    return out


def _risk_signal_to_finding(sig: Dict[str, Any], filename: str) -> Dict[str, Any]:
    level = str(sig.get("severity", "MEDIUM")).upper()
    # A regex/risk signal is an observation, not proof.  Even when a signal
    # claims high severity, confidence reflects the weak evidence.
    evidence_type = str(sig.get("evidence_type") or "static_pattern")
    confidence = canonical_confidence(sig.get("confidence")) if sig.get("confidence") in VALID_CONFIDENCE else confidence_for_evidence(evidence_type)
    evidence = sig.get("evidence", []) or []
    if isinstance(evidence, list):
        evidence_text = " ".join(str(x) for x in evidence[:2])[:240]
    else:
        evidence_text = str(evidence)[:240]
    observation = bool(sig.get("observation")) or (
        evidence_type == "static_pattern" and level not in ("CRITICAL", "HIGH")
    )
    return normalize_finding(
        {
            "id": sig.get("id"),
            "type": sig.get("title", sig.get("id", "")),
            "severity": level,
            "confidence": confidence,
            # Signals are never auto-confirmed; derive status from evidence.
            "file": filename,
            "line": int(sig.get("line", 0) or 0),
            "source": "",
            "sink": evidence_text[:120],
            "flow": [],
            "sanitization_detected": False,
            "evidence": evidence_text,
            "evidence_type": evidence_type,
            "analysis_quality": sig.get("analysis_quality", "heuristic"),
            "limitations": sig.get("limitations", []) or ["Regex/heuristic signal; no source-to-sink path established."],
            "observation": observation,
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
      1. source-to-sink data flows (strongest static evidence)
      2. framework-specific rules
      3. coarse static risk signals (only if not already represented)

    Flows and framework rules are *actionable findings*; coarse signals are
    *observations* and tagged as such so the UI can separate
    "investigate/remediate" from "interesting behavior".
    """
    raw: List[Dict[str, Any]] = []
    for flow in dataflows or []:
        if isinstance(flow, dict):
            record = normalize_finding(flow, fallback_file=filename, default_evidence_type="source_to_sink")
            raw.append(record)
    for fw in framework_findings or []:
        if isinstance(fw, dict):
            record = normalize_finding(fw, fallback_file=filename, default_evidence_type="framework_pattern")
            raw.append(record)

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


def split_findings(findings: Iterable[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Split a finding list into (actionable findings, observations).

    Findings require investigation or remediation; observations are
    interesting behavior that is not (yet) a vulnerability.  This matches the
    accuracy-first philosophy: never let a regex observation masquerade as a
    confirmed vulnerability.
    """
    actionable, observations = [], []
    for f in deduplicate_findings(findings or []):
        (observations if is_observation(f) else actionable).append(f)
    return actionable, observations
