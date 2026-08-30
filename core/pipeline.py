"""The scan pipeline: named stages, their cost weights, and honest progress.

A scan is not "a percentage". It is a sequence of stages with very different
cost profiles -- fetching a page costs a network round trip, downloading
bundles costs bandwidth, and analyzing them costs CPU, while beautifying is
mostly I/O. Treating every stage as one tick (or worse, dividing files done by
the *file cap*) produces a progress bar that stalls at 3%, jumps to 90% and
then sits there, and an ETA that is nonsense.

This module gives the rest of the engine:

  * a declarative stage plan per scan mode,
  * human-readable labels so the UI never prints a raw phase key,
  * :class:`ProgressModel`, which converts per-stage counters into a single
    monotonic 0..1 fraction using each stage's weight.

The fraction is deliberately monotonic: progress that moves backwards destroys
trust in the ETA faster than an imprecise ETA does.
"""
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Stage catalogue
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Stage:
    """One step of the pipeline.

    ``weight`` is its share of the *total expected cost* for a typical scan.
    Weights are relative, not seconds: they say "downloading usually costs
    about twice as much as recon", not "downloading takes 2 seconds".
    """

    key: str
    label: str
    description: str
    weight: float = 1.0
    # Shown in the UI even for scans that finish a stage instantly.
    always: bool = False


#: Every stage, in execution order.
STAGES: Tuple[Stage, ...] = (
    Stage("recon", "Recon",
          "Fetching the page and recording what it references", 1.0),
    Stage("discover", "Discover",
          "Resolving script, module and bundler-chunk references", 1.5),
    Stage("download", "Download",
          "Downloading the referenced JavaScript", 3.0),
    Stage("normalize", "Normalize",
          "Beautifying and normalizing minified bundles", 1.5),
    Stage("analyze", "Analyze",
          "Running the static analysis passes over every script", 6.0),
    Stage("correlate", "Correlate",
          "Correlating flows, de-duplicating and ranking findings", 1.0),
    Stage("verify", "Verify",
          "Confirming behaviour in a local headless browser", 4.0, always=True),
    Stage("report", "Report",
          "Assembling the report", 0.5),
)

_STAGE_BY_KEY: Dict[str, Stage] = {s.key: s for s in STAGES}
STAGE_KEYS: Tuple[str, ...] = tuple(s.key for s in STAGES)

#: Phase names the older code paths emit, mapped onto the new stages.
_LEGACY_PHASE_ALIASES: Dict[str, str] = {
    "queued": "recon",
    "scan": "analyze",
    "inline_scan": "analyze",
    "recursive_scan": "analyze",
    "beautify": "normalize",
    "runtime": "verify",
    "starting": "recon",
    "working": "analyze",
    "done": "report",
}


def canonical_stage(phase: str) -> str:
    """Map any emitted phase name onto a canonical stage key."""
    key = str(phase or "").strip().lower()
    return key if key in _STAGE_BY_KEY else _LEGACY_PHASE_ALIASES.get(key, "analyze")


def stage_label(phase: str) -> str:
    """Human-readable label for a phase key."""
    return _STAGE_BY_KEY[canonical_stage(phase)].label


def stage_description(phase: str) -> str:
    return _STAGE_BY_KEY[canonical_stage(phase)].description


def stage_plan(mode: str = "url", runtime_enabled: bool = False) -> List[Stage]:
    """The stages this particular scan will actually run.

    A pasted snippet has nothing to fetch or download, so weighting those
    stages would guarantee the bar never reaches 100% until the very end.
    """
    mode = str(mode or "url").lower()
    if mode in ("code", "files", "upload"):
        keys = ("analyze", "correlate", "report")
    else:
        keys = ("recon", "discover", "download", "normalize", "analyze", "correlate")
        if runtime_enabled:
            keys = keys + ("verify",)
        keys = keys + ("report",)
    return [_STAGE_BY_KEY[k] for k in keys]


# ---------------------------------------------------------------------------
# Weighted, monotonic progress
# ---------------------------------------------------------------------------


@dataclass
class ProgressModel:
    """Turn per-stage counters into one monotonic 0..1 fraction.

    Each stage owns a slice of the bar proportional to its weight. Inside a
    stage, ``current/total`` decides how much of that slice is filled. Both the
    stage's own fraction and the global fraction are clamped to never decrease,
    so a growing work estimate (bundles keep being discovered) can stall the
    bar but never rewind it.
    """

    plan: Sequence[Stage]
    stage: str = ""
    current: int = 0
    total: int = 0
    _fraction: float = 0.0
    _stage_fraction: Dict[str, float] = field(default_factory=dict)
    _completed_weight: float = 0.0
    _current_weight: float = 0.0

    def __post_init__(self) -> None:
        self.plan = list(self.plan) or list(STAGES)
        self._weights = {s.key: max(0.0, float(s.weight)) for s in self.plan}
        self._total_weight = sum(self._weights.values()) or 1.0
        if not self.stage:
            self.stage = self.plan[0].key
            self._current_weight = self._weights.get(self.stage, 0.0)

    # -- mutation ---------------------------------------------------------
    def set_stage(self, phase: str, current: int = 0, total: int = 0) -> None:
        """Move to ``phase``, banking the progress of the previous one."""
        key = canonical_stage(phase)
        if key == self.stage:
            self.update(current=current, total=total)
            return
        # Bank whatever the outgoing stage had reached.
        self._stage_fraction[self.stage] = max(
            self._stage_fraction.get(self.stage, 0.0), self._stage_progress())
        self._completed_weight += self._current_weight
        self.stage = key
        self._current_weight = self._weights.get(key, 0.0)
        self.current = max(0, int(current or 0))
        self.total = max(0, int(total or 0))
        self._recompute()

    def update(self, current: Optional[int] = None, total: Optional[int] = None) -> None:
        """Update the counters of the current stage.

        ``total`` is allowed to grow (more bundles discovered); it is never
        allowed to shrink below the work already done.
        """
        if current is not None:
            self.current = max(self.current, int(current or 0))
        if total is not None:
            self.total = max(self.total, int(total or 0))
        if self.total and self.current > self.total:
            self.total = self.current
        self._recompute()

    def complete_stage(self, phase: Optional[str] = None) -> None:
        key = canonical_stage(phase) if phase else self.stage
        self._stage_fraction[key] = 1.0

    # -- reading ----------------------------------------------------------
    def _stage_progress(self) -> float:
        if self.total <= 0:
            # No countable work: treat the stage as half done while it runs so
            # the bar keeps moving instead of freezing at a stage boundary.
            return 0.5
        return max(0.0, min(1.0, self.current / float(self.total)))

    def _recompute(self) -> None:
        done = self._completed_weight
        done += self._current_weight * max(
            self._stage_fraction.get(self.stage, 0.0), self._stage_progress())
        # Everything already finished keeps its banked progress.
        for key, frac in self._stage_fraction.items():
            if key != self.stage and key in self._weights:
                done = max(done, 0.0)
        fraction = max(0.0, min(1.0, done / self._total_weight))
        self._fraction = max(self._fraction, fraction)

    @property
    def fraction(self) -> float:
        return self._fraction

    @property
    def percent(self) -> float:
        return round(self._fraction * 100.0, 2)

    def stage_states(self) -> List[Dict[str, object]]:
        """Per-stage snapshot for the UI (pending / active / done)."""
        order = {s.key: i for i, s in enumerate(self.plan)}
        active_index = order.get(self.stage, -1)
        out: List[Dict[str, object]] = []
        for index, stage in enumerate(self.plan):
            if index < active_index or self._stage_fraction.get(stage.key, 0.0) >= 1.0:
                state = "done"
            elif index == active_index:
                state = "active"
            else:
                state = "pending"
            out.append({
                "key": stage.key,
                "label": stage.label,
                "description": stage.description,
                "state": state,
            })
        return out


def describe_plan(plan: Iterable[Stage]) -> List[Dict[str, object]]:
    return [
        {"key": s.key, "label": s.label, "description": s.description}
        for s in plan
    ]
