"""Map scanner findings onto labels, producing recall and false-positive figures.

Two decisions define the numbers this module produces, and both are deliberately
conservative — a benchmark that flatters scanners is worthless:

1. **A finding is attributed to at most one label.** If a single finding could
   plausibly describe two labels, it counts as detection for the strongest match
   only. Recall therefore cannot be inflated by one vague finding satisfying
   several ground-truth entries.
2. **Anything not attributed to a label is a false positive.** For a control
   server that is true by definition. For a vulnerable server it means the
   scanner flagged something no label describes, which is a real cost: it is a
   report a human has to triage.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from harness.model import (
    SERVER_LEVEL,
    Finding,
    Match,
    Scorecard,
    ServerScore,
    ServerSpec,
)

#: Match strengths, strongest first. Higher wins when attributing a finding.
TOOL_EXACT = 3
TOOL_SUBSTRING = 2
SIGNAL = 1
NO_MATCH = 0

_MIN_SIGNAL_LENGTH = 3
_BRACES = re.compile(r"\{[^}]*\}")


@dataclass(frozen=True)
class MatchPolicy:
    """Knobs for the matching algorithm, recorded in the scorecard for honesty."""

    min_signal_length: int = _MIN_SIGNAL_LENGTH
    require_same_server: bool = True

    def describe(self) -> str:
        return (
            "tool name exact match (3) > tool name substring (2) > detection signal "
            f"match (1). Signals shorter than {self.min_signal_length} characters are "
            "ignored. Each finding is attributed to at most one label, strongest match "
            "wins, ties broken by label id. Every unattributed finding counts as a "
            "false positive."
        )


DEFAULT_POLICY = MatchPolicy()


def _tool_strength(label_tool: str, finding: Finding) -> int:
    """How strongly this finding names the label's tool."""
    if label_tool == SERVER_LEVEL:
        return NO_MATCH  # server-level labels can only be matched by signal

    lowered = label_tool.lower()
    if finding.tool and finding.tool.lower() == lowered:
        return TOOL_EXACT

    haystack = finding.haystack
    # Resource templates such as "report://{path}" are matched on their literal stem.
    literal = _BRACES.sub("", lowered).strip()
    for candidate in (literal, lowered):
        if len(candidate) >= 3 and candidate in haystack:
            return TOOL_SUBSTRING
    return NO_MATCH


def _signal_hits(label_signals: list[str], finding: Finding, policy: MatchPolicy) -> list[str]:
    haystack = finding.haystack
    return [
        signal
        for signal in label_signals
        if len(signal) >= policy.min_signal_length and signal in haystack
    ]


def score_server(
    spec: ServerSpec,
    findings: list[Finding],
    policy: MatchPolicy = DEFAULT_POLICY,
) -> ServerScore:
    """Attribute findings to labels for one server.

    Findings belonging to other servers are ignored, so this is safe to call with
    a whole run's output. `build_scorecard` groups by server first only to avoid
    the quadratic scan.
    """
    scoped = [finding for finding in findings if finding.server == spec.slug]
    score = ServerScore(
        slug=spec.slug,
        kind=spec.kind,
        labels_total=len(spec.labels),
        findings_total=len(scoped),
    )

    # Candidate matches: (strength, label_id, finding_index, reason)
    candidates: list[tuple[int, str, int, str]] = []
    for index, finding in enumerate(scoped):
        for label in spec.labels:
            strength = _tool_strength(label.tool, finding)
            reason = "tool name matched exactly" if strength == TOOL_EXACT else ""
            if strength == TOOL_SUBSTRING:
                reason = f"tool name {label.tool!r} appeared in the finding"
            if strength == NO_MATCH:
                hits = _signal_hits(label.signals, finding, policy)
                if hits:
                    strength = SIGNAL
                    reason = f"signal match: {', '.join(hits[:3])}"
            if strength > NO_MATCH:
                candidates.append((strength, label.id, index, reason))

    # Strongest first, then label id, then finding order — fully deterministic.
    candidates.sort(key=lambda item: (-item[0], item[1], item[2]))

    claimed_labels: set[str] = set()
    claimed_findings: set[int] = set()
    for strength, label_id, index, reason in candidates:
        if label_id in claimed_labels or index in claimed_findings:
            continue
        claimed_labels.add(label_id)
        claimed_findings.add(index)
        score.matches.append(
            Match(
                label_id=label_id,
                server=spec.slug,
                reason=f"strength {strength}: {reason}",
                finding=findings[index],
            )
        )

    score.detected_ids = sorted(claimed_labels)
    score.missed_ids = sorted(label.id for label in spec.labels if label.id not in claimed_labels)
    score.unmatched = [f for index, f in enumerate(findings) if index not in claimed_findings]
    return score


def build_scorecard(
    scanner: str,
    specs: list[ServerSpec],
    findings: list[Finding],
    *,
    corpus_root: Path,
    available: bool = True,
    unavailable_reason: str | None = None,
    policy: MatchPolicy = DEFAULT_POLICY,
    notes: list[str] | None = None,
) -> Scorecard:
    """Score one scanner's whole run."""
    by_server: dict[str, list[Finding]] = {}
    for finding in findings:
        by_server.setdefault(finding.server, []).append(finding)

    card = Scorecard(
        scanner=scanner,
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        corpus_root=str(corpus_root),
        available=available,
        unavailable_reason=unavailable_reason,
        notes=list(notes or ()),
    )
    card.label_index = {
        label.id: {
            "server": spec.slug,
            "title": label.title,
            "category": label.category,
            "severity": label.severity,
            "tool": label.tool,
        }
        for spec in specs
        for label in spec.labels
    }

    for spec in specs:
        card.servers.append(score_server(spec, by_server.get(spec.slug, []), policy))

    card.notes.append(f"matching policy: {policy.describe()}")
    unknown = sorted(set(by_server) - {spec.slug for spec in specs})
    if unknown:
        card.notes.append(
            "findings referenced unknown server slugs and were ignored: " + ", ".join(unknown)
        )
    return card
