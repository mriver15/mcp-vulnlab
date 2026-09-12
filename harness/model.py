"""Typed model shared across the harness.

Everything that gets serialized to the scorecard JSON lives here, so the shapes
are defined in exactly one place.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

#: The six threat categories the corpus covers.
CATEGORIES: tuple[str, ...] = (
    "prompt-injection",
    "data-exfiltration",
    "overbroad-tool-schema",
    "missing-auth",
    "pii-disclosure",
    "supply-chain",
)

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low")

#: Sentinel for a label that is not attributable to a single tool.
SERVER_LEVEL = "(server)"


# --------------------------------------------------------------------------- #
# Corpus side
# --------------------------------------------------------------------------- #


@dataclass
class Label:
    """One labeled weakness. Ground truth for recall."""

    id: str
    server: str
    title: str
    category: str
    severity: str
    tool: str
    description: str
    signals: list[str] = field(default_factory=list)

    @classmethod
    def from_json(cls, server: str, raw: dict[str, Any]) -> Label:
        detection = raw.get("detection") or {}
        return cls(
            id=raw["id"],
            server=server,
            title=raw["title"],
            category=raw["category"],
            severity=raw["severity"],
            tool=raw["tool"],
            description=raw["description"],
            signals=[str(s).lower() for s in detection.get("signals", ())],
        )

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ServerSpec:
    """A corpus challenge: its launch spec and its labels."""

    slug: str
    directory: Path
    title: str
    kind: str
    summary: str
    entrypoint: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    categories: list[str] = field(default_factory=list)
    labels: list[Label] = field(default_factory=list)

    @property
    def is_control(self) -> bool:
        """Controls are benign; any finding against them is a false positive."""
        return self.kind == "control"

    @property
    def entrypoint_path(self) -> Path:
        return self.directory / self.entrypoint

    def command(self, python: str) -> list[str]:
        """argv used to launch this server over stdio."""
        return [python, str(self.entrypoint_path), *self.args]

    def to_json(self) -> dict[str, Any]:
        return {
            "slug": self.slug,
            "title": self.title,
            "kind": self.kind,
            "summary": self.summary,
            "entrypoint": self.entrypoint,
            "args": list(self.args),
            "categories": list(self.categories),
            "labels": [label.id for label in self.labels],
        }


# --------------------------------------------------------------------------- #
# Scanner side
# --------------------------------------------------------------------------- #


@dataclass
class Finding:
    """One normalized scanner finding.

    Scanners disagree about field names and shapes; every adapter's job is to
    produce these. `raw` keeps the original object so a disputed match can be
    audited without re-running the scanner.
    """

    scanner: str
    server: str
    message: str = ""
    rule_id: str | None = None
    severity: str | None = None
    category: str | None = None
    tool: str | None = None
    raw: dict[str, Any] | None = None

    @property
    def haystack(self) -> str:
        """Lowercased text used for signal matching."""
        parts = (self.message or "", self.rule_id or "", self.category or "", self.tool or "")
        return " ".join(parts).lower()

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Match:
    """A finding attributed to a label, with the reason recorded."""

    label_id: str
    server: str
    reason: str
    finding: Finding

    def to_json(self) -> dict[str, Any]:
        return {
            "label_id": self.label_id,
            "server": self.server,
            "reason": self.reason,
            "finding": self.finding.to_json(),
        }


# --------------------------------------------------------------------------- #
# Results
# --------------------------------------------------------------------------- #


@dataclass
class ServerScore:
    """Per-server result for one scanner."""

    slug: str
    kind: str
    labels_total: int = 0
    detected_ids: list[str] = field(default_factory=list)
    missed_ids: list[str] = field(default_factory=list)
    findings_total: int = 0
    matches: list[Match] = field(default_factory=list)
    unmatched: list[Finding] = field(default_factory=list)

    @property
    def labels_detected(self) -> int:
        return len(self.detected_ids)

    @property
    def false_positives(self) -> list[Finding]:
        """Every unmatched finding is a false positive.

        For a control server that is true by definition. For a vulnerable server
        it means the scanner flagged something no label describes.
        """
        return list(self.unmatched)

    def to_json(self) -> dict[str, Any]:
        return {
            "slug": self.slug,
            "kind": self.kind,
            "labels_total": self.labels_total,
            "labels_detected": self.labels_detected,
            "detected_ids": list(self.detected_ids),
            "missed_ids": list(self.missed_ids),
            "findings_total": self.findings_total,
            "false_positives": len(self.false_positives),
            "matches": [m.to_json() for m in self.matches],
            "unmatched": [f.to_json() for f in self.unmatched],
        }


@dataclass
class Scorecard:
    """The whole run for one scanner."""

    scanner: str
    generated_at: str
    corpus_root: str
    available: bool = True
    unavailable_reason: str | None = None
    notes: list[str] = field(default_factory=list)
    servers: list[ServerScore] = field(default_factory=list)

    # -- aggregates ------------------------------------------------------- #

    @property
    def labels_total(self) -> int:
        return sum(s.labels_total for s in self.servers)

    @property
    def labels_detected(self) -> int:
        return sum(s.labels_detected for s in self.servers)

    @property
    def recall(self) -> float | None:
        """Fraction of labels detected. None when the scanner did not run."""
        if not self.available or self.labels_total == 0:
            return None
        return self.labels_detected / self.labels_total

    @property
    def findings_total(self) -> int:
        return sum(s.findings_total for s in self.servers)

    @property
    def false_positives(self) -> int:
        return sum(len(s.false_positives) for s in self.servers)

    @property
    def true_positives(self) -> int:
        return sum(len(s.matches) for s in self.servers)

    @property
    def fp_rate(self) -> float | None:
        """Unmatched findings as a fraction of all findings."""
        if not self.available or self.findings_total == 0:
            return None
        return self.false_positives / self.findings_total

    def by_category(self) -> dict[str, dict[str, Any]]:
        """Per-category recall, derived from the per-server labels."""
        buckets: dict[str, dict[str, Any]] = {}
        for score in self.servers:
            for label_id in [*score.detected_ids, *score.missed_ids]:
                info = self.label_index.get(label_id)
                if info is None:
                    continue
                bucket = buckets.setdefault(
                    info["category"], {"total": 0, "detected": 0, "ids": []}
                )
                bucket["total"] += 1
                bucket["ids"].append(label_id)
                if label_id in score.detected_ids:
                    bucket["detected"] += 1
        return dict(sorted(buckets.items()))

    #: label id -> {"server", "title", "category", "severity", "tool"}. Populated by
    #: the runner so a committed scorecard is self-contained and readable without
    #: re-reading the corpus.
    label_index: dict[str, dict[str, str]] = field(default_factory=dict, repr=False)

    def label(self, label_id: str) -> dict[str, str]:
        return self.label_index.get(label_id, {})

    def to_json(self) -> dict[str, Any]:
        categories = self.by_category()
        return {
            "scanner": self.scanner,
            "generated_at": self.generated_at,
            "corpus_root": self.corpus_root,
            "available": self.available,
            "unavailable_reason": self.unavailable_reason,
            "summary": {
                "labels_total": self.labels_total,
                "labels_detected": self.labels_detected,
                "recall": self.recall,
                "findings_total": self.findings_total,
                "true_positives": self.true_positives,
                "false_positives": self.false_positives,
                "fp_rate": self.fp_rate,
            },
            "by_category": categories,
            "labels": self.label_index,
            "servers": [s.to_json() for s in self.servers],
            "notes": list(self.notes),
        }

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> Scorecard:
        """Rebuild a scorecard from its serialized form (used by `report`)."""
        card = cls(
            scanner=raw["scanner"],
            generated_at=raw["generated_at"],
            corpus_root=raw["corpus_root"],
            available=raw.get("available", True),
            unavailable_reason=raw.get("unavailable_reason"),
            notes=list(raw.get("notes", ())),
        )
        card.label_index = {
            str(key): dict(value) for key, value in (raw.get("labels") or {}).items()
        }
        for server in raw.get("servers", ()):
            score = ServerScore(
                slug=server["slug"],
                kind=server["kind"],
                labels_total=server.get("labels_total", 0),
                detected_ids=list(server.get("detected_ids", ())),
                missed_ids=list(server.get("missed_ids", ())),
                findings_total=server.get("findings_total", 0),
            )
            score.unmatched = [_finding_from_json(f) for f in server.get("unmatched", ())]
            score.matches = [
                Match(
                    label_id=m["label_id"],
                    server=m["server"],
                    reason=m["reason"],
                    finding=_finding_from_json(m["finding"]),
                )
                for m in server.get("matches", ())
            ]
            card.servers.append(score)
        return card


def _finding_from_json(raw: dict[str, Any]) -> Finding:
    return Finding(
        scanner=raw.get("scanner", ""),
        server=raw.get("server", ""),
        message=raw.get("message", ""),
        rule_id=raw.get("rule_id"),
        severity=raw.get("severity"),
        category=raw.get("category"),
        tool=raw.get("tool"),
        raw=raw.get("raw"),
    )
