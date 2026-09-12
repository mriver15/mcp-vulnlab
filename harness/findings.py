"""Render the canonical, cross-corpus findings document.

`FINDINGS.md` is the single artefact the project shares: every scanner measured
against both corpora, side by side, with the headline claims derived from the
committed scorecards rather than hand-maintained.

The renderer is deliberately data-driven: tables are computed from
`results/*/scorecard.json` and `results/skills/*/scorecard.json`, so adding a
scanner or a corpus tier never requires editing prose — re-run `make findings`.

Only two things are curated by hand: the scanner metadata below (what each tool
*is*) and the "what these numbers say" narrative (what the numbers *mean*).
"""

from __future__ import annotations

import json
from pathlib import Path

from harness.corpus import discover_skills, repo_root
from harness.model import Scorecard

#: Scanner metadata. Keyed by profile name in scanners.yaml. `family` says what
#: class of detector the tool is; `model` says how it detects.
SCANNERS: dict[str, dict[str, str]] = {
    "cisco-mcp-scanner": {
        "family": "multi-analyser",
        "model": "yara + readiness + prompt-defence analyzers (static rules + policy checks)",
    },
    "mcp-armor": {
        "family": "local model",
        "model": "local prompt-injection model + tool-permission rules",
    },
    "skillspector": {
        "family": "skill-pattern scanner",
        "model": "71-pattern static scanner (+ optional LLM analyzers)",
    },
    "agent-audit": {
        "family": "agent-code analyzer",
        "model": "53 static rules mapped to the OWASP Agentic Top 10",
    },
    "repo-forensics": {
        "family": "supply-chain / skill audit",
        "model": "27 offline scanners + a correlation engine",
    },
    "mcp-security-scanner": {
        "family": "spec conformance",
        "model": "MCP protocol pentest over stdio/http/sse",
    },
    "mcp-shield": {
        "family": "checklist",
        "model": 'per-tool "Verified" checklist (no findings without an API key)',
    },
    "snyk-agent-scan": {
        "family": "hosted cloud",
        "model": "uploads code to Snyk's API; cannot be automated headlessly",
    },
}

#: Self-test / placeholder profiles that must never appear in published findings.
EXCLUDED = frozenset({"replay", "text-only-example"})


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def _summary(card: Scorecard) -> dict[str, float | int | None]:
    return {
        "recall": card.recall,
        "labels_total": card.labels_total,
        "labels_detected": card.labels_detected,
        "findings_total": card.findings_total,
        "false_positives": card.false_positives,
        "fp_rate": card.fp_rate,
    }


def _load_scope(directory: Path) -> list[Scorecard]:
    """Load every committed scorecard under a results scope, in stable order."""
    if not directory.is_dir():
        return []
    cards: list[Scorecard] = []
    for candidate in sorted(directory.iterdir()):
        if not candidate.is_dir():
            continue
        path = candidate / "scorecard.json"
        if not path.is_file():
            continue
        card = Scorecard.from_json(json.loads(path.read_text(encoding="utf-8")))
        if card.scanner not in EXCLUDED:
            cards.append(card)
    return cards


def card_missed(card: Scorecard) -> set[str]:
    return {label_id for score in card.servers for label_id in score.missed_ids}


def _headline_rows(cards: list[tuple[Scorecard, str]]) -> list[str]:
    rows = [
        "| scanner | corpus | recall | detected | findings | false positives | FP rate |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for card, corpus in cards:
        summary = _summary(card)
        if not card.available:
            rows.append(f"| `{card.scanner}` | {corpus} | *not run* | — | — | — | — |")
            continue
        rows.append(
            f"| `{card.scanner}` | {corpus} | **{_pct(summary['recall'])}** | "
            f"{summary['labels_detected']}/{summary['labels_total']} | {summary['findings_total']} | "
            f"{summary['false_positives']} | {_pct(summary['fp_rate'])} |"
        )
    return rows


def _category_table(cards: list[Scorecard]) -> list[str]:
    names = [card.scanner for card in cards]
    lines = [
        "| category | " + " | ".join(f"`{name}`" for name in names) + " |",
        "|---|" + "---:|" * len(names),
    ]
    categories = sorted({category for card in cards for category in card.by_category()})
    for category in categories:
        cells: list[str] = []
        for card in cards:
            bucket = card.by_category().get(category)
            if not card.available or bucket is None:
                cells.append("—")
            else:
                cells.append(f"{bucket['detected']}/{bucket['total']}")
        lines.append(f"| `{category}` | " + " | ".join(cells) + " |")
    return lines


def _missed_by_all(cards: list[Scorecard]) -> set[str]:
    available = [card for card in cards if card.available]
    if not available:
        return set()
    return set.intersection(*(card_missed(card) for card in available))


def _missed_table(cards: list[Scorecard], missed: set[str]) -> list[str]:
    reference = next((card for card in cards if card.available), None)
    lines = [
        "| id | category | severity | server | tool | title |",
        "|---|---|---|---|---|---|",
    ]
    for label_id in sorted(missed):
        info = reference.label(label_id) if reference else {}
        lines.append(
            f"| `{label_id}` | `{info.get('category', '?')}` | {info.get('severity', '?')} | "
            f"`{info.get('server', '?')}` | `{info.get('tool', '?')}` | {info.get('title', '?')} |"
        )
    return lines


def _corpus_counts(root: Path) -> tuple[dict[str, int], dict[str, int]]:
    index = json.loads((root / "corpus" / "labels" / "index.json").read_text(encoding="utf-8"))
    mcp = index["corpus"]
    skills_specs = discover_skills(root, strict=True)
    skills = {
        "servers": len(skills_specs),
        "labels": sum(len(spec.labels) for spec in skills_specs),
        "categories": len({label.category for spec in skills_specs for label in spec.labels}),
        "controls": sum(1 for spec in skills_specs if spec.is_control),
    }
    return mcp, skills


def _narrative(
    missed_mcp: set[str],
    mcp: list[Scorecard],
    skills: list[Scorecard],
) -> list[str]:
    claims: list[str] = []

    if missed_mcp:
        ids = ", ".join(f"`{i}`" for i in sorted(missed_mcp))
        claims.append(
            f"1. **A *disabled* control is the hardest thing to detect.** {ids} — a "
            "path-traversal defence that is explicitly turned off rather than absent — "
            "is the only MCP label missed by every scored scanner. Tools tuned to find "
            "*missing* validation do not find *disabled* validation."
        )

    available_mcp = [c for c in mcp if c.available]
    if available_mcp:
        best = max(available_mcp, key=lambda c: c.recall or 0.0)
        claims.append(
            f"2. **No free lunch.** `{best.scanner}` has the best MCP recall "
            f"({_pct(best.recall)}), but at a false-positive rate of "
            f"{_pct(best.fp_rate)} — every finding that matches no label is triage "
            "cost a security team still pays."
        )

    claims.append(
        "3. **No scanner crosses families.** The spec-conformance pentest sees none of "
        "the semantic weaknesses; the static scanners see none of the protocol issues; "
        "the hosted scanner cannot be automated at all. Coverage is complementary — "
        "defence in depth, not a single tool."
    )

    skill_cards = {c.scanner: c for c in skills if c.available}
    if "skillspector" in skill_cards and "agent-audit" in skill_cards:
        ss = skill_cards["skillspector"]
        aa = skill_cards["agent-audit"]
        claims.append(
            "4. **Skills are a distinct attack surface.** On the skills corpus "
            f"`skillspector` recalls {_pct(ss.recall)} ({ss.labels_detected}/{ss.labels_total}) "
            f"while the generic agent-code analyzer `agent-audit` recalls "
            f"{_pct(aa.recall)} ({aa.labels_detected}/{aa.labels_total}) — it never flags "
            "the Python environment exfiltration at all. Skill detection is a separate "
            "capability from agent-code analysis."
        )

    return claims


def render_findings(root: Path | None = None) -> str:
    """Render FINDINGS.md from the committed scorecards. Deterministic."""
    root = root or repo_root()
    mcp = _load_scope(root / "results")
    skills = _load_scope(root / "results" / "skills")
    mcp_counts, skills_counts = _corpus_counts(root)

    missed_mcp = _missed_by_all(mcp)
    missed_skills = _missed_by_all(skills)

    lines: list[str] = [
        "# MCP VulnLab — Findings",
        "",
        "> Generated from the committed scorecards under `results/`. "
        "Rebuild with `make findings` — never edit the numbers by hand.",
        "",
        "## Corpus",
        "",
        "| corpus | challenges | labels | categories | controls |",
        "|---|---:|---:|---:|---:|",
        f"| MCP servers | {mcp_counts['servers']} | {mcp_counts['labels']} | "
        f"{mcp_counts['categories']} | {mcp_counts['controls']} |",
        f"| Agent skills | {skills_counts['servers']} | {skills_counts['labels']} | "
        f"{skills_counts['categories']} | {skills_counts['controls']} |",
        "",
        "## Headline — every scanner, both corpora",
        "",
    ]
    lines.extend(_headline_rows([*((c, "MCP") for c in mcp), *((c, "skills") for c in skills)]))

    lines += ["", "## Recall by category — MCP servers", ""]
    lines.extend(_category_table(mcp))
    lines += ["", "## Recall by category — agent skills", ""]
    lines.extend(_category_table(skills))

    lines += ["", "## Missed by every scanner", "", "### MCP servers", ""]
    if not missed_mcp:
        lines.append("Nothing — every MCP label was caught by at least one scanner.")
    else:
        lines.extend(_missed_table(mcp, missed_mcp))

    lines += ["", "### Agent skills", ""]
    if not missed_skills:
        lines.append("Nothing — every skill label was caught by at least one scanner.")
    else:
        lines.extend(_missed_table(skills, missed_skills))

    lines += ["", "## What these numbers say", ""]
    lines.extend(_narrative(missed_mcp, mcp, skills))

    lines += [
        "",
        "## How this was measured",
        "",
        "Each scanner finding is attributed to at most one label by a conservative "
        "matching policy (tool-name exact > tool-name substring > declared detection "
        "signal); every unattributed finding counts as a false positive, and a scanner "
        "that could not run is recorded as *not run*, never as 0% recall. The full "
        "policy, per-scanner caveats, and reproduction commands are in "
        "[`docs/methodology.md`](docs/methodology.md).",
        "",
    ]
    return "\n".join(lines)
