"""Render scorecards as Markdown, plain text, or JSON.

Markdown is the primary format: the headline metric of this project *is* the
published scorecard, so rendering it well is the deliverable, not a side quest.
"""

from __future__ import annotations

import json

from harness.model import Scorecard

_DASH = "\u2014"


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def _bar(detected: int, total: int) -> str:
    """A tiny visual so a 0/N category is impossible to miss when skimming."""
    if total == 0:
        return _DASH
    filled = round(detected / total * 10)
    return f"`{'#' * filled}{'.' * (10 - filled)}`"


def _summary_lines(card: Scorecard) -> list[tuple[str, str]]:
    if not card.available:
        return [
            ("status", f"not run {_DASH} {card.unavailable_reason or 'scanner unavailable'}"),
        ]
    return [
        ("recall", f"{_pct(card.recall)} ({card.labels_detected}/{card.labels_total} labels)"),
        ("findings", str(card.findings_total)),
        ("true positives", str(card.true_positives)),
        (
            "false positives",
            f"{card.false_positives} (rate {_pct(card.fp_rate)})",
        ),
    ]


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #


def render_markdown(card: Scorecard, *, heading: str | None = None) -> str:
    lines: list[str] = []
    lines.append(heading or f"# Scorecard: `{card.scanner}`")
    lines.append("")
    lines.append(f"Generated {card.generated_at} against `{card.corpus_root}`.")
    lines.append("")

    if not card.available:
        lines.append("> **This scanner did not run.** The figures below are absent, not zero.")
        lines.append(f"> Reason: {card.unavailable_reason or 'unavailable'}")
        lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| metric | value |")
    lines.append("|---|---|")
    for name, value in _summary_lines(card):
        lines.append(f"| {name} | {value} |")
    lines.append("")

    lines.append("## Recall by category")
    lines.append("")
    lines.append("| category | detected | total | recall | |")
    lines.append("|---|---:|---:|---:|---|")
    for category, bucket in card.by_category().items():
        detected, total = bucket["detected"], bucket["total"]
        recall = _pct(detected / total if total else None)
        lines.append(
            f"| `{category}` | {detected} | {total} | {recall} | {_bar(detected, total)} |"
        )
    lines.append("")

    lines.append("## Per server")
    lines.append("")
    lines.append("| server | kind | labels | detected | findings | false positives |")
    lines.append("|---|---|---:|---:|---:|---:|")
    for score in card.servers:
        lines.append(
            f"| `{score.slug}` | {score.kind} | {score.labels_total} | "
            f"{score.labels_detected} | {score.findings_total} | {len(score.false_positives)} |"
        )
    lines.append("")

    missed = [
        (label_id, card.label(label_id)) for score in card.servers for label_id in score.missed_ids
    ]
    lines.append(f"## Missed labels ({len(missed)})")
    lines.append("")
    if not missed:
        lines.append("None. This scanner detected every labeled weakness in the corpus.")
    else:
        lines.append("| id | category | severity | server | tool | title |")
        lines.append("|---|---|---|---|---|---|")
        for label_id, info in sorted(missed):
            lines.append(
                f"| `{label_id}` | `{info.get('category', '?')}` | {info.get('severity', '?')} | "
                f"`{info.get('server', '?')}` | `{info.get('tool', '?')}` | "
                f"{info.get('title', '?')} |"
            )
    lines.append("")

    lines.append("## False positives")
    lines.append("")
    total_fp = card.false_positives
    if total_fp == 0:
        lines.append("None. Every finding was attributed to a label.")
    else:
        lines.append(
            f"{total_fp} finding(s) matched no label. For a `control` server that is a "
            "false positive by definition."
        )
        lines.append("")
        lines.append("| server | kind | rule | tool | message |")
        lines.append("|---|---|---|---|---|")
        for score in card.servers:
            for finding in score.false_positives:
                message = " ".join((finding.message or "").split())[:160]
                message = message.replace("|", "\\|")
                lines.append(
                    f"| `{score.slug}` | {score.kind} | `{finding.rule_id or _DASH}` | "
                    f"`{finding.tool or _DASH}` | {message} |"
                )
    lines.append("")

    if card.notes:
        lines.append("## Notes")
        lines.append("")
        lines.extend(f"- {note}" for note in card.notes)
        lines.append("")

    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Plain text
# --------------------------------------------------------------------------- #


def render_text(card: Scorecard) -> str:
    lines: list[str] = []
    lines.append(f"scorecard: {card.scanner}  ({card.generated_at})")
    lines.append(f"corpus:    {card.corpus_root}")
    lines.append("")

    if not card.available:
        lines.append(f"STATUS: NOT RUN {'-'} {card.unavailable_reason or 'unavailable'}")
        return "\n".join(lines) + "\n"

    lines.append(f"recall:    {_pct(card.recall)}  ({card.labels_detected}/{card.labels_total})")
    lines.append(
        f"findings:  {card.findings_total}  (TP {card.true_positives}, FP {card.false_positives})"
    )
    lines.append("")

    lines.append("by category")
    for category, bucket in card.by_category().items():
        detected, total = bucket["detected"], bucket["total"]
        lines.append(
            f"  {category:<24} {detected}/{total}  {_pct(detected / total if total else None)}"
        )
    lines.append("")

    lines.append(f"{'server':<24}{'kind':<12}{'labels':>7}{'found':>7}{'findings':>10}{'FP':>5}")
    for score in card.servers:
        lines.append(
            f"{score.slug:<24}{score.kind:<12}{score.labels_total:>7}"
            f"{score.labels_detected:>7}{score.findings_total:>10}{len(score.false_positives):>5}"
        )
    lines.append("")

    missed = sorted(label_id for score in card.servers for label_id in score.missed_ids)
    if missed:
        lines.append(f"missed: {', '.join(missed)}")
    return "\n".join(lines) + "\n"


def render_json(card: Scorecard) -> str:
    return json.dumps(card.to_json(), indent=2) + "\n"


# --------------------------------------------------------------------------- #
# Multi-scanner comparison — the headline artifact
# --------------------------------------------------------------------------- #


def render_comparison(cards: list[Scorecard], *, heading: str = "# MCP VulnLab scorecard") -> str:
    """Render several scanners side by side.

    This is the output the project exists to produce: per-scanner recall, the
    per-category breakdown, and the labels no scanner caught.
    """
    if not cards:
        return f"{heading}\n\nNo scorecards supplied.\n"
    if len(cards) == 1:
        # A single scanner is not a comparison; use the detailed per-scanner report
        # so the scanner's name ends up in the title.
        return render_markdown(cards[0])

    names = [card.scanner for card in cards]
    lines: list[str] = [heading, ""]
    lines.append(f"Scanners: {', '.join(f'`{name}`' for name in names)}")
    lines.append("")
    lines.append(
        "> Coverage is measured against the labeled corpus. A scanner that could not be "
        "run is shown as *not run* — absence of evidence, not evidence of absence."
    )
    lines.append("")

    lines.append("## Headline")
    lines.append("")
    lines.append("| scanner | recall | detected | missed | findings | false positives | FP rate |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    for card in cards:
        if not card.available:
            lines.append(
                f"| `{card.scanner}` | *not run* | {_DASH} | {_DASH} | {_DASH} | {_DASH} | {_DASH} |"
            )
            continue
        lines.append(
            f"| `{card.scanner}` | {_pct(card.recall)} | {card.labels_detected}/{card.labels_total} | "
            f"{card.labels_total - card.labels_detected} | {card.findings_total} | "
            f"{card.false_positives} | {_pct(card.fp_rate)} |"
        )
    lines.append("")

    lines.append("## Recall by category")
    lines.append("")
    header = "| category | " + " | ".join(f"`{name}`" for name in names) + " |"
    lines.append(header)
    lines.append("|---|" + "---:|" * len(names))
    categories = sorted({category for card in cards for category in card.by_category()})
    for category in categories:
        cells: list[str] = []
        for card in cards:
            bucket = card.by_category().get(category)
            if not card.available or bucket is None:
                cells.append(_DASH)
            else:
                detected, total = bucket["detected"], bucket["total"]
                cells.append(f"{detected}/{total} ({_pct(detected / total if total else None)})")
        lines.append(f"| `{category}` | " + " | ".join(cells) + " |")
    lines.append("")

    available = [card for card in cards if card.available]
    missed_by_all = (
        sorted(set.intersection(*(card_missed(card) for card in available))) if available else []
    )
    lines.append("## Missed by every scanner that ran")
    lines.append("")
    if not missed_by_all:
        lines.append("Nothing. Every label was caught by at least one scanner.")
    else:
        lines.append("| id | category | severity | server | tool | title |")
        lines.append("|---|---|---|---|---|---|")
        reference = next(card for card in cards if card.available)
        for label_id in missed_by_all:
            info = reference.label(label_id)
            lines.append(
                f"| `{label_id}` | `{info.get('category', '?')}` | {info.get('severity', '?')} | "
                f"`{info.get('server', '?')}` | `{info.get('tool', '?')}` | {info.get('title', '?')} |"
            )
    lines.append("")
    return "\n".join(lines)


def card_missed(card: Scorecard) -> set[str]:
    return {label_id for score in card.servers for label_id in score.missed_ids}
