"""Reporting tests. The scorecard is the deliverable, so its rendering is behaviour."""

from __future__ import annotations

from pathlib import Path

from conftest import make_finding, make_label, make_spec

from harness.report import render_comparison, render_json, render_markdown, render_text
from harness.score import build_scorecard


def _card(name: str = "unit", *, corpus_root: Path, control_finding: bool = False):
    specs = [
        make_spec(
            "alpha-server",
            labels=[
                make_label(
                    "MCPV-001", tool="alpha", category="prompt-injection", server="alpha-server"
                ),
                make_label(
                    "MCPV-002",
                    tool="beta",
                    category="missing-auth",
                    severity="critical",
                    server="alpha-server",
                ),
            ],
        ),
        make_spec("control-thing", kind="control", labels=[]),
    ]
    findings = [make_finding(server="alpha-server", tool="alpha", message="detected")]
    if control_finding:
        findings.append(make_finding(server="control-thing", message="looks suspicious"))
    return build_scorecard(name, specs, findings, corpus_root=corpus_root)


def test_markdown_reports_the_headline_numbers(tmp_path: Path) -> None:
    rendered = render_markdown(_card(corpus_root=tmp_path))
    assert "# Scorecard: `unit`" in rendered
    assert "50.0%" in rendered  # 1 of 2 labels
    assert "(1/2 labels)" in rendered


def test_markdown_lists_missed_labels_with_enough_context_to_act_on(tmp_path: Path) -> None:
    rendered = render_markdown(_card(corpus_root=tmp_path))
    assert "## Missed labels (1)" in rendered
    assert "MCPV-002" in rendered
    assert "missing-auth" in rendered
    assert "critical" in rendered
    assert "alpha-server" in rendered


def test_markdown_shows_false_positives_when_present(tmp_path: Path) -> None:
    rendered = render_markdown(_card(corpus_root=tmp_path, control_finding=True))
    assert "## False positives" in rendered
    assert "`control-thing`" in rendered
    assert "false positive by definition" in rendered


def test_markdown_says_so_when_there_are_no_false_positives(tmp_path: Path) -> None:
    rendered = render_markdown(_card(corpus_root=tmp_path))
    assert "Every finding was attributed to a label." in rendered


def test_markdown_records_the_matching_policy(tmp_path: Path) -> None:
    """A recall figure without its matching rule is not a reproducible number."""
    rendered = render_markdown(_card(corpus_root=tmp_path))
    assert "matching policy" in rendered


def test_unavailable_scanner_renders_without_crashing(tmp_path: Path) -> None:
    card = build_scorecard(
        "ghost",
        [make_spec("a", labels=[make_label("MCPV-001")])],
        [],
        corpus_root=tmp_path,
        available=False,
        unavailable_reason="command not found: 'ghost'",
    )
    markdown = render_markdown(card)
    text = render_text(card)
    assert "did not run" in markdown
    assert "NOT RUN" in text
    assert "ghost" in text


def test_text_rendering_is_terminal_friendly(tmp_path: Path) -> None:
    rendered = render_text(_card(corpus_root=tmp_path))
    assert "recall:" in rendered
    assert "by category" in rendered
    assert "alpha-server" in rendered
    assert "missed: MCPV-002" in rendered


def test_json_round_trips(tmp_path: Path) -> None:
    import json

    card = _card(corpus_root=tmp_path, control_finding=True)
    payload = json.loads(render_json(card))
    assert payload["summary"]["labels_total"] == 2
    assert payload["summary"]["false_positives"] == 1
    assert payload["labels"]["MCPV-002"]["severity"] == "critical"


def test_single_card_comparison_delegates_to_the_normal_report(tmp_path: Path) -> None:
    rendered = render_comparison([_card(corpus_root=tmp_path)])
    assert rendered.startswith("# Scorecard: `unit`")


def test_comparison_puts_every_scanner_in_one_table(tmp_path: Path) -> None:
    cards = [
        _card("scanner-a", corpus_root=tmp_path),
        _card("scanner-b", corpus_root=tmp_path, control_finding=True),
    ]
    rendered = render_comparison(cards)
    assert "## Headline" in rendered
    assert "`scanner-a`" in rendered and "`scanner-b`" in rendered
    assert "## Recall by category" in rendered


def test_comparison_reports_what_everyone_missed(tmp_path: Path) -> None:
    cards = [
        _card("scanner-a", corpus_root=tmp_path),
        _card("scanner-b", corpus_root=tmp_path),
    ]
    rendered = render_comparison(cards)
    assert "## Missed by every scanner that ran" in rendered
    assert "MCPV-002" in rendered


def test_comparison_ignores_scanners_that_did_not_run(tmp_path: Path) -> None:
    ran = _card("scanner-a", corpus_root=tmp_path)
    missing = build_scorecard(
        "scanner-b",
        [make_spec("alpha-server", labels=[make_label("MCPV-001", tool="alpha")])],
        [],
        corpus_root=tmp_path,
        available=False,
        unavailable_reason="not installed",
    )
    rendered = render_comparison([ran, missing])
    assert "*not run*" in rendered
    # The scanner that never ran must not drag labels into "missed by everyone".
    assert "## Missed by every scanner that ran" in rendered
    assert "Nothing. Every label was caught" not in rendered


def test_comparison_handles_no_cards() -> None:
    assert "No scorecards supplied" in render_comparison([])
