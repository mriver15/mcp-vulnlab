"""The scorer decides the numbers this project publishes, so it gets the closest tests."""

from __future__ import annotations

from pathlib import Path

from conftest import make_finding, make_label, make_spec

from harness.model import SERVER_LEVEL, Finding
from harness.score import SIGNAL, TOOL_EXACT, MatchPolicy, build_scorecard, score_server


def test_exact_tool_match_detects_the_label() -> None:
    spec = make_spec(labels=[make_label("MCPV-001", tool="save_report")])
    score = score_server(spec, [make_finding(tool="save_report", message="bad")])
    assert score.detected_ids == ["MCPV-001"]
    assert score.missed_ids == []


def test_tool_match_is_case_insensitive() -> None:
    spec = make_spec(labels=[make_label("MCPV-001", tool="save_report")])
    score = score_server(spec, [make_finding(tool="SAVE_REPORT", message="bad")])
    assert score.detected_ids == ["MCPV-001"]


def test_tool_name_inside_the_message_also_counts() -> None:
    """Real scanners name the tool in prose far more often than in a field."""
    spec = make_spec(labels=[make_label("MCPV-001", tool="save_report")])
    score = score_server(spec, [make_finding(message="save_report writes anywhere")])
    assert score.detected_ids == ["MCPV-001"]
    assert "strength 2" in score.matches[0].reason


def test_resource_template_matches_on_its_literal_stem() -> None:
    spec = make_spec(labels=[make_label("MCPV-004", tool="report://{path}")])
    score = score_server(spec, [make_finding(message="resource report:// exposes files")])
    assert score.detected_ids == ["MCPV-004"]


def test_signal_match_detects_the_label() -> None:
    spec = make_spec(labels=[make_label("MCPV-005", tool="find_files", signals=["wildcard root"])])
    score = score_server(spec, [make_finding(message="A wildcard root is used here")])
    assert score.detected_ids == ["MCPV-005"]
    assert "signal match" in score.matches[0].reason


def test_short_signals_are_ignored_to_prevent_accidental_matches() -> None:
    spec = make_spec(labels=[make_label("MCPV-005", tool="find_files", signals=["ab"])])
    policy = MatchPolicy(min_signal_length=4)
    score = score_server(spec, [make_finding(message="ab is everywhere")], policy)
    assert score.detected_ids == []


def test_server_level_labels_match_on_signals_only() -> None:
    spec = make_spec(labels=[make_label("MCPV-012", tool=SERVER_LEVEL, signals=["unpinned"])])
    score = score_server(spec, [make_finding(message="requirements.txt is unpinned")])
    assert score.detected_ids == ["MCPV-012"]


def test_one_finding_cannot_satisfy_two_labels() -> None:
    """Deliberate: this is what stops a single vague finding inflating recall."""
    spec = make_spec(
        labels=[
            make_label("MCPV-001", tool="alpha", signals=["danger"]),
            make_label("MCPV-002", tool="beta", signals=["danger"]),
        ]
    )
    score = score_server(spec, [make_finding(tool="alpha", message="danger everywhere")])
    assert score.detected_ids == ["MCPV-001"]
    assert score.missed_ids == ["MCPV-002"]


def test_strongest_match_wins_regardless_of_finding_order() -> None:
    spec = make_spec(
        labels=[
            make_label("MCPV-001", tool="alpha"),
            make_label("MCPV-002", tool="beta", signals=["alpha is mentioned"]),
        ]
    )
    # The finding names alpha in prose only, which is a weaker match than a tool field.
    score = score_server(spec, [make_finding(tool="beta", message="alpha is mentioned")])
    assert set(score.detected_ids) == {"MCPV-002"}
    assert score.missed_ids == ["MCPV-001"]


def test_two_findings_detect_two_labels() -> None:
    spec = make_spec(
        labels=[make_label("MCPV-001", tool="alpha"), make_label("MCPV-002", tool="beta")]
    )
    score = score_server(spec, [make_finding(tool="alpha"), make_finding(tool="beta")])
    assert score.detected_ids == ["MCPV-001", "MCPV-002"]


def test_findings_that_match_nothing_are_false_positives() -> None:
    spec = make_spec(labels=[make_label("MCPV-001", tool="alpha")])
    score = score_server(spec, [make_finding(tool="alpha"), make_finding(tool="unrelated")])
    assert len(score.matches) == 1
    assert len(score.false_positives) == 1
    assert score.false_positives[0].tool == "unrelated"


def test_every_finding_on_a_control_is_a_false_positive() -> None:
    spec = make_spec(kind="control", labels=[])
    score = score_server(spec, [make_finding(message="something looks risky")])
    assert score.labels_total == 0
    assert len(score.false_positives) == 1


def test_missed_ids_are_the_complement_of_detected() -> None:
    spec = make_spec(
        labels=[
            make_label("MCPV-001", tool="alpha"),
            make_label("MCPV-002", tool="beta"),
            make_label("MCPV-003", tool="gamma"),
        ]
    )
    score = score_server(spec, [make_finding(tool="beta")])
    assert score.detected_ids == ["MCPV-002"]
    assert score.missed_ids == ["MCPV-001", "MCPV-003"]


def test_findings_are_scoped_to_their_server() -> None:
    """score_server must ignore other servers' findings rather than silently mis-attribute them."""
    spec = make_spec(labels=[make_label("MCPV-001", tool="alpha")])
    other = make_spec("other")
    findings = [make_finding(server="other", tool="alpha")]
    assert score_server(spec, findings).detected_ids == []
    assert score_server(spec, findings).findings_total == 0
    assert score_server(other, findings).findings_total == 1


def test_scoring_is_deterministic() -> None:
    """The reproducibility claim in the README depends on this."""
    spec = make_spec(
        labels=[make_label("MCPV-001", tool="alpha"), make_label("MCPV-002", tool="beta")]
    )
    findings = [make_finding(tool="beta"), make_finding(tool="alpha")]
    first = score_server(spec, findings)
    second = score_server(spec, findings)
    assert first.to_json() == second.to_json()


def test_scorecard_aggregates_and_records_its_policy(tmp_path: Path) -> None:
    specs = [
        make_spec("a", labels=[make_label("MCPV-001", tool="alpha")]),
        make_spec("b", kind="control", labels=[]),
    ]
    findings = [make_finding(server="a", tool="alpha"), make_finding(server="b", tool="noise")]
    card = build_scorecard("unit", specs, findings, corpus_root=tmp_path)

    assert card.labels_total == 1
    assert card.labels_detected == 1
    assert card.recall == 1.0
    assert card.findings_total == 2
    assert card.true_positives == 1
    assert card.false_positives == 1
    assert card.fp_rate == 0.5
    assert any("matching policy" in note for note in card.notes)


def test_scorecard_round_trips_through_json(tmp_path: Path) -> None:
    specs = [make_spec("a", labels=[make_label("MCPV-001", tool="alpha")])]
    findings = [make_finding(server="a", tool="alpha"), make_finding(server="a", tool="noise")]
    card = build_scorecard("unit", specs, findings, corpus_root=tmp_path)

    restored = type(card).from_json(card.to_json())
    assert restored.scanner == card.scanner
    assert restored.recall == card.recall
    assert restored.false_positives == card.false_positives
    assert restored.by_category() == card.by_category()
    assert restored.label("MCPV-001")["category"] == card.label("MCPV-001")["category"]


def test_unavailable_scanner_reports_no_recall_rather_than_zero(tmp_path: Path) -> None:
    """A scanner that could not run is not a scanner that found nothing."""
    card = build_scorecard(
        "missing",
        [make_spec("a", labels=[make_label("MCPV-001")])],
        [],
        corpus_root=tmp_path,
        available=False,
        unavailable_reason="command not found",
    )
    assert card.recall is None
    assert card.fp_rate is None
    assert card.to_json()["unavailable_reason"] == "command not found"


def test_by_category_groups_labels_correctly(tmp_path: Path) -> None:
    specs = [
        make_spec(
            "a",
            labels=[
                make_label("MCPV-001", tool="alpha", category="prompt-injection"),
                make_label("MCPV-002", tool="beta", category="missing-auth"),
            ],
        )
    ]
    card = build_scorecard(
        "unit", specs, [make_finding(server="a", tool="alpha")], corpus_root=tmp_path
    )
    categories = card.by_category()
    assert categories["prompt-injection"] == {"total": 1, "detected": 1, "ids": ["MCPV-001"]}
    assert categories["missing-auth"] == {"total": 1, "detected": 0, "ids": ["MCPV-002"]}


def test_unknown_server_slugs_are_noted_not_silently_dropped(tmp_path: Path) -> None:
    findings: list[Finding] = [make_finding(server="ghost", tool="alpha")]
    card = build_scorecard("unit", [make_spec("a")], findings, corpus_root=tmp_path)
    assert any("ghost" in note for note in card.notes)


def test_strength_constants_are_ordered() -> None:
    assert TOOL_EXACT > SIGNAL > 0
    assert SERVER_LEVEL == "(server)"
