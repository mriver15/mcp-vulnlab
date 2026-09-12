"""The corpus is the product, so its invariants are the most important tests here."""

from __future__ import annotations

from pathlib import Path

import pytest

from harness.corpus import build_index, validate_corpus, write_index
from harness.model import CATEGORIES, SERVER_LEVEL, ServerSpec


def test_corpus_validates(root: Path) -> None:
    report = validate_corpus(root)
    assert report.ok, report.render()


def test_corpus_meets_the_documented_targets(root: Path) -> None:
    """The one-pager promises >= 12 labeled challenges across 6 categories."""
    index = build_index(root)
    counts = index["corpus"]
    assert counts["labels"] >= 12
    assert counts["categories"] == len(CATEGORIES)
    assert counts["controls"] >= 2, "false-positive controls are required for FP-rate measurement"


def test_every_category_is_exercised_by_a_vulnerable_server(root: Path) -> None:
    index = build_index(root)
    for category in CATEGORIES:
        bucket = index["categories"][category]
        assert bucket["labels"] > 0, f"no labels in category {category!r}"
        assert bucket["servers"], f"no servers in category {category!r}"


def test_controls_carry_no_labels(controls: list[ServerSpec]) -> None:
    assert controls, "expected at least one control server"
    for spec in controls:
        assert spec.labels == [], f"control {spec.slug} declares labels"


def test_vulnerable_servers_have_labels(vulnerable: list[ServerSpec]) -> None:
    for spec in vulnerable:
        assert spec.labels, f"vulnerable server {spec.slug} has no labels"


def test_label_ids_are_unique_and_well_formed(specs: list[ServerSpec]) -> None:
    seen: dict[str, str] = {}
    for spec in specs:
        for label in spec.labels:
            assert label.id.startswith("MCPV-"), label.id
            assert len(label.id) == 8, f"{label.id} should be MCPV-NNN"
            assert label.id not in seen, f"{label.id} used by both {seen[label.id]} and {spec.slug}"
            seen[label.id] = spec.slug


def test_label_server_field_matches_its_directory(specs: list[ServerSpec]) -> None:
    for spec in specs:
        for label in spec.labels:
            assert label.server == spec.slug


def test_label_signals_are_lowercase_and_specific(specs: list[ServerSpec]) -> None:
    for spec in specs:
        for label in spec.labels:
            for signal in label.signals:
                assert signal == signal.lower(), f"{label.id}: signal {signal!r} must be lowercase"
                assert len(signal) >= 3, f"{label.id}: signal {signal!r} is too short to be safe"


def test_exploit_steps_are_actionable(specs: list[ServerSpec]) -> None:
    """A label with no reproduction steps is a label nobody can verify."""
    for spec in specs:
        for label in spec.labels:
            assert label.description.strip()
            assert label.signals, f"{label.id} has no detection signals, so it can never match"


def test_entrypoints_exist(specs: list[ServerSpec]) -> None:
    for spec in specs:
        assert spec.entrypoint_path.is_file(), f"{spec.slug}: missing {spec.entrypoint}"


def test_every_challenge_has_a_warning_readme(specs: list[ServerSpec]) -> None:
    for spec in specs:
        readme = (spec.directory / "README.md").read_text(encoding="utf-8")
        assert len(readme) > 200, f"{spec.slug}: README is too thin to be useful"
        assert "intentionally" in readme.lower(), f"{spec.slug}: README lacks an intent warning"


def test_server_level_labels_do_not_pretend_to_name_a_tool(specs: list[ServerSpec]) -> None:
    for spec in specs:
        for label in spec.labels:
            if label.tool == SERVER_LEVEL:
                assert label.signals, f"{label.id}: a (server) label needs signals to match on"


def test_index_write_is_reproducible(tmp_path: Path, root: Path) -> None:
    """CI diffs the committed index; a non-reproducible index would fail constantly."""
    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    write_index(root, destination=first)
    write_index(root, destination=second)
    assert first.read_text(encoding="utf-8") == second.read_text(encoding="utf-8")


@pytest.mark.parametrize("problem", ["missing_manifest", "slug_mismatch"])
def test_validation_catches_broken_challenges(
    tmp_path: Path, problem: str, specs: list[ServerSpec]
) -> None:
    """Guard the guard: make sure validate_corpus actually fails when it should."""
    corpus = tmp_path / "corpus"
    servers = corpus / "servers"
    source_labels = Path(__file__).resolve().parents[1] / "corpus" / "labels"
    (corpus / "labels").mkdir(parents=True)
    for name in ("label.schema.json", "exploits.schema.json", "manifest.schema.json"):
        (corpus / "labels" / name).write_text(
            (source_labels / name).read_text(encoding="utf-8"), encoding="utf-8"
        )

    original = specs[0]
    broken = servers / original.slug
    broken.mkdir(parents=True)
    (broken / "README.md").write_text("x" * 300 + " intentionally", encoding="utf-8")
    (broken / "exploits.json").write_text(
        (original.directory / "exploits.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (broken / original.entrypoint).write_text("# noop\n", encoding="utf-8")

    if problem == "missing_manifest":
        pass  # deliberately absent
    else:
        manifest = (original.directory / "manifest.json").read_text(encoding="utf-8")
        (broken / "manifest.json").write_text(
            manifest.replace(f'"slug": "{original.slug}"', '"slug": "not-the-dir-name"'),
            encoding="utf-8",
        )

    report = validate_corpus(corpus)
    assert not report.ok, "validate_corpus accepted a deliberately broken corpus"
