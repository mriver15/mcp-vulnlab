"""End-to-end tests: runner -> adapter -> score -> report, plus the CLI surface.

These launch real subprocesses, so they are marked `slow`.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from harness.adapters import ScannerProfile, load_profiles, select_profile
from harness.cli import main
from harness.corpus import build_index, discover_servers
from harness.model import SERVER_LEVEL, Scorecard, ServerSpec
from harness.runner import run_scanner, score_outcome, smoke, write_results

pytestmark = pytest.mark.slow

_BRACES = re.compile(r"\{[^}]*\}")


@pytest.fixture(scope="module")
def profiles(root: Path) -> list[ScannerProfile]:
    return load_profiles(root / "scanners.yaml")


def _score_replay(root: Path, specs: list[ServerSpec], profiles: list[ScannerProfile]) -> Scorecard:
    outcome = run_scanner(select_profile(profiles, "replay"), specs, cwd=root, timeout=90)
    assert outcome.available, outcome.reason
    return score_outcome(outcome, specs, corpus_root=root)


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #


def test_replay_scanner_scores_the_whole_corpus(
    root: Path, specs: list[ServerSpec], profiles: list[ScannerProfile]
) -> None:
    outcome = run_scanner(select_profile(profiles, "replay"), specs, cwd=root, timeout=90)
    assert len(outcome.invocations) == len(specs)
    assert outcome.findings, "the recording produced no findings at all"

    card = score_outcome(outcome, specs, corpus_root=root)
    assert card.labels_total == 12
    # The recording is authored to exercise all three paths: hit, miss, and FP.
    assert 0 < card.labels_detected < card.labels_total
    assert card.false_positives >= 1


def test_scorecard_is_reproducible_apart_from_the_timestamp(
    root: Path, specs: list[ServerSpec], profiles: list[ScannerProfile]
) -> None:
    """The README's reproducibility claim, enforced."""
    first = _score_replay(root, specs, profiles).to_json()
    second = _score_replay(root, specs, profiles).to_json()
    first.pop("generated_at")
    second.pop("generated_at")
    assert first == second


def test_unavailable_scanner_reports_rather_than_raising(
    root: Path, specs: list[ServerSpec]
) -> None:
    profile = ScannerProfile(name="ghost", command=["definitely-not-installed-xyz"])
    outcome = run_scanner(profile, specs, cwd=root, timeout=10)
    assert not outcome.available
    assert "not on PATH" in (outcome.reason or "")

    card = score_outcome(outcome, specs, corpus_root=root)
    assert card.recall is None, "an unavailable scanner must not be scored as 0% recall"


def test_placeholders_are_resolved_before_the_availability_check(
    root: Path, specs: list[ServerSpec]
) -> None:
    """Regression: a profile whose executable is {python} must not look missing."""
    profile = ScannerProfile(
        name="offline",
        command=["{python}", "-c", "import json,sys;print(json.dumps({'findings': []}))"],
    )
    outcome = run_scanner(profile, specs[:1], cwd=root, timeout=30)
    assert outcome.available, outcome.reason


def test_timeout_is_recorded_not_fatal(root: Path, specs: list[ServerSpec]) -> None:
    profile = ScannerProfile(name="slow", command=["{python}", "-c", "import time;time.sleep(30)"])
    outcome = run_scanner(profile, specs[:1], cwd=root, timeout=1)
    assert outcome.findings == []
    assert any("timed out" in note for note in outcome.notes)


def test_bad_scanner_output_becomes_a_note(root: Path, specs: list[ServerSpec]) -> None:
    profile = ScannerProfile(name="garbage", command=["{python}", "-c", "print('not json')"])
    outcome = run_scanner(profile, specs[:1], cwd=root, timeout=30)
    assert outcome.findings == []
    assert any("valid JSON" in note for note in outcome.notes)


def test_scanner_that_emits_nothing_is_recorded_as_not_run(
    root: Path, specs: list[ServerSpec]
) -> None:
    """Non-zero exit + no stdout is a failure to produce evidence, not 0% recall."""
    profile = ScannerProfile(
        name="silent-fail", command=["{python}", "-c", "import sys;sys.exit(1)"]
    )
    outcome = run_scanner(profile, specs[:2], cwd=root, timeout=30)
    assert not outcome.available
    assert "produced no output" in (outcome.reason or "")

    card = score_outcome(outcome, specs, corpus_root=root)
    assert card.recall is None, "a silent failure must not be scored as 0% recall"


def test_config_scanner_receives_a_generated_config(
    root: Path, specs: list[ServerSpec], tmp_path: Path
) -> None:
    """A scanner that only accepts a config file must get a real, rendered one."""
    code = (
        "import json,sys;"
        "cfg=json.load(open(sys.argv[1]));"
        "slug=list(cfg['mcpServers'])[0];"
        "print(json.dumps({'findings':[{'server':slug,'tool':'x','message':'saw config'}]}))"
    )
    profile = ScannerProfile(
        name="config-reader",
        command=["{python}", "-c", code, "{config}"],
        config_template={
            "mcpServers": {"{slug}": {"command": "{python}", "args": ["{entrypoint}"]}}
        },
    )
    outcome = run_scanner(profile, specs[:1], cwd=root, timeout=30, config_dir=tmp_path / "configs")
    assert outcome.available, outcome.reason
    assert outcome.findings and outcome.findings[0].server == specs[0].slug
    assert (tmp_path / "configs" / f"{specs[0].slug}.json").exists()


def test_results_are_written_and_reloadable(
    root: Path, specs: list[ServerSpec], profiles: list[ScannerProfile], tmp_path: Path
) -> None:
    outcome = run_scanner(
        select_profile(profiles, "replay"), specs, cwd=root, timeout=90, only={"injection-echo"}
    )
    card = score_outcome(outcome, specs, corpus_root=root)
    path = write_results(tmp_path / "replay", card, outcome)

    assert path.name == "scorecard.json"
    assert (tmp_path / "replay" / "scorecard.md").exists()
    assert (tmp_path / "replay" / "raw" / "invocations.json").exists()
    assert (tmp_path / "replay" / "raw" / "injection-echo.stdout.txt").exists()

    reloaded = Scorecard.from_json(json.loads(path.read_text(encoding="utf-8")))
    assert reloaded.scanner == "replay"
    assert reloaded.to_json() == card.to_json()


# --------------------------------------------------------------------------- #
# Corpus liveness — the strongest quality check the corpus can have
# --------------------------------------------------------------------------- #


def test_every_challenge_speaks_mcp(root: Path, specs: list[ServerSpec]) -> None:
    results = smoke(specs, cwd=root, timeout=60)
    failures = [(r["slug"], r["error"]) for r in results if not r["ok"]]
    assert not failures, f"challenges failed to speak MCP: {failures}"


def test_every_label_names_a_surface_that_actually_exists(
    root: Path, specs: list[ServerSpec]
) -> None:
    """A label pointing at a tool the server does not expose is unverifiable ground truth."""
    results = {entry["slug"]: entry for entry in smoke(specs, cwd=root, timeout=60)}

    problems: list[str] = []
    for spec in specs:
        entry = results[spec.slug]
        exposed = set(entry["tools"]) | set(entry["templates"]) | set(entry["resources"])
        for label in spec.labels:
            if label.tool == SERVER_LEVEL:
                continue
            stem = _BRACES.sub("", label.tool).strip()
            if label.tool in exposed or (stem and stem in exposed):
                continue
            problems.append(
                f"{label.id} names {label.tool!r}, but {spec.slug} exposes {sorted(exposed)}"
            )
    assert not problems, "\n".join(problems)


def test_challenges_do_not_leak_state_into_each_other(root: Path, specs: list[ServerSpec]) -> None:
    """Sanity: every server runs standalone from its own directory."""
    for spec in specs:
        assert spec.entrypoint_path.is_relative_to(spec.directory)
        assert spec.directory.parent.name == "servers"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_cli_validate_succeeds(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["validate"]) == 0
    assert "validation: OK" in capsys.readouterr().out


def test_cli_corpus_lists_every_server(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["corpus"]) == 0
    out = capsys.readouterr().out
    for spec in discover_servers(strict=True):
        assert spec.slug in out


def test_cli_index_writes_valid_json(
    root: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "index.json"
    assert main(["index", "--out", str(target)]) == 0
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["corpus"]["labels"] >= 12
    assert "wrote" in capsys.readouterr().out


def test_cli_run_and_report_round_trip(
    root: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "results"
    assert (
        main(["run", "--scanner", "replay", "--server", "injection-echo", "--out", str(out)]) == 0
    )
    assert (out / "replay" / "scorecard.json").exists()

    assert main(["report", "--in", str(out / "replay")]) == 0
    assert "Scorecard" in capsys.readouterr().out


def test_cli_report_can_write_a_file(
    root: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "results"
    main(["run", "--scanner", "replay", "--server", "pii-leak", "--out", str(out)])
    target = tmp_path / "scorecard.md"
    assert main(["report", "--in", str(out / "replay"), "--out", str(target)]) == 0
    assert target.read_text(encoding="utf-8").startswith("# Scorecard")
    assert "wrote" in capsys.readouterr().out


def test_cli_report_comparison_across_directories(
    root: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "results"
    main(["run", "--scanner", "replay", "--server", "exfil-write", "--out", str(out)])
    main(["run", "--scanner", "replay", "--server", "pii-leak", "--out", str(out / "copy")])
    assert main(["report", "--in", str(out / "replay"), "--in", str(out / "copy" / "replay")]) == 0
    assert "## Headline" in capsys.readouterr().out


def test_cli_rejects_an_unknown_scanner(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["run", "--scanner", "no-such-scanner"]) == 2
    assert "unknown scanner" in capsys.readouterr().err


def test_cli_rejects_an_unknown_server_filter(
    root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["run", "--scanner", "replay", "--server", "no-such-server"]) == 2
    assert "no challenges matched" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# Committed artifacts
# --------------------------------------------------------------------------- #


def test_committed_index_is_not_stale(root: Path) -> None:
    """CI regenerates the index; a stale committed copy should fail loudly."""
    committed = root / "corpus" / "labels" / "index.json"
    assert committed.exists(), "run `mcp-vulnlab index` and commit corpus/labels/index.json"
    assert json.loads(committed.read_text(encoding="utf-8")) == build_index(root)
