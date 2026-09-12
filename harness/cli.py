"""Command line interface for the harness.

mcp-vulnlab validate                  # is the corpus well-formed?
mcp-vulnlab corpus                    # what is in it?
mcp-vulnlab index                     # regenerate corpus/labels/index.json
mcp-vulnlab smoke                     # do the challenges speak MCP?
mcp-vulnlab run --scanner replay      # score one scanner (or --scanner all)
mcp-vulnlab report --in results/*     # render the scorecard
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from harness import __version__
from harness.adapters import AdapterError, ScannerProfile, load_profiles, select_profile
from harness.corpus import (
    build_index,
    discover_servers,
    repo_root,
    validate_corpus,
    write_index,
)
from harness.model import CATEGORIES, Scorecard
from harness.report import render_comparison, render_json, render_markdown, render_text
from harness.runner import run_scanner, score_outcome, smoke, write_results

DEFAULT_SCANNERS_FILE = "scanners.yaml"
DEFAULT_RESULTS_DIR = "results"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _root() -> Path:
    """Project root, falling back to the working directory outside a checkout."""
    try:
        return repo_root()
    except FileNotFoundError:
        return Path.cwd()


def _scanners_path(value: str | None) -> Path:
    if value:
        path = Path(value)
        return path if path.is_absolute() else (_root() / path)
    return _root() / DEFAULT_SCANNERS_FILE


def _load_profiles(value: str | None) -> list[ScannerProfile]:
    path = _scanners_path(value)
    if not path.exists():
        raise AdapterError(
            f"no scanner profiles at {path}. Pass --scanners or run from the repo root."
        )
    return load_profiles(path)


def _resolve_names(requested: list[str] | None, profiles: list[ScannerProfile]) -> list[str]:
    if not requested or "all" in requested:
        return [profile.name for profile in profiles]
    names: list[str] = []
    for entry in requested:
        names.extend(part for part in entry.split(",") if part)
    for name in names:
        select_profile(profiles, name)  # raises with the known list
    return names


def _load_scorecards(paths: list[str]) -> list[Scorecard]:
    cards: list[Scorecard] = []
    for entry in paths:
        path = Path(entry)
        if path.is_dir():
            path = path / "scorecard.json"
        if not path.exists():
            raise FileNotFoundError(f"no scorecard at {path}")
        cards.append(Scorecard.from_json(json.loads(path.read_text(encoding="utf-8"))))
    return cards


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #


def cmd_validate(args: argparse.Namespace) -> int:
    report = validate_corpus()
    print(report.render())
    if args.json:
        print(
            json.dumps(
                {
                    "ok": report.ok,
                    "servers": report.servers,
                    "labels": report.labels,
                    "issues": [str(issue) for issue in report.issues],
                },
                indent=2,
            )
        )
    return 0 if report.ok else 1


def cmd_corpus(args: argparse.Namespace) -> int:
    specs = discover_servers(strict=True)
    index = build_index()
    counts = index["corpus"]
    print(
        f"{counts['servers']} servers "
        f"({counts['vulnerable']} vulnerable, {counts['controls']} control), "
        f"{counts['labels']} labels across {counts['categories']} categories"
    )
    print()
    print(f"{'slug':<24}{'kind':<12}{'labels':>7}  categories")
    for spec in specs:
        categories = ", ".join(spec.categories) or "-"
        print(f"{spec.slug:<24}{spec.kind:<12}{len(spec.labels):>7}  {categories}")
    print()
    print("labels by category")
    for category in CATEGORIES:
        bucket = index["categories"].get(category, {"labels": 0, "servers": []})
        print(f"  {category:<24}{bucket['labels']:>3}  {', '.join(bucket['servers']) or '-'}")
    return 0


def cmd_index(args: argparse.Namespace) -> int:
    destination = Path(args.out) if args.out else None
    path = write_index(destination=destination)
    print(f"wrote {path}")
    return 0


def cmd_smoke(args: argparse.Namespace) -> int:
    specs = discover_servers(strict=True)
    if args.server:
        wanted = set(args.server)
        specs = [spec for spec in specs if spec.slug in wanted]
    results = smoke(specs, cwd=_root(), timeout=args.timeout)

    failures = 0
    for entry in results:
        if entry["ok"]:
            tools = ", ".join(entry["tools"]) or "(none)"
            extras = []
            if entry["resources"]:
                extras.append(f"resources: {', '.join(entry['resources'])}")
            if entry["templates"]:
                extras.append(f"templates: {', '.join(entry['templates'])}")
            suffix = f"  {'; '.join(extras)}" if extras else ""
            print(f"ok    {entry['slug']:<24} v{entry['version']:<8} tools: {tools}{suffix}")
        else:
            failures += 1
            print(f"FAIL  {entry['slug']:<24} {entry['error']}")

    if args.json:
        print(json.dumps(results, indent=2))
    print()
    print(f"{len(results) - failures}/{len(results)} servers responded over stdio")
    return 0 if failures == 0 else 1


def cmd_run(args: argparse.Namespace) -> int:
    root = _root()
    specs = discover_servers(strict=True)
    if args.server:
        wanted = set(args.server)
        specs = [spec for spec in specs if spec.slug in wanted]
        if not specs:
            print("no challenges matched --server", file=sys.stderr)
            return 2

    profiles = _load_profiles(args.scanners)
    names = _resolve_names(args.scanner, profiles)
    out_root = Path(args.out) if args.out else root / DEFAULT_RESULTS_DIR

    exit_code = 0
    for name in names:
        profile = select_profile(profiles, name)
        print(f"== {name}: {len(specs)} challenge(s)")
        outcome = run_scanner(
            profile,
            specs,
            timeout=args.timeout,
            cwd=root,
            config_dir=out_root / name / "configs",
        )
        card = score_outcome(outcome, specs, corpus_root=root)
        path = write_results(out_root / name, card, outcome)
        print(render_text(card), end="")
        print(f"-> {path}")
        if not outcome.available:
            exit_code = max(exit_code, 1)
    return exit_code


def cmd_report(args: argparse.Namespace) -> int:
    cards = _load_scorecards(args.input)
    if len(cards) > 1:
        rendered = render_comparison(cards)
    elif args.format == "json":
        rendered = render_json(cards[0])
    elif args.format == "text":
        rendered = render_text(cards[0])
    else:
        rendered = render_markdown(cards[0])

    if args.out:
        Path(args.out).write_text(rendered, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(rendered, end="" if rendered.endswith("\n") else "\n")
    return 0


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-vulnlab",
        description="Score any MCP scanner against a labeled corpus of vulnerable MCP servers.",
    )
    parser.add_argument("--version", action="version", version=f"mcp-vulnlab {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_validate = subparsers.add_parser("validate", help="validate every label and manifest")
    p_validate.add_argument("--json", action="store_true", help="also emit machine-readable output")
    p_validate.set_defaults(func=cmd_validate)

    p_corpus = subparsers.add_parser("corpus", help="print the corpus inventory")
    p_corpus.set_defaults(func=cmd_corpus)

    p_index = subparsers.add_parser("index", help="regenerate corpus/labels/index.json")
    p_index.add_argument("--out", help="destination path (default: corpus/labels/index.json)")
    p_index.set_defaults(func=cmd_index)

    p_smoke = subparsers.add_parser("smoke", help="launch each challenge over stdio and list tools")
    p_smoke.add_argument("--server", action="append", help="limit to these slugs; repeatable")
    p_smoke.add_argument("--timeout", type=float, default=30.0)
    p_smoke.add_argument("--json", action="store_true", help="also emit machine-readable output")
    p_smoke.set_defaults(func=cmd_smoke)

    p_run = subparsers.add_parser("run", help="run a scanner across the corpus and score it")
    p_run.add_argument(
        "--scanner",
        action="append",
        help="scanner name from scanners.yaml, or 'all'. Repeatable, comma-separated allowed. "
        "Default: all.",
    )
    p_run.add_argument("--server", action="append", help="limit to these slugs; repeatable")
    p_run.add_argument("--scanners", help=f"profiles file (default: {DEFAULT_SCANNERS_FILE})")
    p_run.add_argument("--out", help=f"output directory (default: {DEFAULT_RESULTS_DIR}/<scanner>)")
    p_run.add_argument(
        "--timeout", type=float, default=120.0, help="per-invocation timeout in seconds"
    )
    p_run.set_defaults(func=cmd_run)

    p_report = subparsers.add_parser("report", help="render a saved scorecard")
    p_report.add_argument(
        "--in",
        dest="input",
        action="append",
        required=True,
        help="scorecard.json, a results directory, or several of them for a comparison. Repeatable.",
    )
    p_report.add_argument("--format", choices=["markdown", "text", "json"], default="markdown")
    p_report.add_argument("--out", help="write to a file instead of stdout")
    p_report.set_defaults(func=cmd_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (AdapterError, FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
