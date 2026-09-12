"""Run scanners against the corpus and persist the raw evidence.

The runner does not talk to the MCP servers itself. Each scanner is responsible
for launching the challenge it is pointed at — the adapter profile supplies the
argv with `{entrypoint}` and friends substituted. That mirrors how these tools
actually work and keeps the harness from pretending to be one.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from harness.adapters import AdapterError, ScannerProfile, parse_output
from harness.model import Finding, Scorecard, ServerSpec
from harness.score import MatchPolicy, build_scorecard

DEFAULT_TIMEOUT = 120.0
SMOKE_TIMEOUT = 30.0


@dataclass
class Invocation:
    """One scanner run against one challenge."""

    slug: str
    argv: list[str]
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    error: str | None = None
    findings: int = 0
    config: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "slug": self.slug,
            "argv": self.argv,
            "returncode": self.returncode,
            "error": self.error,
            "findings": self.findings,
            "config": self.config,
        }


@dataclass
class ScannerOutcome:
    """Everything one scanner produced across the corpus."""

    profile: ScannerProfile
    findings: list[Finding] = field(default_factory=list)
    available: bool = True
    reason: str | None = None
    notes: list[str] = field(default_factory=list)
    invocations: list[Invocation] = field(default_factory=list)


def _executable_exists(token: str, python: str) -> bool:
    if token == python:
        return True
    if Path(token).exists():
        return True
    return shutil.which(token) is not None


def run_scanner(
    profile: ScannerProfile,
    specs: list[ServerSpec],
    *,
    python: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    cwd: Path | None = None,
    only: set[str] | None = None,
    config_dir: Path | None = None,
) -> ScannerOutcome:
    """Run one scanner across every challenge. Never raises for scanner problems."""
    interpreter = python or sys.executable
    working_directory = cwd or Path.cwd()
    outcome = ScannerOutcome(profile=profile)

    targets = [spec for spec in specs if only is None or spec.slug in only]
    if not targets:
        outcome.available = False
        outcome.reason = "no challenges matched the --server filter"
        return outcome

    # Availability has to be tested on a *rendered* argv, because a profile may
    # legitimately use {python} as its executable (see the offline `replay`
    # scanner). Checking profile.command[0] verbatim would report "{python} is not
    # on PATH", which is exactly the bug this ordering avoids.
    try:
        probe_argv = profile.render_command(
            server_dir=targets[0].directory,
            entrypoint=targets[0].entrypoint_path,
            slug=targets[0].slug,
            python=interpreter,
        )
    except AdapterError as exc:
        outcome.available = False
        outcome.reason = str(exc)
        return outcome

    executable = probe_argv[0]
    if not _executable_exists(executable, interpreter):
        outcome.available = False
        outcome.reason = f"command not found: {executable!r} is not on PATH"
        return outcome

    for spec in targets:
        config_path: Path | None = None
        if profile.needs_config:
            # Some scanners only accept a client config file, never a server command.
            # Materialise one per challenge so the argv has something to point at.
            destination = (config_dir or working_directory / ".mcpvulnlab-configs") / (
                f"{spec.slug}.json"
            )
            try:
                document = profile.render_config(
                    server_dir=spec.directory,
                    entrypoint=spec.entrypoint_path,
                    slug=spec.slug,
                    python=interpreter,
                )
            except AdapterError as exc:
                outcome.notes.append(f"{spec.slug}: {exc}")
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
            config_path = destination

        # Some scanners write their report to a file (`{out_file}`) rather than to
        # stdout. Give each invocation its own path so concurrent runs cannot collide.
        out_file: Path | None = None
        if profile.output_to_file:
            out_dir = (config_dir or working_directory / ".mcpvulnlab-configs") / "out"
            out_dir.mkdir(parents=True, exist_ok=True)
            out_file = out_dir / f"{spec.slug}.json"

        try:
            argv = profile.render_command(
                server_dir=spec.directory,
                entrypoint=spec.entrypoint_path,
                slug=spec.slug,
                python=interpreter,
                config=config_path,
                out_file=out_file,
            )
        except AdapterError as exc:
            outcome.notes.append(str(exc))
            continue

        # The generated config path is recorded so a disputed run can be replayed
        # without regenerating anything by hand.
        invocation = Invocation(
            slug=spec.slug, argv=argv, config=str(config_path) if config_path else None
        )
        try:
            completed = subprocess.run(
                argv,
                cwd=working_directory,
                capture_output=True,
                text=True,
                timeout=timeout,
                env={**os.environ, **spec.env},
                check=False,
                # A scanner must not be able to hang the harness on an interactive
                # prompt: anything it prompts for on stdin is answered with EOF.
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            invocation.error = f"timed out after {timeout:g}s"
            outcome.notes.append(f"{spec.slug}: timed out after {timeout:g}s")
            outcome.invocations.append(invocation)
            continue
        except OSError as exc:
            invocation.error = f"could not launch: {exc}"
            outcome.notes.append(f"{spec.slug}: could not launch: {exc}")
            outcome.invocations.append(invocation)
            continue

        invocation.returncode = completed.returncode
        invocation.stdout = completed.stdout
        invocation.stderr = completed.stderr

        # Read back a file-based report, if the profile expects one.
        output_text = completed.stdout
        if profile.output_to_file:
            if out_file is not None and out_file.exists():
                output_text = out_file.read_text(encoding="utf-8")
                invocation.stdout = output_text  # keep the parsed report, not the banner
            else:
                invocation.error = f"expected report at {out_file}, but it was not written"
                outcome.notes.append(f"{spec.slug}: {invocation.error}")
                outcome.invocations.append(invocation)
                continue

        if completed.returncode != 0:
            outcome.notes.append(f"{spec.slug}: scanner exited with status {completed.returncode}")

        # A non-zero exit with no output at all is a failure to produce evidence,
        # not a clean scan. Scoring it as "found nothing" would understate the
        # scanner and silently corrupt the recall figure.
        if completed.returncode != 0 and not output_text.strip():
            invocation.error = f"exited with status {completed.returncode} and produced no output"
            outcome.notes.append(f"{spec.slug}: {invocation.error}")
            outcome.invocations.append(invocation)
            continue

        try:
            found = parse_output(profile, spec.slug, output_text, completed.stderr)
        except AdapterError as exc:
            invocation.error = str(exc)
            outcome.notes.append(f"{spec.slug}: {exc}")
            outcome.invocations.append(invocation)
            continue

        invocation.findings = len(found)
        outcome.findings.extend(found)
        outcome.invocations.append(invocation)

    # If nothing succeeded, this scanner did not run. Reporting 0% recall for a
    # scanner that never produced output would be a fabricated measurement.
    if outcome.invocations and all(invocation.error for invocation in outcome.invocations):
        outcome.available = False
        outcome.reason = f"every invocation failed; first error: {outcome.invocations[0].error}"
        outcome.findings = []

    return outcome


def score_outcome(
    outcome: ScannerOutcome,
    specs: list[ServerSpec],
    *,
    corpus_root: Path,
    policy: MatchPolicy | None = None,
) -> Scorecard:
    return build_scorecard(
        outcome.profile.name,
        specs,
        outcome.findings,
        corpus_root=corpus_root,
        available=outcome.available,
        unavailable_reason=outcome.reason,
        policy=policy or MatchPolicy(),
        notes=outcome.notes,
    )


def write_results(out_dir: Path, card: Scorecard, outcome: ScannerOutcome) -> Path:
    """Persist the scorecard plus the raw scanner output it was derived from."""
    from harness.report import render_markdown

    out_dir.mkdir(parents=True, exist_ok=True)
    scorecard_path = out_dir / "scorecard.json"
    scorecard_path.write_text(json.dumps(card.to_json(), indent=2) + "\n", encoding="utf-8")
    (out_dir / "scorecard.md").write_text(render_markdown(card) + "\n", encoding="utf-8")

    raw_dir = out_dir / "raw"
    raw_dir.mkdir(exist_ok=True)
    (raw_dir / "invocations.json").write_text(
        json.dumps([inv.to_json() for inv in outcome.invocations], indent=2) + "\n",
        encoding="utf-8",
    )
    for invocation in outcome.invocations:
        if invocation.stdout.strip():
            (raw_dir / f"{invocation.slug}.stdout.txt").write_text(
                invocation.stdout, encoding="utf-8"
            )
        if invocation.stderr.strip():
            (raw_dir / f"{invocation.slug}.stderr.txt").write_text(
                invocation.stderr, encoding="utf-8"
            )
    return scorecard_path


# --------------------------------------------------------------------------- #
# Smoke test: does each challenge actually speak MCP?
# --------------------------------------------------------------------------- #


async def _probe(
    spec: ServerSpec,
    interpreter: str,
    working_directory: Path,
) -> dict[str, Any]:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    entry: dict[str, Any] = {
        "slug": spec.slug,
        "ok": False,
        "server": None,
        "version": None,
        "tools": [],
        "resources": [],
        "templates": [],
        "error": None,
    }
    params = StdioServerParameters(
        command=interpreter,
        args=[str(spec.entrypoint_path), *spec.args],
        env={**os.environ, **spec.env},
        cwd=str(working_directory),
    )
    try:
        async with (
            stdio_client(params) as (read, write),
            ClientSession(read, write) as session,
        ):
            init = await session.initialize()
            entry["server"] = init.server_info.name
            entry["version"] = init.server_info.version
            entry["tools"] = sorted(tool.name for tool in (await session.list_tools()).tools)
            try:
                listed = await session.list_resources()
                entry["resources"] = sorted(str(resource.uri) for resource in listed.resources)
            except Exception:
                entry["resources"] = []
            try:
                templates = await session.list_resource_templates()
                # mcp 2.x result models are snake_case: `resource_templates`,
                # and each item exposes `uri_template`.
                entry["templates"] = sorted(
                    uri
                    for template in getattr(templates, "resource_templates", [])
                    if (uri := getattr(template, "uri_template", None))
                )
            except Exception:
                entry["templates"] = []
            entry["ok"] = True
    except Exception as exc:  # an MCP failure is the result we want to report
        entry["error"] = f"{type(exc).__name__}: {exc}"
    return entry


async def _smoke_all(
    specs: list[ServerSpec],
    interpreter: str,
    working_directory: Path,
    timeout: float,
) -> list[dict[str, Any]]:
    import asyncio

    results: list[dict[str, Any]] = []
    for spec in specs:
        try:
            results.append(
                await asyncio.wait_for(
                    _probe(spec, interpreter, working_directory), timeout=timeout
                )
            )
        except TimeoutError:
            results.append(
                {
                    "slug": spec.slug,
                    "ok": False,
                    "server": None,
                    "version": None,
                    "tools": [],
                    "resources": [],
                    "templates": [],
                    "error": f"timed out after {timeout:g}s",
                }
            )
    return results


def smoke(
    specs: list[ServerSpec],
    *,
    python: str | None = None,
    cwd: Path | None = None,
    timeout: float = SMOKE_TIMEOUT,
) -> list[dict[str, Any]]:
    """Launch every challenge over stdio and list what it exposes."""
    import asyncio

    return asyncio.run(_smoke_all(specs, python or sys.executable, cwd or Path.cwd(), timeout))
