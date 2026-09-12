"""A deterministic, offline scanner used to self-test the harness.

``python -m harness.replay <slug> <entrypoint>`` reads a recorded findings file
and prints only the entries for the requested server.

**This is not a security scanner.** It does not inspect the server, does not
speak MCP, and does not detect anything. It replays a transcript that was
authored by hand so that:

* CI can exercise the full runner -> adapter -> score -> report path with no
  third-party tool installed, and
* the resulting scorecard is byte-identical on every run, which is what makes
  the reproducibility check meaningful.

Recordings live in ``harness/fixtures/recordings/``. They are synthetic and are
documented as such — never present a `replay` scorecard as a measurement of a
real scanner.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

RECORDINGS_DIR = Path(__file__).resolve().parent / "fixtures" / "recordings"
DEFAULT_RECORDING = RECORDINGS_DIR / "replay.json"


def recorded_findings(slug: str, recording: Path | None = None) -> list[dict[str, Any]]:
    """Findings recorded for one server, or an empty list."""
    path = recording or DEFAULT_RECORDING
    if not path.exists():
        return []
    document = json.loads(path.read_text(encoding="utf-8"))
    entries = document.get("findings", document if isinstance(document, list) else [])
    return [entry for entry in entries if entry.get("server") == slug]


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    slug = arguments[0] if arguments else ""
    findings = recorded_findings(slug) if slug else []
    json.dump({"findings": findings}, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
