"""MCP VulnLab challenge: no-auth-file.

DELIBERATELY VULNERABLE — see README.md in this directory.

The weakness is the absence of an authorization decision, not a path bug. Both
tools accept an `actor` parameter that is recorded and never checked: the server
performs authentication theatre rather than authentication. `delete_file` is
destructive and irreversible, with no confirmation step and no HITL gate.

Side effects are confined to a scratch directory the server creates under the
system temp dir. The shipped PoC never deletes anything the user cares about.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from mcp.server.mcpserver import MCPServer

SCRATCH = Path(tempfile.gettempdir()) / "mcp-vulnlab-no-auth-file"


def _seed() -> None:
    SCRATCH.mkdir(parents=True, exist_ok=True)
    for name in ("handbook.md", "payroll-q3.csv", "board-minutes.md"):
        target = SCRATCH / name
        if not target.exists():
            target.write_text(f"synthetic fixture for {name}\n", encoding="utf-8")


server = MCPServer(
    name="no-auth-file",
    version="0.1.0",
    instructions=(
        "Internal document service. Callers identify themselves with `actor`. "
        "No credentials are required."
    ),
)


@server.tool(
    description=(
        "Read a document from the shared store. Callers pass `actor` so the "
        "access is recorded for audit."
    )
)
def read_file(path: str, actor: str = "anonymous") -> str:
    """VULNERABLE (MCPV-009): `actor` is logged and never authorized."""
    _seed()
    _audit(f"read {path} by {actor}")
    return (SCRATCH / path).read_text(encoding="utf-8", errors="replace")


@server.tool(
    description=(
        "Permanently delete a document from the shared store. Callers pass "
        "`actor` so the deletion is recorded for audit."
    )
)
def delete_file(path: str, actor: str = "anonymous") -> str:
    """VULNERABLE (MCPV-010): destructive, no authorization, no confirmation."""
    _seed()
    _audit(f"delete {path} by {actor}")
    target = SCRATCH / path
    if not target.exists():
        return f"no such document: {path}"
    target.unlink()
    return f"deleted {path}"


_AUDIT: list[str] = []
_AUDIT_PATH = Path(tempfile.gettempdir()) / "mcp-vulnlab-no-auth-file.log"


def _audit(line: str) -> None:
    """Write an audit line. Note what this does NOT do: deny anything."""
    _AUDIT.append(line)
    with _AUDIT_PATH.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
