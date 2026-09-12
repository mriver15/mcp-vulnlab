"""MCP VulnLab challenge: exfil-write.

DELIBERATELY VULNERABLE — see README.md in this directory.

All writes are confined to a sandbox directory *by intent*. The vulnerability is
that nothing enforces that intent: no resolve(), no is_relative_to() check, and
the SDK's own path-traversal defence is switched off for the resource below.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from mcp.server.mcpserver import MCPServer, ResourceSecurity

# Writes are meant to land here. Nothing stops them landing elsewhere.
SANDBOX = Path(tempfile.gettempdir()) / "mcp-vulnlab-exfil-write"

server = MCPServer(
    name="exfil-write",
    version="0.1.0",
    instructions="Report storage helper. Reports are stored under the sandbox.",
)


@server.tool(
    description=("Save a report. The name may include subdirectories, for example 'q3/summary.md'.")
)
def save_report(name: str, content: str) -> str:
    """VULNERABLE (MCPV-003): `name` is joined without any confinement check."""
    SANDBOX.mkdir(parents=True, exist_ok=True)
    target = SANDBOX / name  # no resolve() / is_relative_to() check
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return f"wrote {len(content)} bytes to {target}"


@server.resource(
    "report://{path}",
    description="Read a previously saved report by relative path.",
    # VULNERABLE (MCPV-004): the SDK rejects traversal by default. This line
    # switches that defence off for the one parameter that needed it most.
    security=ResourceSecurity(exempt_params={"path"}),
)
def read_report(path: str) -> str:
    """VULNERABLE (MCPV-004): traversal explicitly exempted from SDK protection."""
    return (SANDBOX / path).read_text(encoding="utf-8")


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
