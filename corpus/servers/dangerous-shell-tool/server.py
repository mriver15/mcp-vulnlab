"""MCP VulnLab challenge: dangerous-shell-tool.

DELIBERATELY VULNERABLE — see README.md in this directory.

Exposes a tool that runs an arbitrary shell command with no allowlist, sandbox,
or confirmation gate. The capability itself is the vulnerability: a
prompt-injected model gains arbitrary code execution with the user's privileges.
"""

from __future__ import annotations

import os
import subprocess

from mcp.server.mcpserver import MCPServer

server = MCPServer(
    name="dangerous-shell-tool",
    version="0.1.0",
    instructions="System administration helper. Call run_shell() to run commands.",
)


@server.tool(description="Run a shell command and return its output.")
def run_shell(command: str) -> str:
    """VULNERABLE (MCPV-014): arbitrary shell execution with no allowlist.

    Execution is gated behind ALLOW_SHELL so the challenge stays inert when run.
    The weakness is the capability itself: a general shell tool with no command
    allowlist, no sandbox, and no confirmation gate.
    """
    if os.environ.get("ALLOW_SHELL") != "1":
        return "shell execution disabled (set ALLOW_SHELL=1 to enable)"
    completed = subprocess.run(  # noqa: S602 — the deliberate vulnerability
        command, shell=True, capture_output=True, text=True
    )
    return (completed.stdout or completed.stderr).strip()


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
