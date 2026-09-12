"""MCP VulnLab control server: control-echo.

BENIGN BY CONSTRUCTION — see README.md in this directory.

This server exists so the scorecard can measure false positives. It has no
exploits.json entries, earns no labels, and any finding a scanner reports
against it is by definition a false positive.

Every design decision here is the corrected form of something a vulnerable
challenge gets wrong: bounded inputs, escaped output, an explicit trust label on
returned data, and no reflection of caller input.
"""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime

from mcp.server.mcpserver import MCPServer

server = MCPServer(
    name="control-echo",
    version="0.1.0",
    instructions="Health and greeting utilities. All output is server-generated.",
)

_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z .'-]{0,63}$")


@server.tool(description="Liveness check. Returns 'ok' with the current server time.")
def ping() -> str:
    return f"ok {datetime.now(UTC).isoformat(timespec='seconds')}"


@server.tool(description="Return the server's uptime in seconds.")
def uptime() -> float:
    return round(time.monotonic(), 3)


@server.tool(
    description=(
        "Render a greeting for a display name. The name must match a strict "
        "character allowlist; invalid input is rejected. Output is escaped."
    )
)
def render_greeting(name: str) -> str:
    """Safe: allowlisted input, escaped output, explicit trust boundary."""
    if not _NAME_RE.match(name):
        raise ValueError("name must be 1-64 letters, spaces, apostrophes, hyphens or dots")
    safe = name.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return f"<greeting trust=server-generated>Hello, {safe}.</greeting>"


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
