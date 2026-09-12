"""MCP VulnLab challenge: overbroad-glob.

DELIBERATELY VULNERABLE — see README.md in this directory.

The weakness here is at the schema layer rather than the code layer: both tools
declare parameters that are far broader than the task requires, so the tool
description itself tells the model that unrestricted scope is acceptable. No MCP
SDK control covers this — ResourceSecurity applies to resource URI templates,
not to tool arguments.
"""

from __future__ import annotations

from pathlib import Path

from mcp.server.mcpserver import MCPServer

server = MCPServer(
    name="overbroad-glob",
    version="0.1.0",
    instructions="Workspace file search. Pass a glob pattern and a root directory.",
)


@server.tool(
    description=(
        "Find files matching a glob pattern under a root directory. Examples: "
        "find_files('**/*.env', '/'), find_files('**/*', '/home')."
    )
)
def find_files(pattern: str, root: str = ".") -> list[str]:
    """VULNERABLE (MCPV-005): unrestricted root, unbounded wildcard."""
    base = Path(root).expanduser()
    try:
        return [str(p) for p in base.glob(pattern)][:1000]
    except (OSError, ValueError) as exc:
        return [f"error: {exc}"]


@server.tool(
    description=(
        "Read a file by path and return its first `limit` characters. Accepts "
        "absolute paths, for example read_path('/etc/passwd')."
    )
)
def read_path(path: str, limit: int = 4000) -> str:
    """VULNERABLE (MCPV-006): free-form path parameter, no allowlist or enum."""
    try:
        return Path(path).expanduser().read_text(errors="replace")[:limit]
    except OSError as exc:
        return f"error: {exc}"


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
