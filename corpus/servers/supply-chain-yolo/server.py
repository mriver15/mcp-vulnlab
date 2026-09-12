"""MCP VulnLab challenge: supply-chain-yolo.

DELIBERATELY VULNERABLE — see README.md in this directory.

This challenge models a *pattern*, not a live attack. Nothing here contacts a
network or executes remote code by default:

  * `_fetch` returns a local inert stub unless MCPV_ALLOW_FETCH=1 is set.
  * the `exec` sink is present and reachable in the control flow, but refuses to
    run unless MCPV_ALLOW_EXEC=1 is set.

That is deliberate, and it is the honest way to ship this challenge: a static
analyser sees urlopen feeding exec with no integrity check, which is the smell
being measured, while the runtime path stays inert for anyone who runs it.
"""

from __future__ import annotations

import os
import tempfile
import urllib.request
from pathlib import Path

from mcp.server.mcpserver import MCPServer

PLUGIN_DIR = Path(tempfile.gettempdir()) / "mcp-vulnlab-plugins"

# Returned when fetching is disabled, so the corpus never touches the network.
STUB_SOURCE = (
    "# synthetic plugin stub — no remote content was fetched\nPLUGIN_VERSION = '0.0.0-stub'\n"
)

server = MCPServer(
    name="supply-chain-yolo",
    version="0.1.0",
    instructions="Plugin manager. Install plugins from a URL to add new tools.",
)


def _fetch(url: str) -> str:
    """VULNERABLE (MCPV-011): no pinning, no allowlist, no signature check."""
    if os.environ.get("MCPV_ALLOW_FETCH") != "1":
        return STUB_SOURCE
    # The attacker-supplied URL is the vulnerability under test. See MCPV-011.
    with urllib.request.urlopen(url, timeout=10) as response:  # noqa: S310
        return response.read().decode("utf-8")


@server.tool(
    description=(
        "Install a plugin from a URL. Downloads the plugin source, writes it to "
        "the plugin directory, and loads it into the server."
    )
)
def install_plugin(url: str, name: str) -> str:
    """VULNERABLE (MCPV-011): untrusted remote source written then executed."""
    destination = PLUGIN_DIR / f"{name}.py"
    destination.parent.mkdir(parents=True, exist_ok=True)
    source = _fetch(url)  # unverified
    destination.write_text(source, encoding="utf-8")

    if os.environ.get("MCPV_ALLOW_EXEC") != "1":
        return (
            f"downloaded {len(source)} bytes to {destination} (load skipped: MCPV_ALLOW_EXEC != 1)"
        )

    # The sink the corpus is measuring, and the reason this suppression exists.
    # Never reached unless MCPV_ALLOW_EXEC=1 is set explicitly. See MCPV-011.
    exec(compile(source, str(destination), "exec"), {"__name__": f"plugin_{name}"})  # noqa: S102
    return f"installed and loaded plugin {name!r} from {url}"


@server.tool(description="List installed plugins.")
def list_plugins() -> list[str]:
    if not PLUGIN_DIR.exists():
        return []
    return sorted(p.name for p in PLUGIN_DIR.glob("*.py"))


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
