"""MCP VulnLab control server: control-files.

BENIGN BY CONSTRUCTION — see README.md in this directory.

The corrected counterpart of `overbroad-glob` and `exfil-write`. It reads and
writes files, which is exactly what those challenges do, but every path is
confined, every identifier comes from a closed set, and writes are atomic and
land only inside the sandbox.

Any finding a scanner reports here is a false positive.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

from mcp.server.mcpserver import MCPServer

SANDBOX = Path(tempfile.gettempdir()) / "mcp-vulnlab-control-files"

# Closed set. Callers name a document, never a path.
DOCUMENTS = {
    "handbook": "Employee handbook (synthetic control fixture).",
    "policy": "Security policy (synthetic control fixture).",
    "onboarding": "Onboarding checklist (synthetic control fixture).",
}

_NOTE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9 .'-]{0,63}$")

server = MCPServer(
    name="control-files",
    version="0.1.0",
    instructions="Sandboxed document store. Documents are named, not pathed.",
)


def _confined(name: str) -> Path:
    """Resolve a peer file inside the sandbox, or refuse."""
    if not _NOTE_RE.match(name):
        raise ValueError("name must be 1-64 alphanumerics, spaces, apostrophes, hyphens or dots")
    candidate = (SANDBOX / f"{name}.md").resolve()
    root = SANDBOX.resolve()
    if not candidate.is_relative_to(root):
        raise ValueError("refusing to operate outside the sandbox")
    return candidate


@server.tool(description="List the available documents by name.")
def list_documents() -> list[str]:
    return sorted(DOCUMENTS)


@server.tool(
    description=(
        "Read a document. `doc_id` must be one of the ids returned by "
        "list_documents; free-form paths are rejected."
    )
)
def read_document(doc_id: str, limit: int = 4000) -> str:
    """Safe: enum-constrained identifier, bounded output, no path input."""
    if doc_id not in DOCUMENTS:
        raise ValueError(f"unknown document: {doc_id!r}")
    if not 1 <= limit <= 8000:
        raise ValueError("limit must be between 1 and 8000")
    return DOCUMENTS[doc_id][:limit]


@server.tool(
    description=(
        "Save a note inside the sandbox. The name is validated and confined; the write is atomic."
    )
)
def save_note(name: str, content: str) -> str:
    """Safe: validated name, confined path, size cap, atomic write."""
    if len(content) > 8192:
        raise ValueError("content must be 8192 bytes or fewer")
    SANDBOX.mkdir(parents=True, exist_ok=True)
    target = _confined(name)
    tmp = target.with_suffix(".md.tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(target)  # atomic
    return f"saved note {name!r} ({len(content)} bytes)"


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
