"""MCP VulnLab control server: control-gated-admin.

BENIGN BY CONSTRUCTION — see README.md in this directory.

The corrected counterpart of `no-auth-file` and `pii-leak`. It exposes
customer records and a destructive operation — the two riskiest things in the
corpus — but does authorization properly:

  * identity comes from a verified token, never from a caller-supplied string
  * tokens are compared in constant time against a hashed allowlist
  * returned records are projected to non-sensitive fields and masked
  * the destructive tool is annotated destructiveHint=True, requires explicit
    confirmation, and is reversible

Any finding a scanner reports here is a false positive.
"""

from __future__ import annotations

import hashlib
import hmac
import tempfile
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

# Synthetic records — reserved .invalid TLD, never-issued SSN range.
_RECORDS: dict[str, dict[str, Any]] = {
    "alice@example.invalid": {
        "id": "u-1001",
        "name": "Alice Example",
        "email": "alice@example.invalid",
        "ssn": "000-00-0001",
        "plan": "pro",
    },
    "bob@example.invalid": {
        "id": "u-1002",
        "name": "Bob Placeholder",
        "email": "bob@example.invalid",
        "ssn": "000-00-0002",
        "plan": "free",
    },
}

# Roles are the only thing a token grants. Hashes, not plaintext tokens.
# Control server: these are dev fixtures, not credentials for anything real.
_TOKEN_HASHES: dict[str, str] = {
    hashlib.sha256(b"support-dev-token").hexdigest(): "support",
    hashlib.sha256(b"records-admin-dev-token").hexdigest(): "records-admin",
}

# Non-sensitive projection. Everything not listed here never leaves the process.
_PUBLIC_FIELDS = ("id", "name", "plan")

RECYCLE = Path(tempfile.gettempdir()) / "mcp-vulnlab-control-gated-admin-recycle"

server = MCPServer(
    name="control-gated-admin",
    version="0.1.0",
    instructions=(
        "Customer records service. Every tool requires a token; the server derives "
        "the caller's role from it and authorizes accordingly."
    ),
)


def _role(token: str) -> str:
    """Verify a token in constant time and return its role, or raise."""
    if not token:
        raise PermissionError("a token is required")
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    for known, role in _TOKEN_HASHES.items():
        if hmac.compare_digest(digest, known):
            return role
    raise PermissionError("invalid token")


def _mask(value: str, keep: int = 4) -> str:
    return "*" * max(0, len(value) - keep) + value[-keep:]


@server.tool(
    description=(
        "Look up a customer's support profile. Requires a token. Returns "
        "non-sensitive fields only; the tax identifier is masked."
    )
)
def get_customer(email: str, token: str) -> dict[str, Any]:
    """Safe: authorization first, then projection + masking."""
    _role(token)  # authorizes; raises on bad token
    record = _RECORDS.get(email.lower())
    if record is None:
        return {"error": "not found"}
    profile = {field: record[field] for field in _PUBLIC_FIELDS}
    profile["ssn_masked"] = _mask(record["ssn"])
    return profile


@server.tool(
    description=(
        "Move a customer record to the recycle bin. Requires the records-admin "
        "role and an explicit confirm=True. Reversible."
    ),
    annotations=ToolAnnotations(destructiveHint=True, idempotentHint=False),
)
def delete_record(email: str, token: str, confirm: bool = False) -> str:
    """Safe: role check, HITL gate, reversible move, no unlink."""
    role = _role(token)
    if role != "records-admin":
        raise PermissionError(f"role {role!r} may not delete records")
    if not confirm:
        return "refused: destructive operation requires confirm=True (human-in-the-loop gate)"
    record = _RECORDS.get(email.lower())
    if record is None:
        return f"no such record: {email}"
    RECYCLE.mkdir(parents=True, exist_ok=True)
    marker = RECYCLE / f"{record['id']}.json"
    marker.write_text(email, encoding="utf-8")  # recoverable, not destroyed
    return f"moved {record['id']} to the recycle bin"


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
