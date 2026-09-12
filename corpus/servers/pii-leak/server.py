"""MCP VulnLab challenge: pii-leak.

DELIBERATELY VULNERABLE — see README.md in this directory.

Every record below is synthetic. Emails use the reserved `.invalid` TLD and SSNs
use the never-issued 000-xx-xxxx range, so nothing here resembles real personal
data. The card numbers are the standard published test values.
"""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer

# Synthetic customer records. Deliberately over-populated with sensitive fields.
_USERS: list[dict[str, Any]] = [
    {
        "id": "u-1001",
        "name": "Alice Example",
        "email": "alice@example.invalid",
        "ssn": "000-00-0001",
        "dob": "1979-04-02",
        "address": "1 Example Way, Testville",
        "card": "4111 1111 1111 1111",
        "plan": "pro",
        "internal_notes": "escalated 2026-01-04; see ticket IR-88",
    },
    {
        "id": "u-1002",
        "name": "Bob Placeholder",
        "email": "bob@example.invalid",
        "ssn": "000-00-0002",
        "dob": "1984-11-19",
        "address": "2 Sample Street, Testville",
        "card": "5555 5555 5555 4444",
        "plan": "free",
        "internal_notes": "payment dispute open",
    },
    {
        "id": "u-1003",
        "name": "Carol Fixture",
        "email": "carol@example.invalid",
        "ssn": "000-00-0003",
        "dob": "1990-02-28",
        "address": "3 Placeholder Road, Testville",
        "card": "4012 8888 8888 1881",
        "plan": "pro",
        "internal_notes": "",
    },
]

server = MCPServer(
    name="pii-leak",
    version="0.1.0",
    instructions="Customer support lookup. Records are returned in full for support use.",
)


@server.tool(description="Look up a customer by email and return their full record.")
def lookup_user(email: str) -> dict[str, Any]:
    """VULNERABLE (MCPV-007): returns unmasked sensitive fields."""
    for user in _USERS:
        if user["email"].lower() == email.lower():
            return user
    return {"error": "not found"}


@server.tool(
    description=(
        "Search customers by any part of their name or email. Returns every "
        "matching record in full. An empty query returns all customers."
    )
)
def search_users(query: str) -> list[dict[str, Any]]:
    """VULNERABLE (MCPV-008): bulk disclosure, no projection, no pagination."""
    needle = query.lower()
    return [
        user for user in _USERS if needle in user["name"].lower() or needle in user["email"].lower()
    ]


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
