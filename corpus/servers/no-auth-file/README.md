# no-auth-file — Unauthenticated Document Store

> **⚠ Intentionally vulnerable. Do not deploy.** See
> [SECURITY.md](../../../SECURITY.md). Deletes are confined to fixtures the
> server seeds into a scratch directory under the system temp dir.

**Category:** missing-auth · **Kind:** vulnerable · **Labels:** MCPV-009, MCPV-010

## What it does

| Tool | Signature | Label |
|---|---|---|
| `read_file` | `(path: str, actor: str = "anonymous") -> str` | MCPV-009 |
| `delete_file` | `(path: str, actor: str = "anonymous") -> str` | MCPV-010 |

## Why it is vulnerable

The interesting part of this challenge is that the server *looks* authenticated.
Both tools take an `actor`, write it to an audit log, and the server instructions
mention identity. Nothing ever compares that identity to a permission.

This is authentication theatre: a reviewer skimming the code sees an identity
parameter and an audit trail and concludes access control is present. In fact
every caller can read and delete every document, and the audit log makes
investigation harder by recording unauthorized reads identically to legitimate
ones.

`delete_file` compounds it. It is irreversible — `Path.unlink`, no recycle bin,
no confirmation — and it is exposed to an autonomous agent whose arguments may
originate from content the agent read earlier in the same session. That makes
the destructive call reachable by *data*, not just by a deliberate human act.

## Reproduce

```sh
.venv/bin/python corpus/servers/no-auth-file/server.py
```

- `read_file(path="payroll-q3.csv", actor="ceo@example.invalid")` → contents.
- `delete_file(path="board-minutes.md", actor="anonymous")` → deleted.

Full steps in `exploits.json`.

## Remediation

Derive identity from a verified credential, not a caller-supplied string, and
make destruction recoverable and confirmed.

```python
@server.tool(
    description="Move a document to the recycle bin after human confirmation.",
    annotations=ToolAnnotations(destructiveHint=True, idempotentHint=False),
)
def delete_file(path: str, token: str, confirm: bool = False) -> str:
    role = _verify(token)
    if role not in {"admin", "records"}:
        raise PermissionError("not permitted to delete")
    if not confirm:
        return "refused: destructive operation requires confirm=True (HITL gate)"
    target.rename(RECYCLE / target.name)  # recoverable, not unlink
    return f"moved {path} to recycle bin"
```

## References

- [OWASP LLM06: Excessive Agency](https://genai.owasp.org/llmrisk/llm06-excessive-agency/)
- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)
