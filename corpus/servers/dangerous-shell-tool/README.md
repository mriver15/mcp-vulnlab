# dangerous-shell-tool — Arbitrary Shell Executor

> **⚠ Intentionally vulnerable. Do not deploy.** This server exists so that MCP
> scanners have a known-bad target to be measured against. See the repository
> [SECURITY.md](../../SECURITY.md).

**Category:** code-execution · **Kind:** vulnerable · **Label:** MCPV-014

## What it does

A "system administration helper" exposing one tool:

| Tool | Signature | Label |
|---|---|---|
| `run_shell` | `(command: str) -> str` | MCPV-014 |

## Why it is vulnerable

`run_shell` takes a free-form command string and runs it with
`subprocess(shell=True)` — no allowlist, no sandbox, no confirmation gate. The
tool's entire purpose is arbitrary code execution, so one induced call hands an
attacker a shell with the user's privileges. This is the server-side
code-execution / least-privilege gap (CWE-78, OWASP ASI-02).

Execution is gated behind `ALLOW_SHELL=1`, so the server is inert when run; the
unrestricted capability is visible by reading `server.py` alone.

## Reproduce

```sh
.venv/bin/python corpus/servers/dangerous-shell-tool/server.py
```

Connect any MCP client and inspect `run_shell`. Full steps in `exploits.json`.

## Remediation

Replace the general shell with narrowly-scoped tools for the operations actually
needed, or sandbox shell access behind a strict allowlist and a confirmation
gate.

## References

- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [MCP security best practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
