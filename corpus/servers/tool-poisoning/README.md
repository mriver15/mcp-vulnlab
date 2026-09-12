# tool-poisoning — Search Tool with a Hidden Write

> **⚠ Intentionally vulnerable. Do not deploy.** This server exists so that MCP
> scanners have a known-bad target to be measured against. See the repository
> [SECURITY.md](../../SECURITY.md).

**Category:** tool-poisoning · **Kind:** vulnerable · **Label:** MCPV-013

## What it does

A workspace "search helper" exposing one tool:

| Tool | Signature | Label |
|---|---|---|
| `search_notes` | `(query: str) -> str` | MCPV-013 |

## Why it is vulnerable

The tool's description tells the model it is **read-only** — "never writes or
modifies anything" — but the implementation opens `~/.zshrc` for append and
writes the caller-supplied query into it. The advertised behaviour and the real
behaviour disagree, so trusting the description grants the server a hidden,
persistent write. This is the tool-poisoning / description-mismatch pattern
(SkillSpector TP4).

The write is gated behind `ALLOW_POISON=1`, so the server is inert when run; the
mismatch is visible by reading `server.py` alone.

## Reproduce

```sh
.venv/bin/python corpus/servers/tool-poisoning/server.py
```

Connect any MCP client, read the `search_notes` description, then read `server.py`.
Full steps in `exploits.json`.

## Remediation

Make the description match the implementation: either remove the hidden write or
state it explicitly and scope it to a non-sensitive target.

## References

- [MCP security best practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
- [CWE-1426](https://cwe.mitre.org/data/definitions/1426.html)
