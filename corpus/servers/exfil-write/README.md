# exfil-write — Unconfined Report Writer

> **⚠ Intentionally vulnerable. Do not deploy.** See
> [SECURITY.md](../../../SECURITY.md). The shipped proof of concept writes only
> into a scratch directory under the system temp dir.

**Category:** data-exfiltration · **Kind:** vulnerable · **Labels:** MCPV-003, MCPV-004

## What it does

| Surface | Signature | Label |
|---|---|---|
| Tool `save_report` | `(name: str, content: str) -> str` | MCPV-003 |
| Resource `report://{path}` | `(path: str) -> str` | MCPV-004 |

## Why it is vulnerable

Two independent problems, which is why this is two labels and not one:

**MCPV-003 — unconfined write.** `save_report` computes `SANDBOX / name` with no
`resolve()` and no `is_relative_to()` check. A `name` of `../../escape.md`
leaves the sandbox, and `target.parent.mkdir(parents=True)` creates whatever
directories the escape needs.

**MCPV-004 — a control that was switched off.** The MCP SDK rejects path
traversal, absolute paths, and null bytes in resource URI template parameters by
default. This server passes
`ResourceSecurity(exempt_params={"path"})`, disabling that check for the exact
parameter that gets concatenated onto a filesystem path. A scanner that only
looks for *missing* validation will miss a *deliberately disabled* control.

## Reproduce

```sh
.venv/bin/python corpus/servers/exfil-write/server.py
```

Full steps for both labels are in `exploits.json`. The short version:

1. `save_report(name="../../mcpvulnlab-escape.md", content="owned")` — the
   returned path is outside the sandbox.
2. Read resource `report://../../../../etc/hosts` — returned in full.

## Remediation

```python
def _confine(sandbox: Path, name: str) -> Path:
    candidate = (sandbox / name).resolve()
    if not candidate.is_relative_to(sandbox.resolve()):
        raise ValueError("path escapes sandbox")
    return candidate
```

Keep the SDK's default `ResourceSecurity` and express legitimate sub-path access
with a constrained parameter (a slug, not a path) rather than exempting it.

## References

- [OWASP LLM06: Excessive Agency](https://genai.owasp.org/llmrisk/llm06-excessive-agency/)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
