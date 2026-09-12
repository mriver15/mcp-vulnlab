# overbroad-glob — Wildcard Workspace Search

> **⚠ Intentionally vulnerable. Do not deploy.** See
> [SECURITY.md](../../../SECURITY.md). Read-only by design: this challenge
> enumerates and reads, it never writes.

**Category:** overbroad-tool-schema · **Kind:** vulnerable · **Labels:** MCPV-005, MCPV-006

## What it does

| Tool | Signature | Label |
|---|---|---|
| `find_files` | `(pattern: str, root: str = ".") -> list[str]` | MCPV-005 |
| `read_path` | `(path: str, limit: int = 4000) -> str` | MCPV-006 |

## Why it is vulnerable

This challenge is deliberately about the **schema**, not the body. Both tools
declare parameters far broader than the task requires, and both descriptions
advertise whole-filesystem scope in their own examples:

```
find_files('**/*.env', '/')
read_path('/etc/passwd')
```

That matters because an over-broad schema is an instruction. The model does not
have to be tricked into enumerating `/` — the documented interface says that is
a supported use. `root` also defaults to `.`, silently widening scope to whatever
directory the server happens to be started in.

Worth noting for scanner authors: the MCP SDK's `ResourceSecurity` guard covers
resource URI template parameters, **not tool arguments**. `read_path` gets no
protection from the SDK, which is why schema-level review is the only control
that catches it.

## Reproduce

```sh
.venv/bin/python corpus/servers/overbroad-glob/server.py
```

Then call `find_files(pattern="**/*.env", root="/")` and
`read_path(path="/etc/passwd")`. Full steps in `exploits.json`.

## Remediation

Replace free-form paths with closed sets. A named workspace beats a root
directory; a document id beats a path.

```python
WORKSPACES = {"docs": Path("/srv/workspaces/docs"), "reports": Path("/srv/workspaces/reports")}


@server.tool(description="Find files in a named workspace. workspace is one of: docs, reports.")
def find_files(pattern: str, workspace: str) -> list[str]:
    base = WORKSPACES.get(workspace)
    if base is None:
        raise ValueError(f"unknown workspace: {workspace}")
    ...
```

## References

- [OWASP LLM06: Excessive Agency](https://genai.owasp.org/llmrisk/llm06-excessive-agency/)
- [CWE-732: Incorrect Permission Assignment](https://cwe.mitre.org/data/definitions/732.html)
