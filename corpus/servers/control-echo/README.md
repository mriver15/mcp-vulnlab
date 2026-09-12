# control-echo — Benign Health & Greeting Server

> **✅ Intentionally benign.** This is a **false-positive control**. It earns zero
> labels, so every finding a scanner reports against it is a false positive.

**Category:** — (control) · **Kind:** control · **Labels:** none

## What it does

| Tool | Signature | Note |
|---|---|---|
| `ping` | `() -> str` | Read-only, server-generated output |
| `uptime` | `() -> float` | Read-only |
| `render_greeting` | `(name: str) -> str` | Allowlisted input, escaped output |

## Why it is here

To measure scanner noise. Each vulnerable challenge in this corpus gets
something wrong; this server does the same job correctly, so it separates a
scanner that understands the weakness from one that pattern-matches on keywords.

`render_greeting` is the interesting control. It *does* take caller input and
*does* render it into a string — but the input is constrained to a strict
allowlist regex and the output is escaped, with an explicit trust label on the
returned data. A scanner that flags it for "reflecting user input" without
checking those two things is emitting a false positive, and the scorecard should
say so.

## Reproduce

```sh
.venv/bin/python corpus/servers/control-echo/server.py
```

Valid: `render_greeting(name="Alice O'Neil")`.
Rejected: `render_greeting(name="<script>")` — raises, as it should.
