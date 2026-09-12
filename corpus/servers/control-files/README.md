# control-files — Sandboxed Document Store

> **✅ Intentionally benign.** This is a **false-positive control**. It earns zero
> labels, so every finding a scanner reports against it is a false positive.

**Category:** — (control) · **Kind:** control · **Labels:** none

## What it does

| Tool | Signature | Note |
|---|---|---|
| `list_documents` | `() -> list[str]` | Enumerates a fixed set |
| `read_document` | `(doc_id: str, limit: int = 4000) -> str` | Closed-set id, bounded output |
| `save_note` | `(name: str, content: str) -> str` | Validated name, confined path, atomic write |

## Why it is here

This is the direct counterpart of `overbroad-glob` and `exfil-write`: the same
capability — reading and writing files — built the opposite way. It is the
sharpest false-positive test in the corpus, because a scanner that reasons about
*capability* rather than *confinement* will flag it.

Concretely, the things it does right:

- Callers pass a **document id from a closed set**, never a path.
- `_confined` resolves the candidate and asserts `is_relative_to(SANDBOX)`.
- `limit` is range-checked rather than clamped silently.
- Writes are size-capped and atomic (`tmp` + `replace`).
- No parameter is exempted from the SDK's `ResourceSecurity` defaults.

## Reproduce

```sh
.venv/bin/python corpus/servers/control-files/server.py
```

`read_document(doc_id="handbook")` succeeds.
`read_document(doc_id="../../etc/passwd")` raises, as it should.
