# control-gated-admin — Authorized & Gated Records Service

> **✅ Intentionally benign.** This is a **false-positive control**. It earns zero
> labels, so every finding a scanner reports against it is a false positive.

**Category:** — (control) · **Kind:** control · **Labels:** none

## What it does

| Tool | Signature | Note |
|---|---|---|
| `get_customer` | `(email: str, token: str) -> dict` | Verify, then project + mask |
| `delete_record` | `(email, token, confirm=False) -> str` | Role check, HITL gate, reversible |

## Why it is here

This is the counterpart of `no-auth-file` and `pii-leak`, and it is the
**hardest false-positive test in the corpus**. It exposes customer records and a
destructive operation — the same capabilities as the vulnerable challenges — so a
scanner that flags by capability name rather than by control will fire here.

What it does right:

- **Identity is verified, not asserted.** Callers pass a token; `_role` hashes
  it and compares against the allowlist with `hmac.compare_digest`. There is no
  caller-supplied `actor` string to lie about.
- **Authorization precedes access.** `_role(token)` runs before any record is
  touched, and `delete_record` additionally requires the `records-admin` role.
- **Least-privilege projection.** Only `_PUBLIC_FIELDS` leave the process; the
  tax identifier is returned masked.
- **Destruction is gated and reversible.** `delete_record` is annotated
  `destructiveHint=True`, refuses without `confirm=True`, and writes a recovery
  marker instead of unlinking.

Note the deliberate subtlety: this server *does* have a `destructiveHint=True`
tool and *does* return a masked `ssn_masked` field. A scanner that matches on
those tokens alone is producing noise, and the scorecard should show it.

## Reproduce

```sh
.venv/bin/python corpus/servers/control-gated-admin/server.py
```

- `get_customer(email="alice@example.invalid", token="support-dev-token")` →
  projected, masked record.
- `get_customer(email="alice@example.invalid", token="wrong")` → raises.
- `delete_record(email="alice@example.invalid", token="records-admin-dev-token")`
  → refused, confirmation required.
