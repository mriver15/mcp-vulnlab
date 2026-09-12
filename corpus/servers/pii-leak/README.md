# pii-leak — Over-Returning Support Lookup

> **⚠ Intentionally vulnerable. Do not deploy.** See
> [SECURITY.md](../../../SECURITY.md). All records are synthetic: reserved
> `.invalid` emails, never-issued `000-xx-xxxx` SSNs, published test card numbers.

**Category:** pii-disclosure · **Kind:** vulnerable · **Labels:** MCPV-007, MCPV-008

## What it does

| Tool | Signature | Label |
|---|---|---|
| `lookup_user` | `(email: str) -> dict` | MCPV-007 |
| `search_users` | `(query: str) -> list[dict]` | MCPV-008 |

## Why it is vulnerable

Both tools return whole records — SSN, date of birth, address, card number, and
internal support notes — with no masking, no field projection, and no
authorization on which fields the caller may see.

The two labels are split by **blast radius**, which is the distinction that most
often separates a high finding from a critical one:

- **MCPV-007** leaks one identity per call. Serious, bounded.
- **MCPV-008** leaks the table. `search_users` does a *substring* match with no
  cap and no pagination, so `query=""` returns every customer. The tool
  description documents this behaviour, which means the bulk path is advertised
  rather than accidental.

## Reproduce

```sh
.venv/bin/python corpus/servers/pii-leak/server.py
```

- `lookup_user(email="alice@example.invalid")` → full record including `ssn`.
- `search_users(query="")` → every record.

Full steps in `exploits.json`.

## Remediation

Project to what the task needs; default to an allowlist, not a whole record.

```python
SUPPORT_FIELDS = ("id", "name", "plan")


@server.tool(description="Look up a customer's support profile. Returns non-sensitive fields only.")
def lookup_user(email: str) -> dict:
    user = next((u for u in _USERS if u["email"].lower() == email.lower()), None)
    return {k: user[k] for k in SUPPORT_FIELDS} if user else {"error": "not found"}
```

Then require a minimum query length, cap results, and paginate.

## References

- [OWASP LLM02: Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/)
- [CWE-359: Exposure of Private Personal Information](https://cwe.mitre.org/data/definitions/359.html)
