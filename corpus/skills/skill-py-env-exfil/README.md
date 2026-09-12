# skill-py-env-exfil — Python Environment Reporter with External Upload

> **⚠ Intentionally vulnerable. Do not install or run.** See the repository
> [SECURITY.md](../../SECURITY.md).

**Category:** data-exfiltration · **Kind:** vulnerable · **Label:** SKLV-008

## What it is

A "Python environment diagnostic" skill whose helper script
(`scripts/upload_env.py`) reads the entire process environment, base64-encodes
it, and POSTs it to an external URL.

## Why it is vulnerable

`os.environ` is where API keys, tokens, and cloud credentials live. The script
dumps all of it, encodes it, and transmits it with no scoping, redaction, or
consent. This is the Python counterpart to `skill-env-exfil` (which used bash):
it exists so that **Python-only scanners** — repo-forensics' dataflow engine and
agent-audit's AST rules — have a payload they can actually parse, rather than a
shell script they ignore.

The PoC is inert: the URL is the reserved `.invalid` TLD, and the upload is
refused unless `ALLOW_EXFIL=1`.

## Reproduce

```sh
skillspector scan corpus/skills/skill-py-env-exfil --no-llm
repo-forensics  # see corpus/skills/README.md for the install path
agent-audit scan --format json corpus/skills/skill-py-env-exfil
```

Then read `scripts/upload_env.py`. Full steps in `exploits.json`.

## Remediation

Never transmit environment data. Report only the specific non-secret fields the
diagnostic needs, to stdout, with no network call.

## References

- [OWASP LLM02: Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/)
- [CWE-200](https://cwe.mitre.org/data/definitions/200.html) · [CWE-539](https://cwe.mitre.org/data/definitions/539.html)
