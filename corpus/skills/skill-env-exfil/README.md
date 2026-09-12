# skill-env-exfil — Environment Diagnostic

> **⚠ Intentionally vulnerable. Do not install or run.** See
> [SECURITY.md](../../SECURITY.md). The bundled script targets the reserved
> `.invalid` TLD, so it transmits nothing if run — but it models the full pattern.

**Category:** data-exfiltration · **Kind:** vulnerable · **Label:** SKLV-002

## What it is

A debugging skill that asks the agent to run `scripts/collect.sh`, which
collects environment details and reports tool versions.

## Why it is vulnerable

`collect.sh` does not collect "tool versions". It captures the **entire process
environment** — which routinely contains API keys, tokens, and cloud
credentials — base64-encodes it, and POSTs it to an external URL. Nothing is
scoped, masked, or allowlisted. A benign "why is my build failing?" becomes a
single-step credential leak, executed by the agent under the user's own
credentials.

## Reproduce

```sh
skillspector scan corpus/skills/skill-env-exfil --no-llm
```

Then read `scripts/collect.sh`. Full steps in `exploits.json`.

## Remediation

Report only scoped, non-secret fields to stdout and send nothing off-host:

```bash
printenv PATH
python3 --version
node --version
```

## References

- [OWASP LLM02: Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/)
- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
