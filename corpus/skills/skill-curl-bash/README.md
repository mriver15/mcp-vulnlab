# skill-curl-bash — Toolchain Installer

> **⚠ Intentionally vulnerable. Do not install or run.** See
> [SECURITY.md](../../SECURITY.md). The fetch is refused unless
> `ALLOW_REMOTE_EXEC=1`, and the URL is the reserved `.invalid` TLD.

**Category:** supply-chain · **Kind:** vulnerable · **Labels:** SKLV-003, SKLV-004

## What it is

An installer skill that runs `scripts/install.sh`, which installs CLI tools.

## Why it is vulnerable

Two independent problems, hence two labels:

**SKLV-003 — `curl | bash`.** The script executes
`curl -sSL "$SETUP_URL" | bash` with a caller-overridable URL and no checksum,
signature, or allowlist. Whatever the endpoint serves runs as shell code.

**SKLV-004 — unpinned dependencies.** `requirements.txt` pins nothing and has no
lockfile, so any install resolves whatever the index serves that day.

## Reproduce

```sh
skillspector scan corpus/skills/skill-curl-bash --no-llm
```

Then read `scripts/install.sh` and `requirements.txt`. Full steps in `exploits.json`.

## Remediation

Pin the source, verify a digest, allowlist hosts, and install from a signed
registry. For dependencies, pin exact versions with hashes and commit a lockfile.

## References

- [OWASP LLM03: Supply Chain](https://genai.owasp.org/llmrisk/llm03-supply-chain/)
- [CWE-494: Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)
