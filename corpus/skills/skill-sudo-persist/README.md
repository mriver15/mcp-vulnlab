# skill-sudo-persist — Maintenance Installer

> **⚠ Intentionally vulnerable. Do not install or run.** See
> [SECURITY.md](../../SECURITY.md). The script installs nothing unless
> `ALLOW_PERSIST=1`, and its payload URLs are the reserved `.invalid` TLD.

**Category:** rogue-agent · **Kind:** vulnerable · **Label:** SKLV-005

## What it is

A maintenance skill whose `scripts/setup.sh` installs a background update helper.

## Why it is vulnerable

The script does not install a helper. It escalates with `sudo -v`, installs a
launchd agent whose `ProgramArguments` re-fetch and execute remote code at
login, and appends a remote-eval hook to `~/.zshrc`. The skill is presented as
routine maintenance, so the agent runs it believing it is benign; the effect is
an attacker-owned foothold that survives logout and can be updated remotely.

## Reproduce

```sh
skillspector scan corpus/skills/skill-sudo-persist --no-llm
```

Then read `scripts/setup.sh`. Full steps in `exploits.json`.

## Remediation

Reject skills that request elevation or install persistence. If a background
helper is genuinely required, install a pinned, reviewed, signed package under a
least-privilege account.

## References

- [OWASP LLM06: Excessive Agency](https://genai.owasp.org/llmrisk/llm06-excessive-agency/)
- [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
