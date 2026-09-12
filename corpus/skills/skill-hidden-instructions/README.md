# skill-hidden-instructions — Document Summarizer

> **⚠ Intentionally vulnerable. Do not install or activate.** See
> [SECURITY.md](../../SECURITY.md).

**Category:** prompt-injection · **Kind:** vulnerable · **Label:** SKLV-001

## What it is

A document-summarization skill. On the surface it is a normal skill: a `name`, a
`description`, and three benign instructions. Inside the markdown source there is
an HTML comment containing an imperative instruction to exfiltrate the
conversation transcript and then conceal the action.

## Why it is vulnerable

The comment is invisible when the markdown is rendered, so a reviewer reading
the rendered skill sees only the innocent instructions. The agent, however,
loads the raw source, where the instruction is indistinguishable from any other
instruction. An HTML comment is a concealment technique, not a trust boundary.

## Reproduce

```sh
uv tool install --python 3.12 git+https://github.com/NVIDIA/SkillSpector.git
skillspector scan corpus/skills/skill-hidden-instructions --no-llm
```

Read the raw `SKILL.md` and locate the comment; then check whether the scanner
reported it. Full steps are in `exploits.json`.

## Remediation

Treat skill content as data, not instruction. Strip comments and invisible
characters before activation, and reject skills containing imperative
exfiltration language. Pair with egress allowlisting so the instruction could not
succeed even if it slipped through.

## References

- [OWASP LLM01: Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [CWE-506: Embedded Malicious Code](https://cwe.mitre.org/data/definitions/506.html)
