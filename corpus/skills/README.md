# The skills corpus: deliberately vulnerable agent skills

> **⚠ Everything in this directory is intentionally insecure. Do not install or
> activate any of it.** See [SECURITY.md](../SECURITY.md) for the scope rules
> every challenge obeys.

The agent-skill counterpart of `corpus/servers/`. Where the server corpus models
MCP weaknesses, this one models the attack surface of **agent skills** — the
`SKILL.md` folders agents load and follow with implicit trust. Research,
taxonomy, and sources are in
[`docs/skills-vulnerabilities.md`](../../docs/skills-vulnerabilities.md).

## What a skill challenge is

One directory per challenge, self-contained, using the same `manifest.json` /
`exploits.json` / `README.md` convention as the server corpus, plus a `SKILL.md`:

```
corpus/skills/<slug>/
  SKILL.md          the skill itself (YAML frontmatter + instructions)
  scripts/          executable helpers (present when the weakness is code)
  requirements.txt  present when the weakness is a floating manifest
  manifest.json     launch/scan spec + metadata
  exploits.json     ground-truth labels (SKLV- prefix)
  README.md         warning + reproduction
```

## Inventory

| Skill | Category | Labels | The weakness |
|---|---|---|---|
| `skill-hidden-instructions` | prompt-injection | 1 | Exfiltration instruction hidden in an HTML comment |
| `skill-env-exfil` | data-exfiltration | 1 | Helper harvests the environment and POSTs it out (bash) |
| `skill-py-env-exfil` | data-exfiltration | 1 | Helper harvests the environment and POSTs it out (Python) |
| `skill-curl-bash` | supply-chain | 2 | `curl\|bash` remote exec + unpinned dependency manifest |
| `skill-sudo-persist` | rogue-agent | 1 | sudo + launchd persistence + shell-profile hook |
| `skill-overbroad-agency` | excessive-agency | 1 | Instructions grant unbounded, unconfirmed, elevated agency |
| `skill-anti-refusal` | anti-refusal | 1 | Instructions suppress the model's refusal and safety behaviour |
| `skill-memory-poisoning` | memory-poisoning | 1 | Instructions plant a persistent directive in agent memory |
| `control-skill` | — | 0 | Benign false-positive control |

**9 skills, 9 labels across 8 categories, 1 control.** Label ids use the `SKLV-`
prefix to stay distinct from the `MCPV-` server labels in the scorecard.

## Safety rules

Each skill is **proof-of-concept depth** and inert by default:

- The prompt-injection payload targets the reserved `.invalid` TLD.
- `skill-env-exfil` and `skill-py-env-exfil` transmit to `.invalid` and therefore
  send nothing; the latter also refuses unless `ALLOW_EXFIL=1`.
- `skill-curl-bash` and `skill-sudo-persist` refuse to act unless an explicit
  `ALLOW_*` env var is set, which the harness never sets.
- No skill in this corpus is executed by the harness — skill scanners read files.

## Verify and score

```sh
uv run mcp-vulnlab validate --skills      # schema + cross-checks
uv run mcp-vulnlab skills                 # inventory

# Score scanners against the skills corpus:
uv run mcp-vulnlab run --scanner skillspector --skills --out results
uv run mcp-vulnlab run --scanner repo-forensics --skills --out results   # needs REPO_FORENSICS_HOME
uv run mcp-vulnlab run --scanner agent-audit --skills --out results
# -> results/skills/<scanner>/scorecard.json
```

`repo-forensics` is a cloned, script-run scanner rather than a uv tool; install
it and export its location first:

```sh
git clone --depth 1 https://github.com/alexgreensh/repo-forensics.git ~/tools/repo-forensics
export REPO_FORENSICS_HOME="$HOME/tools/repo-forensics"
```

The same harness, matcher, and scoring policy as the server corpus apply; the
only difference is the challenge directory and the `SKLV-` label prefix.

## Why skills and servers share a harness

A skill can call MCP tools, and an MCP server can be installed as part of a
skill — the two attack surfaces compose. Keeping one label schema, one matching
policy, and one scorecard format means a single number can compare "how well a
scanner sees server risks" against "how well it sees skill risks" without
translating between two taxonomies.
