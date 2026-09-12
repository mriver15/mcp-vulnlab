# MCP VulnLab scorecard

First real measurement, 2026-09-12. Six scanners ran; one (Snyk) could not be
driven headlessly. Every number below is reproducible from the committed corpus
with the commands in this file, and the raw scanner output that produced it is
preserved under `results/<scanner>/raw/`.

On the same day the corpus expanded: 9 → 11 MCP servers (12 → 14 labels, 6 → 8
categories, adding `tool-poisoning` and `code-execution`) and 6 → 9 skills (6 →
9 labels, 5 → 8 categories, adding `anti-refusal` and `memory-poisoning`). The
tables below are from the expanded corpus.

## Headline

| scanner | version | recall | detected | findings | false positives | FP rate |
|---|---|---:|---:|---:|---:|---:|
| `cisco-mcp-scanner` | 4.8.4 | **85.7%** | 12/14 | 44 | 32 | 72.7% |
| `mcp-armor` | 1.0.2 | **50.0%** | 7/14 | 17 | 10 | 58.8% |
| `skillspector` | 2.11.2 (git `66e7983`) | **28.6%** | 4/14 | 46 | 42 | 91.3% |
| `agent-audit` | 0.19.2 | **7.1%** | 1/14 | 15 | 14 | 93.3% |
| `mcp-security-scanner` | 0.1.5 (sidhpurwala) | **0.0%** | 0/14 | 11 | 11 | 100.0% |
| `mcp-shield` | 1.0.4 | **0.0%** | 0/14 | 0 | 0 | n/a |
| `snyk-agent-scan` | 0.6.3 | *not run* | — | — | — | — |

## Recall by category

| category | `cisco` | `mcp-armor` | `skillspector` | `agent-audit` | `mcp-shield` |
|---|---:|---:|---:|---:|---:|
| `prompt-injection` | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 |
| `data-exfiltration` | 1/2 | 0/2 | 0/2 | 0/2 | 0/2 |
| `overbroad-tool-schema` | 2/2 | 1/2 | 0/2 | 0/2 | 0/2 |
| `missing-auth` | 2/2 | 1/2 | 1/2 | 0/2 | 0/2 |
| `pii-disclosure` | 2/2 | 1/2 | 0/2 | 0/2 | 0/2 |
| `supply-chain` | 1/2 | 1/2 | 2/2 | 1/2 | 0/2 |
| `tool-poisoning` | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 |
| `code-execution` | 1/1 | 0/1 | 1/1 | 0/1 | 0/1 |

Reading the columns as a whole: Cisco has the broadest recall and is the only
scanner to catch both new categories; `mcp-armor` has the best precision among
the useful scanners (58.8% FP rate) and is the only one to catch both
prompt-injection labels without a hosted API key; SkillSpector and `agent-audit`
are static and supply-chain oriented; `mcp-shield` (keyless) is a checklist that
reports nothing. The two new categories split the field cleanly: Cisco and
`mcp-armor` flag the description/behaviour mismatch (`tool-poisoning`), while
Cisco and SkillSpector flag the arbitrary shell (`code-execution`).

## The finding: `MCPV-004` is missed by every scanner that ran

| id | category | severity | server | tool | title |
|---|---|---|---|---|---|
| `MCPV-004` | `data-exfiltration` | high | `exfil-write` | `report://{path}` | Path-traversal defence explicitly disabled on a read resource |

`MCPV-004` is not an *absent* control; it is an **explicitly disabled** one —
`ResourceSecurity(exempt_params={"path"})` turns off the SDK's path-traversal
check for the one parameter that needs it. Every scored scanner missed it — and
after the corpus expanded to 14 labels it remains the **only** label missed by
every scanner. That is the headline result and the strongest single argument for
this benchmark's existence: tools tuned to detect missing validation do not
detect disabled validation.

The mirror image is `mcp-security-scanner` (sidhpurwala-huzaifa, 0.1.5): a
*spec-compliance pentest* tool that checks MCP protocol conformance (auth,
transport, tools, prompts, resources) rather than vulnerability signatures. It
found nothing on the corpus — every challenge is spec-*compliant* (built with
the real SDK), and its only finding is the same `BASE-01` baseline quirk on
every server. The vulnerabilities this corpus labels are **semantic** (prompt
injection in a tool description, over-broad schemas, a disabled control), not
protocol violations, so a conformance scanner is structurally blind to them.
That is itself a measurement: it bounds the two families of "MCP security"
tooling against each other.

## Not scored, by category of reason

The rest of the ecosystem was investigated and could not be scored as a stdio
CLI, each for a distinct reason worth recording:

| Tool | Why not scored here |
|---|---|
| `nova-proximity` (Nova-Hunting) | Live scan requires a streamable-HTTP endpoint; our challenges are stdio servers |
| `AI-Infra-Guard` (Tencent) | Docker/client-server red-teaming platform, not a one-shot CLI |
| `agentic-radar` (splx-ai) | Scans agentic-framework *code* (LangGraph/CrewAI/n8n); "MCP detection" is a code feature, not a server scan |
| `mcpSafetyScanner` | Requires an OpenAI API key (`scan.py --config …`) |
| `repo-forensics` | Static repo/skill audit (supply-chain forensics), not a live MCP scan |
| `pipelock` | Runtime egress firewall (proxy); a different tier — traffic mediation, not scanning |
| `medusa` (Pantheon) | Adjacent: Claude Code hooks, skills, secrets (`medusa scan --git`) |

## What these numbers mean — and what they do not

Caveats without which these figures would be misleading:

1. **SkillSpector was run static-only.** `--no-llm` skips its three semantic
   analyzers, which are the ones that detect description/behaviour mismatch —
   precisely `MCPV-001` (a tool description that *tells* the model to trust
   injected instructions). A 0/2 prompt-injection result for a static-only,
   no-API-key run is not the same claim as "SkillSpector cannot detect prompt
   injection." Full-capability runs need an API key.
2. **SkillSpector and `agent-audit` scan the whole directory**, including the
   corpus's *own ground-truth files* (`README.md`, `exploits.json`). Those
   documents contain the exact security keywords the scanners match, so some of
   their unmatched findings are the scanners flagging the *documentation of* a
   vulnerability. `agent-audit` is a generic agent-code analyzer (its
   `AGENT-026` rule fires on `@tool`-decorated string parameters regardless of
   what the function does), which is why its recall against MCP-specific labels
   is low.
3. **Cisco's unmatched findings are mostly taxonomy, not error.** Its
   `readiness` and `prompt_defense` analyzers report *missing defences* on
   essentially every tool — including all three benign controls. By the harness's
   definition (a finding matching no label) that is a 75% FP rate; by Cisco's own
   definition it is a readiness checklist. The per-category recall above is the
   fairer comparison.
4. **`mcp-armor` runs a local prompt-injection model** (downloaded once, ~290MB)
   rather than calling a hosted API, so its prompt-injection detection is
   reproducible offline. Its `Excessive Tool Permissions` rule fires on every
   server (it treats the Python interpreter path as a risky host permission),
   which is the bulk of its false positives.
5. **`mcp-shield` keyless output is a checklist, not a findings list.** It marks
   every tool "Verified" and emits no severity or finding vocabulary, so its 0%
   is a statement about its default output format, not a verdict that the corpus
   is clean. With `--claude-api-key` it would likely report differently, but
   that path was not reproducible here.

`snyk-agent-scan` 0.6.3 emitted no stdout and exited 1 in every headless run, so
it is recorded as *not run* rather than 0% — see `docs/findings.md` (F8).

## Skills scorecard (first measurement)

The corpus also ships a skills lab — nine deliberately vulnerable agent skills
across eight categories plus one control. Research and taxonomy are in
[docs/skills-vulnerabilities.md](skills-vulnerabilities.md).

| scanner | version | recall | detected | findings | false positives | FP rate |
|---|---|---:|---:|---:|---:|---:|
| `skillspector` (skills corpus) | 2.11.2 | **100.0%** | 9/9 | 85 | 76 | 89.4% |
| `repo-forensics` (skills corpus) | 2.14.8 | **77.8%** | 7/9 | 33 | 26 | 78.8% |
| `agent-audit` (skills corpus) | 0.19.2 | **11.1%** | 1/9 | 2 | 1 | 50.0% |

SkillSpector still recalls every skill label — now including the three added
skills: anti-refusal (SKLV-007), the Python env exfiltration (SKLV-008), and
memory poisoning (SKLV-009). Its 89.4% FP rate has the same causes as before: it
is a high-recall/low-precision static scanner that also reads the corpus's own
`README.md` and `exploits.json`.

`repo-forensics` caught all three new skills too. The notable one is SKLV-008:
it matched on the **real file** with a clean tool-name hit, because its Python
dataflow scanner links `os.environ` to the network sink in `scripts/upload_env.py`
— the thing the skill exists to test. Its two misses are still SKLV-004
(unpinned `requirements.txt`) and SKLV-006 (unbounded agency).

`agent-audit` remains at one hit (SKLV-005) and does **not** flag the Python env
exfiltration — a useful data point: its rules target agent/MCP code patterns
(`@tool` decorators, MCP configs), not generic environment exfiltration.

```sh
git clone --depth 1 https://github.com/alexgreensh/repo-forensics.git ~/tools/repo-forensics
export REPO_FORENSICS_HOME="$HOME/tools/repo-forensics"

uv run mcp-vulnlab run --scanner skillspector --skills --out results
uv run mcp-vulnlab run --scanner repo-forensics --skills --out results
uv run mcp-vulnlab run --scanner agent-audit --skills --out results
```

Raw evidence: [`results/skills/skillspector/`](../results/skills/skillspector/),
[`results/skills/repo-forensics/`](../results/skills/repo-forensics/),
[`results/skills/agent-audit/`](../results/skills/agent-audit/).

## Reproduce

```sh
uv tool install --python 3.13 cisco-ai-mcp-scanner
uv tool install --python 3.13 mcp-armor
uv tool install --python 3.12 git+https://github.com/NVIDIA/SkillSpector.git
uv tool install agent-audit
npm install -g mcp-shield
uv tool install snyk-agent-scan

for s in cisco-mcp-scanner mcp-armor skillspector agent-audit mcp-shield snyk-agent-scan; do
  uv run mcp-vulnlab run --scanner "$s" --out results
done

uv run mcp-vulnlab report \
  --in results/cisco-mcp-scanner \
  --in results/mcp-armor \
  --in results/skillspector \
  --in results/agent-audit \
  --in results/mcp-shield \
  --in results/snyk-agent-scan \
  --out results/comparison.md
```

`report` writes the raw comparison tables to `results/comparison.md`; this file
wraps them with the caveats above. The two must be regenerated together.

Matching policy, recorded verbatim in every `scorecard.json`: tool name exact
match (3) > tool name substring (2) > detection signal match (1); each finding is
attributed to at most one label; every unattributed finding counts as a false
positive. Signals shorter than three characters are ignored. Fully deterministic
— CI runs the offline `replay` scanner twice and diffs the output.

