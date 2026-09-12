# Methodology

How the numbers in [`FINDINGS.md`](../FINDINGS.md) are produced, and how to read
them honestly. `FINDINGS.md` is **generated** (`make findings`) from the
committed scorecards; this file is the interpretation guide that does not change
when a scanner is re-run.

## What is measured

| metric | definition |
|---|---|
| **recall** | labeled weaknesses detected ÷ labeled weaknesses present |
| **false-positive rate** | findings matching no label ÷ all findings |
| **not run** | a scanner that produced no parseable output is *not run*, never 0% recall |

The corpus is the ground truth: `corpus/servers/` (MCP) and `corpus/skills/`
(agent skills), each challenge carrying labels specific enough that a human can
decide whether a given finding corresponds to it.

## The matching policy

Attribution is deliberately conservative, so recall cannot be inflated:

1. **A finding is attributed to at most one label.** If one vague finding could
   describe two labels, it counts for the strongest match only.
2. **Match strength:** finding names the label's tool exactly (3) > the tool name
   appears in the finding text (2) > the finding text contains one of the label's
   declared `detection.signals` (1).
3. **Every unattributed finding is a false positive.** On a control challenge that
   is true by definition; on a vulnerable one it is a report a human still has to
   triage.
4. **Ties break by label id, then finding order** — fully deterministic, which CI
   enforces by running twice and diffing.

The policy is recorded in every scorecard, so a disputed number can be re-derived
from its own rules. The signal floor (3 chars) and the "one finding, one label"
rule are the two knobs most capable of moving the headline number; they are fixed
for exactly that reason.

## The two families of scanner

The single most useful lens on the results is that the scanners fall into
families that are *structurally blind* to each other's findings:

- **Spec-conformance** (`mcp-security-scanner`) checks MCP protocol conformance
  (auth, transport, tools, prompts, resources) rather than vulnerability
  signatures. It found nothing on the corpus because every challenge is
  spec-*compliant* — the labeled weaknesses are **semantic** (a poisoned tool
  description, an over-broad schema, a disabled control), not protocol
  violations. A conformance scanner is blind to them by construction.
- **Static / supply-chain** (`cisco-mcp-scanner`, `agent-audit`,
  `repo-forensics`) read code and configs; they see capability and pattern, not
  runtime behaviour.
- **Semantic / model-based** (`mcp-armor`, SkillSpector's LLM analyzers) judge
  *meaning* — what a description tells the model to do — which static rules
  cannot.
- **Hosted** (`snyk-agent-scan`) uploads code to a cloud API and could not be
  automated at all.

No scanner in the measurement crosses these boundaries, which is the argument
for running several of them, not one.

## The headline finding

`MCPV-004` is a path-traversal defence that is **explicitly disabled**
(`ResourceSecurity(exempt_params={"path"})`), not absent. Every scored scanner
misses it — the only label with that property after the corpus grew to 14. Tools
tuned to detect *missing* validation do not detect *disabled* validation. The
full table is in [`FINDINGS.md`](../FINDINGS.md); the build log that predicted it
is in [`docs/engineering-notes.md`](engineering-notes.md) (F2).

## Caveats — what the numbers do not say

1. **SkillSpector was run static-only.** `--no-llm` skips its three semantic
   analyzers, which are the ones that detect description/behaviour mismatch —
   precisely `MCPV-001` (a tool description that *tells* the model to trust
   injected instructions). A static-only, no-API-key run is a capability ceiling
   of that run, not proof the tool cannot detect it.
2. **Directory-scoped scanners read the corpus's own ground truth.** SkillSpector
   and `agent-audit` scan the whole challenge directory, including `README.md`
   and `exploits.json` — the exact security vocabulary the labels use. Some of
   their unmatched findings are the scanners flagging the *documentation of* a
   vulnerability, which inflates the false-positive rate without inflating
   recall.
3. **Cisco's unmatched findings are mostly taxonomy, not error.** Its `readiness`
   and `prompt_defense` analyzers report "missing defence against X" on
   essentially every tool, including all three benign controls. By the harness's
   definition that is a high FP rate; by Cisco's definition it is a readiness
   checklist. The per-category recall table in `FINDINGS.md` is the fairer
   comparison.
4. **`mcp-armor` runs a local model** (downloaded once, ~290MB) rather than a
   hosted API, so its prompt-injection detection is reproducible offline. Its
   `Excessive Tool Permissions` rule treats the server's interpreter path as a
   risky host permission and fires on every server — the bulk of its false
   positives.
5. **`mcp-shield` keyless output is a checklist, not a findings list.** It marks
   every tool "Verified" with no severity or finding vocabulary, so its 0% is a
   statement about its default output format, not a verdict that the corpus is
   clean.
6. **`agent-audit` is a generic agent-code analyzer, not a skill scanner.** It
   never flags the Python environment exfiltration (SKLV-008), which is the data
   point that separates "skill detection" from "agent-code analysis". See
   [`docs/research/skills.md`](research/skills.md).

`snyk-agent-scan` 0.6.3 emitted no stdout and exited 1 in every headless run, so
it is recorded as *not run* rather than 0% — see
[`docs/engineering-notes.md`](engineering-notes.md) (F8).

## Not scored, by category of reason

The rest of the ecosystem was investigated and could not be scored as a stdio
CLI, each for a distinct reason worth recording:

| Tool | Why not scored here |
|---|---|
| `nova-proximity` (Nova-Hunting) | Live scan requires a streamable-HTTP endpoint; our challenges are stdio servers |
| `AI-Infra-Guard` (Tencent) | Docker/client-server red-teaming platform, not a one-shot CLI |
| `agentic-radar` (splx-ai) | Scans agentic-framework *code* (LangGraph/CrewAI/n8n); "MCP detection" is a code feature, not a server scan |
| `mcpSafetyScanner` | Requires an OpenAI API key (`scan.py --config …`) |
| `pipelock` | Runtime egress firewall (proxy); a different tier — traffic mediation, not scanning |
| `medusa` (Pantheon) | Adjacent: Claude Code hooks, skills, secrets (`medusa scan --git`) |

## Reproduce

```sh
uv tool install --python 3.13 cisco-ai-mcp-scanner
uv tool install --python 3.13 mcp-armor
uv tool install --python 3.12 git+https://github.com/NVIDIA/SkillSpector.git
uv tool install agent-audit
npm install -g mcp-shield
uv tool install snyk-agent-scan

git clone --depth 1 https://github.com/alexgreensh/repo-forensics.git ~/tools/repo-forensics
export REPO_FORENSICS_HOME="$HOME/tools/repo-forensics"

for s in cisco-mcp-scanner mcp-armor skillspector agent-audit mcp-shield snyk-agent-scan; do
  uv run mcp-vulnlab run --scanner "$s" --out results
done
for s in skillspector repo-forensics agent-audit; do
  uv run mcp-vulnlab run --scanner "$s" --skills --out results
done

make findings   # regenerate FINDINGS.md from results/
```

Raw scanner output is committed under `results/<scanner>/raw/` and
`results/skills/<scanner>/raw/`, so any disputed match can be audited without
re-running anything.
