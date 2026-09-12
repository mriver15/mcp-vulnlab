# Agent-skill vulnerabilities — research notes

Grounding for the skills corpus (`corpus/skills/`). What skills are, how they are
attacked, and which weaknesses the corpus models. Compiled 2026-09-12 from
primary sources; each claim is cited.

## What a skill is

A **skill** is a folder of instructions, scripts, and resources that an agent
loads dynamically to perform a task. The de-facto standard is a directory with a
`SKILL.md` file: YAML frontmatter plus Markdown instructions, with optional
`scripts/`, `references/`, and `assets/` subdirectories.

Frontmatter (from the [Agent Skills spec](https://agentskills.io/specification)):

| Field | Required | Notes |
|---|---|---|
| `name` | yes | lowercase, hyphens; must match the directory name |
| `description` | yes | ≤1024 chars; says what the skill does *and when to use it* |
| `license` | no | |
| `compatibility` | no | environment requirements |
| `metadata` | no | arbitrary key-value map |
| `allowed-tools` | no | space-separated pre-approved tools (experimental) |

Skills are loaded *progressively*: metadata at startup, full `SKILL.md` on
activation, referenced files on demand. That means the `description` and the
first screen of `SKILL.md` are the highest-trust surface — and the highest-value
target for an attacker.

## The threat model

The defining property of agent skills is **implicit trust**: the agent loads a
skill and follows it, running under the user's own credentials, with access to
the user's files, session context, and (often) the user's other tools. There is
no signature requirement, no sandbox by default, and no human review step
between "installed" and "executed with my credentials." Marketplaces (ClawHub and
similar) distribute third-party skills at zero friction, which turns every
install into a supply-chain decision.

## The empirical evidence

Three independent measurements say the risk is real, not theoretical:

1. **SkillSpector / Liu et al., 2026** — "Agent Skills in the Wild: An Empirical
   Study of Security Vulnerabilities at Scale": 42,447 skills from major
   marketplaces; **26.1% contain at least one vulnerability**, **5.2% show likely
   malicious intent**, and skills with executable scripts are **2.12× more
   likely** to be vulnerable.
2. **Snyk ToxicSkills** — **36.8% of agent skills have security flaws**.
3. **ClawHavoc campaign** — **341 malicious ClawedBot skills** found on ClawHub
   in a single campaign (1,184 malicious skills total), the same campaign that
   repo-forensics targets with dedicated IOC detection.

These are the numbers the skills corpus exists to make *measurable*: a scanner's
recall against labeled vulnerable skills.

## The vulnerability taxonomy

SkillSpector's 71 patterns across 17 categories are the most complete published
taxonomy and the one the corpus is aligned to (IDs below are SkillSpector's):

| Category | Example patterns | Corpus skill |
|---|---|---|
| Prompt injection | P1 instruction override, **P2 hidden instructions**, P3 exfiltration commands, P9 whitespace padding | `skill-hidden-instructions` |
| Anti-refusal | AR1 refusal suppression, AR2 disclaimer suppression, AR3 safety nullification | `skill-anti-refusal` |
| Data exfiltration | **E1 external transmission**, **E2 env-var harvesting**, E3 file enumeration, E4 context leakage | `skill-env-exfil`, `skill-py-env-exfil` |
| Privilege escalation | PE1 excessive permissions, **PE2 sudo/root**, PE3 credential access | `skill-sudo-persist` |
| Supply chain | **SC1 unpinned deps**, **SC2 curl\|bash**, SC3 obfuscation, SC4 known CVEs, SC6 typosquatting, SC8 shipped bytecode | `skill-curl-bash` |
| Excessive agency | EA1 unrestricted tool access, **EA2 autonomous decisions**, EA3 scope creep | `skill-overbroad-agency` |
| Output handling | OH1 unvalidated output injection, OH2 cross-context output, OH3 unbounded output | — |
| System prompt leakage | P6–P8 | — |
| Memory poisoning | MP1 persistent context, MP2 context stuffing, MP3 memory manipulation | `skill-memory-poisoning` |
| Tool misuse | TM1 parameter abuse, TM2 chaining, TM3 unsafe defaults | — |
| Rogue agent | RA1 self-modification, **RA2 session persistence** | `skill-sudo-persist` |
| Trigger abuse | TR1 broad triggers, TR2 shadow commands, TR3 keyword baiting | — |
| Behavioral AST | AST1 `exec()`, AST2 `eval()`, AST3 dynamic import, AST4 subprocess, AST5 `os.system`, AST6 `compile()`, AST8 dangerous chains | (implied by curl\|bash) |
| Taint tracking | TT1–TT5 (source→sink flows) | `skill-env-exfil`, `skill-py-env-exfil` (TT3 credentials→network, bash + Python) |
| YARA | YR1–YR4 malware/webshell/cryptominer signatures | — |
| MCP least privilege | LP1–LP4 | (MCP corpus) |
| MCP tool poisoning | TP1 hidden metadata, TP2 unicode deception, TP3 param injection, TP4 description/behaviour mismatch | (MCP corpus) |

Mapping to **OWASP Agentic AI Top 10** (ASI): prompt injection → ASI-01; tool
misuse / dangerous code → ASI-02; supply chain → ASI-03; data exfiltration →
ASI-04; excessive agency → ASI-05; rogue-agent persistence → ASI-06; memory
poisoning → ASI-07; cascading failures → ASI-08. The corpus labels are tagged
with OWASP LLM Top 10 and CWE where applicable.

## The patterns that matter most

Across the three studies, seven patterns recur and are the ones the MVP corpus
deliberately contains:

1. **Hidden instructions** (`skill-hidden-instructions`): instruction-shaped text
   concealed in comments or invisible characters, so the human reviewer sees a
   benign skill and the agent sees a directive.
2. **Secret harvesting + external transmission** (`skill-env-exfil`,
   `skill-py-env-exfil`): reading the process environment and sending it out. The
   single highest-blast-radius pattern because the environment is where the keys
   live. Modelled in both bash and Python so shell-only and Python-only scanners
   each have a target.
3. **Remote fetch-and-execute** (`skill-curl-bash`): `curl | bash` with no
   checksum, signature, or allowlist — the one-line install that trades away all
   integrity.
4. **Persistence** (`skill-sudo-persist`): escalation plus a launchd/cron/startup
   artifact that re-fetches a remote payload, so the foothold survives logout and
   can be updated.
5. **Unbounded agency in the instructions themselves** (`skill-overbroad-agency`):
   the skill *declares* the authority to escalate, skip confirmation, and disable
   guardrails. No code required — the instruction text is the payload.
6. **Anti-refusal** (`skill-anti-refusal`): instructions that tell the model to
   never refuse, ignore safety guidelines, and suppress disclaimers — targeting
   the model's own guardrails rather than any tool or file.
7. **Memory poisoning** (`skill-memory-poisoning`): instructions that plant a
   persistent, attacker-authored directive into the agent's long-term memory, so
   a single activation becomes a standing authorization.

## Scanner landscape for skills

Unlike the MCP side, the skill-scanner field is thin but real:

- **SkillSpector (NVIDIA)** — the reference skill scanner: 71 patterns, two-stage
  (fast static + optional LLM), JSON/Markdown/SARIF output. Installed and scored
  in this repo (`skillspector scan <dir> --no-llm`).
- **repo-forensics** — offline static audit (27 scanners; 17 in `--skill-scan`
  mode) for skills/repos/plugins with supply-chain forensics, a correlation
  engine, and ClawHavoc IOC detection. Installed and scored in this repo
  (`bash "$REPO_FORENSICS_HOME/skills/repo-forensics/scripts/run_forensics.sh"
  <skill> --skill-scan --format json --offline`). License: PolyForm
  Noncommercial (free for personal/research/education).
- **snyk-agent-scan** — scans skills alongside MCP configs, but it is a **hosted
  cloud scanner**: the CLI uploads every file in the target directory (including
  this corpus's `exploits.json` ground truth) to
  `api.snyk.io/hidden/mcp-scan/analysis-machine`. It also could not be driven
  headlessly in v0.6.3 (see F8), so it is recorded as *not run* rather than
  scored — and should not be pointed at non-public code.
- **agent-audit** — generic agent-code static analyzer (53 rules, OWASP Agentic
  Top 10 mapping). Not skill-aware (it parses Python, not `SKILL.md` or shell),
  but it does fire on shell daemon/persistence patterns; scored in this repo as
  a contrast case.

## First measurements (2026-09-12)

| scanner | recall | findings | FP rate | note |
|---|---|---:|---:|---|
| SkillSpector | **9/9 (100%)** | 85 | 89.4% | static-only; scans ground-truth files |
| repo-forensics | **7/9 (77.8%)** | 33 | 78.8% | catches the Python env exfil (SKLV-008) on the real file; misses unpinned deps (004) and agency (006) |
| agent-audit | **1/9 (11.1%)** | 2 | 50.0% | only the launchd daemon (SKLV-005); blind to the Python env exfil |

SkillSpector recalled **9/9 skill labels (100%)** with 85 findings (76
unmatched) — the same high-recall/low-precision profile it showed against the MCP
corpus, and for the same reason: it also scans the corpus's own `README.md` and
`exploits.json` ground-truth files. `repo-forensics` caught all three added
skills, including a clean tool-name hit on the Python env exfil via its dataflow
scanner. Full scorecards in [`results/skills/`](../../results/skills/).

## Sources

- [Agent Skills specification](https://agentskills.io/specification)
- [anthropics/skills](https://github.com/anthropics/skills) (format + examples)
- [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector) (71-pattern taxonomy, Liu et al. 2026)
- [Snyk ToxicSkills](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub) (36.8% figure)
- [repo-forensics](https://github.com/alexgreensh/repo-forensics) (ClawHavoc campaign)
- [OWASP Agentic AI Top 10](https://genai.owasp.org/) (ASI mapping)
