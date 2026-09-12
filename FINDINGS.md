# MCP VulnLab — Findings

> Generated from the committed scorecards under `results/`. Rebuild with `make findings` — never edit the numbers by hand.

## Corpus

| corpus | challenges | labels | categories | controls |
|---|---:|---:|---:|---:|
| MCP servers | 11 | 14 | 8 | 3 |
| Agent skills | 9 | 9 | 7 | 1 |

## Headline — every scanner, both corpora

| scanner | corpus | recall | detected | findings | false positives | FP rate |
|---|---:|---:|---:|---:|---:|---:|
| `agent-audit` | MCP | **7.1%** | 1/14 | 15 | 14 | 93.3% |
| `cisco-mcp-scanner` | MCP | **85.7%** | 12/14 | 44 | 32 | 72.7% |
| `mcp-armor` | MCP | **50.0%** | 7/14 | 17 | 10 | 58.8% |
| `mcp-security-scanner` | MCP | **0.0%** | 0/14 | 11 | 11 | 100.0% |
| `mcp-shield` | MCP | **0.0%** | 0/14 | 0 | 0 | n/a |
| `skillspector` | MCP | **28.6%** | 4/14 | 46 | 42 | 91.3% |
| `snyk-agent-scan` | MCP | *not run* | — | — | — | — |
| `agent-audit` | skills | **11.1%** | 1/9 | 2 | 1 | 50.0% |
| `repo-forensics` | skills | **77.8%** | 7/9 | 33 | 26 | 78.8% |
| `skillspector` | skills | **100.0%** | 9/9 | 85 | 76 | 89.4% |

## Recall by category — MCP servers

| category | `agent-audit` | `cisco-mcp-scanner` | `mcp-armor` | `mcp-security-scanner` | `mcp-shield` | `skillspector` | `snyk-agent-scan` |
|---|---:|---:|---:|---:|---:|---:|---:|
| `code-execution` | 0/1 | 1/1 | 0/1 | 0/1 | 0/1 | 1/1 | — |
| `data-exfiltration` | 0/2 | 1/2 | 0/2 | 0/2 | 0/2 | 0/2 | — |
| `missing-auth` | 0/2 | 2/2 | 1/2 | 0/2 | 0/2 | 1/2 | — |
| `overbroad-tool-schema` | 0/2 | 2/2 | 1/2 | 0/2 | 0/2 | 0/2 | — |
| `pii-disclosure` | 0/2 | 2/2 | 1/2 | 0/2 | 0/2 | 0/2 | — |
| `prompt-injection` | 0/2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 | — |
| `supply-chain` | 1/2 | 1/2 | 1/2 | 0/2 | 0/2 | 2/2 | — |
| `tool-poisoning` | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | — |

## Recall by category — agent skills

| category | `agent-audit` | `repo-forensics` | `skillspector` |
|---|---:|---:|---:|
| `anti-refusal` | 0/1 | 1/1 | 1/1 |
| `data-exfiltration` | 0/2 | 2/2 | 2/2 |
| `excessive-agency` | 0/1 | 0/1 | 1/1 |
| `memory-poisoning` | 0/1 | 1/1 | 1/1 |
| `prompt-injection` | 0/1 | 1/1 | 1/1 |
| `rogue-agent` | 1/1 | 1/1 | 1/1 |
| `supply-chain` | 0/2 | 1/2 | 2/2 |

## Missed by every scanner

### MCP servers

| id | category | severity | server | tool | title |
|---|---|---|---|---|---|
| `MCPV-004` | `data-exfiltration` | high | `exfil-write` | `report://{path}` | Path-traversal defence explicitly disabled on a read resource |

### Agent skills

Nothing — every skill label was caught by at least one scanner.

## What these numbers say

1. **A *disabled* control is the hardest thing to detect.** `MCPV-004` — a path-traversal defence that is explicitly turned off rather than absent — is the only MCP label missed by every scored scanner. Tools tuned to find *missing* validation do not find *disabled* validation.
2. **No free lunch.** `cisco-mcp-scanner` has the best MCP recall (85.7%), but at a false-positive rate of 72.7% — every finding that matches no label is triage cost a security team still pays.
3. **No scanner crosses families.** The spec-conformance pentest sees none of the semantic weaknesses; the static scanners see none of the protocol issues; the hosted scanner cannot be automated at all. Coverage is complementary — defence in depth, not a single tool.
4. **Skills are a distinct attack surface.** On the skills corpus `skillspector` recalls 100.0% (9/9) while the generic agent-code analyzer `agent-audit` recalls 11.1% (1/9) — it never flags the Python environment exfiltration at all. Skill detection is a separate capability from agent-code analysis.

## How this was measured

Each scanner finding is attributed to at most one label by a conservative matching policy (tool-name exact > tool-name substring > declared detection signal); every unattributed finding counts as a false positive, and a scanner that could not run is recorded as *not run*, never as 0% recall. The full policy, per-scanner caveats, and reproduction commands are in [`docs/methodology.md`](docs/methodology.md).
