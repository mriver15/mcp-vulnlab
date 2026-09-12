# MCP VulnLab scorecard

Scanners: `cisco-mcp-scanner`, `mcp-armor`, `skillspector`, `agent-audit`, `mcp-security-scanner`, `mcp-shield`, `snyk-agent-scan`

> Coverage is measured against the labeled corpus. A scanner that could not be run is shown as *not run* — absence of evidence, not evidence of absence.

## Headline

| scanner | recall | detected | missed | findings | false positives | FP rate |
|---|---:|---:|---:|---:|---:|---:|
| `cisco-mcp-scanner` | 83.3% | 10/12 | 2 | 40 | 30 | 75.0% |
| `mcp-armor` | 50.0% | 6/12 | 6 | 14 | 8 | 57.1% |
| `skillspector` | 25.0% | 3/12 | 9 | 37 | 34 | 91.9% |
| `agent-audit` | 8.3% | 1/12 | 11 | 10 | 9 | 90.0% |
| `mcp-security-scanner` | 0.0% | 0/12 | 12 | 9 | 9 | 100.0% |
| `mcp-shield` | 0.0% | 0/12 | 12 | 0 | 0 | n/a |
| `snyk-agent-scan` | *not run* | — | — | — | — | — |

## Recall by category

| category | `cisco-mcp-scanner` | `mcp-armor` | `skillspector` | `agent-audit` | `mcp-security-scanner` | `mcp-shield` | `snyk-agent-scan` |
|---|---:|---:|---:|---:|---:|---:|---:|
| `data-exfiltration` | 1/2 (50.0%) | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) | — |
| `missing-auth` | 2/2 (100.0%) | 1/2 (50.0%) | 1/2 (50.0%) | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) | — |
| `overbroad-tool-schema` | 2/2 (100.0%) | 1/2 (50.0%) | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) | — |
| `pii-disclosure` | 2/2 (100.0%) | 1/2 (50.0%) | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) | — |
| `prompt-injection` | 2/2 (100.0%) | 2/2 (100.0%) | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) | 0/2 (0.0%) | — |
| `supply-chain` | 1/2 (50.0%) | 1/2 (50.0%) | 2/2 (100.0%) | 1/2 (50.0%) | 0/2 (0.0%) | 0/2 (0.0%) | — |

## Missed by every scanner that ran

| id | category | severity | server | tool | title |
|---|---|---|---|---|---|
| `MCPV-004` | `data-exfiltration` | high | `exfil-write` | `report://{path}` | Path-traversal defence explicitly disabled on a read resource |
