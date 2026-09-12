# Scorecard: `agent-audit`

Generated 2026-09-12T15:45:46+00:00 against `/Users/river/Projects/mcp-vulnlab`.

## Summary

| metric | value |
|---|---|
| recall | 16.7% (1/6 labels) |
| findings | 1 |
| true positives | 1 |
| false positives | 0 (rate 0.0%) |

## Recall by category

| category | detected | total | recall | |
|---|---:|---:|---:|---|
| `data-exfiltration` | 0 | 1 | 0.0% | `..........` |
| `excessive-agency` | 0 | 1 | 0.0% | `..........` |
| `prompt-injection` | 0 | 1 | 0.0% | `..........` |
| `rogue-agent` | 1 | 1 | 100.0% | `##########` |
| `supply-chain` | 0 | 2 | 0.0% | `..........` |

## Per server

| server | kind | labels | detected | findings | false positives |
|---|---|---:|---:|---:|---:|
| `control-skill` | control | 0 | 0 | 0 | 0 |
| `skill-curl-bash` | vulnerable | 2 | 0 | 0 | 0 |
| `skill-env-exfil` | vulnerable | 1 | 0 | 0 | 0 |
| `skill-hidden-instructions` | vulnerable | 1 | 0 | 0 | 0 |
| `skill-overbroad-agency` | vulnerable | 1 | 0 | 0 | 0 |
| `skill-sudo-persist` | vulnerable | 1 | 1 | 1 | 0 |

## Missed labels (5)

| id | category | severity | server | tool | title |
|---|---|---|---|---|---|
| `SKLV-001` | `prompt-injection` | high | `skill-hidden-instructions` | `(skill)` | Skill embeds an exfiltration instruction in an HTML comment |
| `SKLV-002` | `data-exfiltration` | critical | `skill-env-exfil` | `scripts/collect.sh` | Skill helper harvests environment variables and transmits them externally |
| `SKLV-003` | `supply-chain` | critical | `skill-curl-bash` | `scripts/install.sh` | Installer pipes a remote URL straight into bash |
| `SKLV-004` | `supply-chain` | high | `skill-curl-bash` | `(skill)` | Skill ships a fully unpinned dependency manifest |
| `SKLV-006` | `excessive-agency` | high | `skill-overbroad-agency` | `(skill)` | Skill grants unbounded agency and instructs the agent to disable its own guardrails |

## False positives

None. Every finding was attributed to a label.

## Notes

- skill-sudo-persist: scanner exited with status 1
- matching policy: tool name exact match (3) > tool name substring (2) > detection signal match (1). Signals shorter than 3 characters are ignored. Each finding is attributed to at most one label, strongest match wins, ties broken by label id. Every unattributed finding counts as a false positive.

