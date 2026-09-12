# Scorecard: `mcp-armor`

Generated 2026-09-12T14:29:24+00:00 against `/Users/river/Projects/mcp-vulnlab`.

## Summary

| metric | value |
|---|---|
| recall | 50.0% (6/12 labels) |
| findings | 14 |
| true positives | 6 |
| false positives | 8 (rate 57.1%) |

## Recall by category

| category | detected | total | recall | |
|---|---:|---:|---:|---|
| `data-exfiltration` | 0 | 2 | 0.0% | `..........` |
| `missing-auth` | 1 | 2 | 50.0% | `#####.....` |
| `overbroad-tool-schema` | 1 | 2 | 50.0% | `#####.....` |
| `pii-disclosure` | 1 | 2 | 50.0% | `#####.....` |
| `prompt-injection` | 2 | 2 | 100.0% | `##########` |
| `supply-chain` | 1 | 2 | 50.0% | `#####.....` |

## Per server

| server | kind | labels | detected | findings | false positives |
|---|---|---:|---:|---:|---:|
| `control-echo` | control | 0 | 0 | 2 | 2 |
| `control-files` | control | 0 | 0 | 3 | 3 |
| `control-gated-admin` | control | 0 | 0 | 1 | 1 |
| `exfil-write` | vulnerable | 2 | 0 | 1 | 1 |
| `injection-echo` | vulnerable | 2 | 2 | 2 | 0 |
| `no-auth-file` | vulnerable | 2 | 1 | 2 | 1 |
| `overbroad-glob` | vulnerable | 2 | 1 | 1 | 0 |
| `pii-leak` | vulnerable | 2 | 1 | 1 | 0 |
| `supply-chain-yolo` | vulnerable | 2 | 1 | 1 | 0 |

## Missed labels (6)

| id | category | severity | server | tool | title |
|---|---|---|---|---|---|
| `MCPV-003` | `data-exfiltration` | critical | `exfil-write` | `save_report` | Arbitrary file write via unconfined path join |
| `MCPV-004` | `data-exfiltration` | high | `exfil-write` | `report://{path}` | Path-traversal defence explicitly disabled on a read resource |
| `MCPV-006` | `overbroad-tool-schema` | high | `overbroad-glob` | `read_path` | Unconstrained absolute path parameter on a read tool |
| `MCPV-008` | `pii-disclosure` | critical | `pii-leak` | `search_users` | Substring search dumps the entire customer table |
| `MCPV-010` | `missing-auth` | critical | `no-auth-file` | `delete_file` | Irreversible delete with no authorization and no confirmation |
| `MCPV-012` | `supply-chain` | high | `supply-chain-yolo` | `(server)` | Floating dependency manifest with no pins or hashes |

## False positives

8 finding(s) matched no label. For a `control` server that is a false positive by definition.

| server | kind | rule | tool | message |
|---|---|---|---|---|
| `control-echo` | control | `Excessive Tool Permissions` | `control-echo` | Excessive host permissions detected for MCP tools on the affected server. |
| `control-echo` | control | `Prompt Injection` | `uptime` | MCP components with hidden instructions may alter agent behavior and trigger unintended or malicious actions. |
| `control-files` | control | `Command Injection` | `read_document` | Hidden command execution patterns found in MCP component metadata, indicating potential command injection vectors. |
| `control-files` | control | `Excessive Tool Permissions` | `control-files` | Excessive host permissions detected for MCP tools on the affected server. |
| `control-files` | control | `Prompt Injection` | `read_document` | MCP components with hidden instructions may alter agent behavior and trigger unintended or malicious actions. |
| `control-gated-admin` | control | `Excessive Tool Permissions` | `control-gated-admin` | Excessive host permissions detected for MCP tools on the affected server. |
| `exfil-write` | vulnerable | `Excessive Tool Permissions` | `exfil-write` | Excessive host permissions detected for MCP tools on the affected server. |
| `no-auth-file` | vulnerable | `Excessive Tool Permissions` | `no-auth-file` | Excessive host permissions detected for MCP tools on the affected server. |

## Notes

- matching policy: tool name exact match (3) > tool name substring (2) > detection signal match (1). Signals shorter than 3 characters are ignored. Each finding is attributed to at most one label, strongest match wins, ties broken by label id. Every unattributed finding counts as a false positive.

