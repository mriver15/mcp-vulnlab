# Scorecard: `replay`

Generated 2026-09-12T13:40:33+00:00 against `/Users/river/Projects/mcp-vulnlab`.

## Summary

| metric | value |
|---|---|
| recall | 58.3% (7/12 labels) |
| findings | 8 |
| true positives | 7 |
| false positives | 1 (rate 12.5%) |

## Recall by category

| category | detected | total | recall | |
|---|---:|---:|---:|---|
| `data-exfiltration` | 2 | 2 | 100.0% | `##########` |
| `missing-auth` | 1 | 2 | 50.0% | `#####.....` |
| `overbroad-tool-schema` | 1 | 2 | 50.0% | `#####.....` |
| `pii-disclosure` | 1 | 2 | 50.0% | `#####.....` |
| `prompt-injection` | 1 | 2 | 50.0% | `#####.....` |
| `supply-chain` | 1 | 2 | 50.0% | `#####.....` |

## Per server

| server | kind | labels | detected | findings | false positives |
|---|---|---:|---:|---:|---:|
| `control-echo` | control | 0 | 0 | 1 | 1 |
| `control-files` | control | 0 | 0 | 0 | 0 |
| `control-gated-admin` | control | 0 | 0 | 0 | 0 |
| `exfil-write` | vulnerable | 2 | 2 | 2 | 0 |
| `injection-echo` | vulnerable | 2 | 1 | 1 | 0 |
| `no-auth-file` | vulnerable | 2 | 1 | 1 | 0 |
| `overbroad-glob` | vulnerable | 2 | 1 | 1 | 0 |
| `pii-leak` | vulnerable | 2 | 1 | 1 | 0 |
| `supply-chain-yolo` | vulnerable | 2 | 1 | 1 | 0 |

## Missed labels (5)

| id | category | severity | server | tool | title |
|---|---|---|---|---|---|
| `MCPV-002` | `prompt-injection` | medium | `injection-echo` | `echo` | Tool arguments reflected verbatim into model context |
| `MCPV-006` | `overbroad-tool-schema` | high | `overbroad-glob` | `read_path` | Unconstrained absolute path parameter on a read tool |
| `MCPV-008` | `pii-disclosure` | critical | `pii-leak` | `search_users` | Substring search dumps the entire customer table |
| `MCPV-009` | `missing-auth` | high | `no-auth-file` | `read_file` | Document reads served without any authorization check |
| `MCPV-012` | `supply-chain` | high | `supply-chain-yolo` | `(server)` | Floating dependency manifest with no pins or hashes |

## False positives

1 finding(s) matched no label. For a `control` server that is a false positive by definition.

| server | kind | rule | tool | message |
|---|---|---|---|---|
| `control-echo` | control | `MCP-INJ-009` | `render_greeting` | Tool render_greeting reflects caller-supplied input into its response. |

## Notes

- matching policy: tool name exact match (3) > tool name substring (2) > detection signal match (1). Signals shorter than 3 characters are ignored. Each finding is attributed to at most one label, strongest match wins, ties broken by label id. Every unattributed finding counts as a false positive.

