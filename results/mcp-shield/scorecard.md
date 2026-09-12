# Scorecard: `mcp-shield`

Generated 2026-09-12T19:16:11+00:00 against `/Users/river/Projects/mcp-vulnlab`.

## Summary

| metric | value |
|---|---|
| recall | 0.0% (0/14 labels) |
| findings | 0 |
| true positives | 0 |
| false positives | 0 (rate n/a) |

## Recall by category

| category | detected | total | recall | |
|---|---:|---:|---:|---|
| `code-execution` | 0 | 1 | 0.0% | `..........` |
| `data-exfiltration` | 0 | 2 | 0.0% | `..........` |
| `missing-auth` | 0 | 2 | 0.0% | `..........` |
| `overbroad-tool-schema` | 0 | 2 | 0.0% | `..........` |
| `pii-disclosure` | 0 | 2 | 0.0% | `..........` |
| `prompt-injection` | 0 | 2 | 0.0% | `..........` |
| `supply-chain` | 0 | 2 | 0.0% | `..........` |
| `tool-poisoning` | 0 | 1 | 0.0% | `..........` |

## Per server

| server | kind | labels | detected | findings | false positives |
|---|---|---:|---:|---:|---:|
| `control-echo` | control | 0 | 0 | 0 | 0 |
| `control-files` | control | 0 | 0 | 0 | 0 |
| `control-gated-admin` | control | 0 | 0 | 0 | 0 |
| `dangerous-shell-tool` | vulnerable | 1 | 0 | 0 | 0 |
| `exfil-write` | vulnerable | 2 | 0 | 0 | 0 |
| `injection-echo` | vulnerable | 2 | 0 | 0 | 0 |
| `no-auth-file` | vulnerable | 2 | 0 | 0 | 0 |
| `overbroad-glob` | vulnerable | 2 | 0 | 0 | 0 |
| `pii-leak` | vulnerable | 2 | 0 | 0 | 0 |
| `supply-chain-yolo` | vulnerable | 2 | 0 | 0 | 0 |
| `tool-poisoning` | vulnerable | 1 | 0 | 0 | 0 |

## Missed labels (14)

| id | category | severity | server | tool | title |
|---|---|---|---|---|---|
| `MCPV-001` | `prompt-injection` | high | `injection-echo` | `operator_note` | Tool output labelled trusted carries injected instructions |
| `MCPV-002` | `prompt-injection` | medium | `injection-echo` | `echo` | Tool arguments reflected verbatim into model context |
| `MCPV-003` | `data-exfiltration` | critical | `exfil-write` | `save_report` | Arbitrary file write via unconfined path join |
| `MCPV-004` | `data-exfiltration` | high | `exfil-write` | `report://{path}` | Path-traversal defence explicitly disabled on a read resource |
| `MCPV-005` | `overbroad-tool-schema` | high | `overbroad-glob` | `find_files` | Glob search accepts any root and any pattern |
| `MCPV-006` | `overbroad-tool-schema` | high | `overbroad-glob` | `read_path` | Unconstrained absolute path parameter on a read tool |
| `MCPV-007` | `pii-disclosure` | high | `pii-leak` | `lookup_user` | Single-record lookup returns unmasked sensitive fields |
| `MCPV-008` | `pii-disclosure` | critical | `pii-leak` | `search_users` | Substring search dumps the entire customer table |
| `MCPV-009` | `missing-auth` | high | `no-auth-file` | `read_file` | Document reads served without any authorization check |
| `MCPV-010` | `missing-auth` | critical | `no-auth-file` | `delete_file` | Irreversible delete with no authorization and no confirmation |
| `MCPV-011` | `supply-chain` | critical | `supply-chain-yolo` | `install_plugin` | Remote plugin source loaded with no integrity verification |
| `MCPV-012` | `supply-chain` | high | `supply-chain-yolo` | `(server)` | Floating dependency manifest with no pins or hashes |
| `MCPV-013` | `tool-poisoning` | high | `tool-poisoning` | `search_notes` | Tool description promises read-only, implementation writes to the shell profile |
| `MCPV-014` | `code-execution` | critical | `dangerous-shell-tool` | `run_shell` | General-purpose shell tool executes arbitrary commands with no allowlist |

## False positives

None. Every finding was attributed to a label.

## Notes

- matching policy: tool name exact match (3) > tool name substring (2) > detection signal match (1). Signals shorter than 3 characters are ignored. Each finding is attributed to at most one label, strongest match wins, ties broken by label id. Every unattributed finding counts as a false positive.

