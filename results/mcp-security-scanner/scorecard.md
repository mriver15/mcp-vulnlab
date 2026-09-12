# Scorecard: `mcp-security-scanner`

Generated 2026-09-12T14:42:06+00:00 against `/Users/river/Projects/mcp-vulnlab`.

## Summary

| metric | value |
|---|---|
| recall | 0.0% (0/12 labels) |
| findings | 9 |
| true positives | 0 |
| false positives | 9 (rate 100.0%) |

## Recall by category

| category | detected | total | recall | |
|---|---:|---:|---:|---|
| `data-exfiltration` | 0 | 2 | 0.0% | `..........` |
| `missing-auth` | 0 | 2 | 0.0% | `..........` |
| `overbroad-tool-schema` | 0 | 2 | 0.0% | `..........` |
| `pii-disclosure` | 0 | 2 | 0.0% | `..........` |
| `prompt-injection` | 0 | 2 | 0.0% | `..........` |
| `supply-chain` | 0 | 2 | 0.0% | `..........` |

## Per server

| server | kind | labels | detected | findings | false positives |
|---|---|---:|---:|---:|---:|
| `control-echo` | control | 0 | 0 | 1 | 1 |
| `control-files` | control | 0 | 0 | 1 | 1 |
| `control-gated-admin` | control | 0 | 0 | 1 | 1 |
| `exfil-write` | vulnerable | 2 | 0 | 1 | 1 |
| `injection-echo` | vulnerable | 2 | 0 | 1 | 1 |
| `no-auth-file` | vulnerable | 2 | 0 | 1 | 1 |
| `overbroad-glob` | vulnerable | 2 | 0 | 1 | 1 |
| `pii-leak` | vulnerable | 2 | 0 | 1 | 1 |
| `supply-chain-yolo` | vulnerable | 2 | 0 | 1 | 1 |

## Missed labels (12)

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

## False positives

9 finding(s) matched no label. For a `control` server that is a false positive by definition.

| server | kind | rule | tool | message |
|---|---|---|---|---|
| `control-echo` | control | `BASE-01` | `—` | Fingerprint server capabilities |
| `control-files` | control | `BASE-01` | `—` | Fingerprint server capabilities |
| `control-gated-admin` | control | `BASE-01` | `—` | Fingerprint server capabilities |
| `exfil-write` | vulnerable | `BASE-01` | `—` | Fingerprint server capabilities |
| `injection-echo` | vulnerable | `BASE-01` | `—` | Fingerprint server capabilities |
| `no-auth-file` | vulnerable | `BASE-01` | `—` | Fingerprint server capabilities |
| `overbroad-glob` | vulnerable | `BASE-01` | `—` | Fingerprint server capabilities |
| `pii-leak` | vulnerable | `BASE-01` | `—` | Fingerprint server capabilities |
| `supply-chain-yolo` | vulnerable | `BASE-01` | `—` | Fingerprint server capabilities |

## Notes

- control-echo: scanner exited with status 1
- control-files: scanner exited with status 1
- control-gated-admin: scanner exited with status 1
- exfil-write: scanner exited with status 1
- injection-echo: scanner exited with status 1
- no-auth-file: scanner exited with status 1
- overbroad-glob: scanner exited with status 1
- pii-leak: scanner exited with status 1
- supply-chain-yolo: scanner exited with status 1
- matching policy: tool name exact match (3) > tool name substring (2) > detection signal match (1). Signals shorter than 3 characters are ignored. Each finding is attributed to at most one label, strongest match wins, ties broken by label id. Every unattributed finding counts as a false positive.

