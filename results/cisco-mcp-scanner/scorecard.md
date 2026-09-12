# Scorecard: `cisco-mcp-scanner`

Generated 2026-09-12T14:12:51+00:00 against `/Users/river/Projects/mcp-vulnlab`.

## Summary

| metric | value |
|---|---|
| recall | 83.3% (10/12 labels) |
| findings | 40 |
| true positives | 10 |
| false positives | 30 (rate 75.0%) |

## Recall by category

| category | detected | total | recall | |
|---|---:|---:|---:|---|
| `data-exfiltration` | 1 | 2 | 50.0% | `#####.....` |
| `missing-auth` | 2 | 2 | 100.0% | `##########` |
| `overbroad-tool-schema` | 2 | 2 | 100.0% | `##########` |
| `pii-disclosure` | 2 | 2 | 100.0% | `##########` |
| `prompt-injection` | 2 | 2 | 100.0% | `##########` |
| `supply-chain` | 1 | 2 | 50.0% | `#####.....` |

## Per server

| server | kind | labels | detected | findings | false positives |
|---|---|---:|---:|---:|---:|
| `control-echo` | control | 0 | 0 | 6 | 6 |
| `control-files` | control | 0 | 0 | 6 | 6 |
| `control-gated-admin` | control | 0 | 0 | 4 | 4 |
| `exfil-write` | vulnerable | 2 | 1 | 2 | 1 |
| `injection-echo` | vulnerable | 2 | 2 | 4 | 2 |
| `no-auth-file` | vulnerable | 2 | 2 | 4 | 2 |
| `overbroad-glob` | vulnerable | 2 | 2 | 6 | 4 |
| `pii-leak` | vulnerable | 2 | 2 | 4 | 2 |
| `supply-chain-yolo` | vulnerable | 2 | 1 | 4 | 3 |

## Missed labels (2)

| id | category | severity | server | tool | title |
|---|---|---|---|---|---|
| `MCPV-004` | `data-exfiltration` | high | `exfil-write` | `report://{path}` | Path-traversal defence explicitly disabled on a read resource |
| `MCPV-012` | `supply-chain` | high | `supply-chain-yolo` | `(server)` | Floating dependency manifest with no pins or hashes |

## False positives

30 finding(s) matched no label. For a `control` server that is a false positive by definition.

| server | kind | rule | tool | message |
|---|---|---|---|---|
| `control-echo` | control | `readiness_analyzer` | `ping` | Tool 'ping' does not specify a timeout. Operations may hang indefinitely if external services become unresponsive. |
| `control-echo` | control | `promptdefense_analyzer` | `ping` | No instruction override defense found. Tool description lacks safeguards against users overriding system instructions. |
| `control-echo` | control | `readiness_analyzer` | `uptime` | Tool 'uptime' does not specify a timeout. Operations may hang indefinitely if external services become unresponsive. |
| `control-echo` | control | `promptdefense_analyzer` | `uptime` | No instruction override defense found. Tool description lacks safeguards against users overriding system instructions. |
| `control-echo` | control | `readiness_analyzer` | `render_greeting` | Tool 'render_greeting' does not specify a timeout. Operations may hang indefinitely if external services become unresponsive. |
| `control-echo` | control | `promptdefense_analyzer` | `render_greeting` | No data leakage defense found. Tool description lacks instructions to protect sensitive or confidential information. |
| `control-files` | control | `readiness_analyzer` | `list_documents` | Tool 'list_documents' does not specify a timeout. Operations may hang indefinitely if external services become unresponsive. |
| `control-files` | control | `promptdefense_analyzer` | `list_documents` | No instruction override defense found. Tool description lacks safeguards against users overriding system instructions. |
| `control-files` | control | `readiness_analyzer` | `read_document` | Tool 'read_document' does not specify a timeout. Operations may hang indefinitely if external services become unresponsive. |
| `control-files` | control | `promptdefense_analyzer` | `read_document` | No data leakage defense found. Tool description lacks instructions to protect sensitive or confidential information. |
| `control-files` | control | `readiness_analyzer` | `save_note` | Tool 'save_note' does not specify a timeout. Operations may hang indefinitely if external services become unresponsive. |
| `control-files` | control | `promptdefense_analyzer` | `save_note` | No instruction override defense found. Tool description lacks safeguards against users overriding system instructions. |
| `control-gated-admin` | control | `readiness_analyzer` | `get_customer` | Tool 'get_customer' does not specify a timeout. Operations may hang indefinitely if external services become unresponsive. |
| `control-gated-admin` | control | `promptdefense_analyzer` | `get_customer` | No instruction override defense found. Tool description lacks safeguards against users overriding system instructions. |
| `control-gated-admin` | control | `readiness_analyzer` | `delete_record` | Tool 'delete_record' does not specify a timeout. Operations may hang indefinitely if external services become unresponsive. |
| `control-gated-admin` | control | `promptdefense_analyzer` | `delete_record` | No instruction override defense found. Tool description lacks safeguards against users overriding system instructions. |
| `exfil-write` | vulnerable | `promptdefense_analyzer` | `save_report` | No instruction override defense found. Tool description lacks safeguards against users overriding system instructions. |
| `injection-echo` | vulnerable | `promptdefense_analyzer` | `operator_note` | No instruction override defense found. Tool description lacks safeguards against users overriding system instructions. |
| `injection-echo` | vulnerable | `promptdefense_analyzer` | `echo` | No instruction override defense found. Tool description lacks safeguards against users overriding system instructions. |
| `no-auth-file` | vulnerable | `promptdefense_analyzer` | `read_file` | No instruction override defense found. Tool description lacks safeguards against users overriding system instructions. |
| `no-auth-file` | vulnerable | `promptdefense_analyzer` | `delete_file` | No instruction override defense found. Tool description lacks safeguards against users overriding system instructions. |
| `overbroad-glob` | vulnerable | `readiness_analyzer` | `find_files` | Tool 'find_files' does not specify a timeout. Operations may hang indefinitely if external services become unresponsive. |
| `overbroad-glob` | vulnerable | `promptdefense_analyzer` | `find_files` | No instruction override defense found. Tool description lacks safeguards against users overriding system instructions. |
| `overbroad-glob` | vulnerable | `readiness_analyzer` | `read_path` | Tool 'read_path' does not specify a timeout. Operations may hang indefinitely if external services become unresponsive. |
| `overbroad-glob` | vulnerable | `promptdefense_analyzer` | `read_path` | No instruction override defense found. Tool description lacks safeguards against users overriding system instructions. |
| `pii-leak` | vulnerable | `promptdefense_analyzer` | `lookup_user` | No instruction override defense found. Tool description lacks safeguards against users overriding system instructions. |
| `pii-leak` | vulnerable | `promptdefense_analyzer` | `search_users` | No instruction override defense found. Tool description lacks safeguards against users overriding system instructions. |
| `supply-chain-yolo` | vulnerable | `promptdefense_analyzer` | `install_plugin` | No instruction override defense found. Tool description lacks safeguards against users overriding system instructions. |
| `supply-chain-yolo` | vulnerable | `readiness_analyzer` | `list_plugins` | Tool 'list_plugins' does not specify a timeout. Operations may hang indefinitely if external services become unresponsive. |
| `supply-chain-yolo` | vulnerable | `promptdefense_analyzer` | `list_plugins` | No instruction override defense found. Tool description lacks safeguards against users overriding system instructions. |

## Notes

- matching policy: tool name exact match (3) > tool name substring (2) > detection signal match (1). Signals shorter than 3 characters are ignored. Each finding is attributed to at most one label, strongest match wins, ties broken by label id. Every unattributed finding counts as a false positive.

