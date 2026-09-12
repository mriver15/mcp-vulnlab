# Scorecard: `skillspector`

Generated 2026-09-12T14:12:21+00:00 against `/Users/river/Projects/mcp-vulnlab`.

## Summary

| metric | value |
|---|---|
| recall | 25.0% (3/12 labels) |
| findings | 37 |
| true positives | 3 |
| false positives | 34 (rate 91.9%) |

## Recall by category

| category | detected | total | recall | |
|---|---:|---:|---:|---|
| `data-exfiltration` | 0 | 2 | 0.0% | `..........` |
| `missing-auth` | 1 | 2 | 50.0% | `#####.....` |
| `overbroad-tool-schema` | 0 | 2 | 0.0% | `..........` |
| `pii-disclosure` | 0 | 2 | 0.0% | `..........` |
| `prompt-injection` | 0 | 2 | 0.0% | `..........` |
| `supply-chain` | 2 | 2 | 100.0% | `##########` |

## Per server

| server | kind | labels | detected | findings | false positives |
|---|---|---:|---:|---:|---:|
| `control-echo` | control | 0 | 0 | 2 | 2 |
| `control-files` | control | 0 | 0 | 1 | 1 |
| `control-gated-admin` | control | 0 | 0 | 0 | 0 |
| `exfil-write` | vulnerable | 2 | 0 | 1 | 1 |
| `injection-echo` | vulnerable | 2 | 0 | 0 | 0 |
| `no-auth-file` | vulnerable | 2 | 1 | 10 | 9 |
| `overbroad-glob` | vulnerable | 2 | 0 | 10 | 10 |
| `pii-leak` | vulnerable | 2 | 0 | 0 | 0 |
| `supply-chain-yolo` | vulnerable | 2 | 2 | 13 | 11 |

## Missed labels (9)

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

## False positives

34 finding(s) matched no label. For a `control` server that is a false positive by definition.

| server | kind | rule | tool | message |
|---|---|---|---|---|
| `control-echo` | control | `EA2` | `—` | Skill enables autonomous high-impact decisions without human-in-the-loop verification. Critical operations (destructive commands, financial transactions, data d |
| `control-echo` | control | `EA2` | `—` | Skill enables autonomous high-impact decisions without human-in-the-loop verification. Critical operations (destructive commands, financial transactions, data d |
| `control-files` | control | `PE3` | `—` | Code accesses credential files (SSH keys, AWS credentials, etc.). This could indicate credential theft attempts. |
| `exfil-write` | vulnerable | `PE3` | `—` | Code accesses credential files (SSH keys, AWS credentials, etc.). This could indicate credential theft attempts. |
| `no-auth-file` | vulnerable | `EA2` | `—` | Skill enables autonomous high-impact decisions without human-in-the-loop verification. Critical operations (destructive commands, financial transactions, data d |
| `no-auth-file` | vulnerable | `EA2` | `—` | Skill enables autonomous high-impact decisions without human-in-the-loop verification. Critical operations (destructive commands, financial transactions, data d |
| `no-auth-file` | vulnerable | `EA2` | `—` | Skill enables autonomous high-impact decisions without human-in-the-loop verification. Critical operations (destructive commands, financial transactions, data d |
| `no-auth-file` | vulnerable | `EA2` | `—` | Skill enables autonomous high-impact decisions without human-in-the-loop verification. Critical operations (destructive commands, financial transactions, data d |
| `no-auth-file` | vulnerable | `EA2` | `—` | Skill enables autonomous high-impact decisions without human-in-the-loop verification. Critical operations (destructive commands, financial transactions, data d |
| `no-auth-file` | vulnerable | `EA2` | `—` | Skill enables autonomous high-impact decisions without human-in-the-loop verification. Critical operations (destructive commands, financial transactions, data d |
| `no-auth-file` | vulnerable | `EA2` | `—` | Skill enables autonomous high-impact decisions without human-in-the-loop verification. Critical operations (destructive commands, financial transactions, data d |
| `no-auth-file` | vulnerable | `EA2` | `—` | Skill enables autonomous high-impact decisions without human-in-the-loop verification. Critical operations (destructive commands, financial transactions, data d |
| `no-auth-file` | vulnerable | `EA2` | `—` | Skill enables autonomous high-impact decisions without human-in-the-loop verification. Critical operations (destructive commands, financial transactions, data d |
| `overbroad-glob` | vulnerable | `PE3` | `—` | Code accesses credential files (SSH keys, AWS credentials, etc.). This could indicate credential theft attempts. |
| `overbroad-glob` | vulnerable | `PE3` | `—` | Code accesses credential files (SSH keys, AWS credentials, etc.). This could indicate credential theft attempts. |
| `overbroad-glob` | vulnerable | `PE3` | `—` | Code accesses credential files (SSH keys, AWS credentials, etc.). This could indicate credential theft attempts. |
| `overbroad-glob` | vulnerable | `PE3` | `—` | Code accesses credential files (SSH keys, AWS credentials, etc.). This could indicate credential theft attempts. |
| `overbroad-glob` | vulnerable | `PE3` | `—` | Code accesses credential files (SSH keys, AWS credentials, etc.). This could indicate credential theft attempts. |
| `overbroad-glob` | vulnerable | `PE3` | `—` | Code accesses credential files (SSH keys, AWS credentials, etc.). This could indicate credential theft attempts. |
| `overbroad-glob` | vulnerable | `PE3` | `—` | Code accesses credential files (SSH keys, AWS credentials, etc.). This could indicate credential theft attempts. |
| `overbroad-glob` | vulnerable | `PE3` | `—` | Code accesses credential files (SSH keys, AWS credentials, etc.). This could indicate credential theft attempts. |
| `overbroad-glob` | vulnerable | `PE3` | `—` | Code accesses credential files (SSH keys, AWS credentials, etc.). This could indicate credential theft attempts. |
| `overbroad-glob` | vulnerable | `PE3` | `—` | Code accesses credential files (SSH keys, AWS credentials, etc.). This could indicate credential theft attempts. |
| `supply-chain-yolo` | vulnerable | `AST1` | `—` | Direct exec() call allows arbitrary code execution. An attacker can inject code that runs with the full privileges of the process. |
| `supply-chain-yolo` | vulnerable | `AST6` | `—` | compile() creates code objects from strings. When combined with exec()/eval(), it enables obfuscated code execution. |
| `supply-chain-yolo` | vulnerable | `SC4` | `—` | Dependency has known vulnerabilities (CVEs). Using packages with unpatched security flaws exposes the environment to known exploits. |
| `supply-chain-yolo` | vulnerable | `SC1` | `—` | Dependencies lack version pinning, allowing potential malicious package updates. Consider pinning versions. |
| `supply-chain-yolo` | vulnerable | `SC4` | `—` | Dependency has known vulnerabilities (CVEs). Using packages with unpatched security flaws exposes the environment to known exploits. |
| `supply-chain-yolo` | vulnerable | `SC1` | `—` | Dependencies lack version pinning, allowing potential malicious package updates. Consider pinning versions. |
| `supply-chain-yolo` | vulnerable | `SC4` | `—` | Dependency has known vulnerabilities (CVEs). Using packages with unpatched security flaws exposes the environment to known exploits. |
| `supply-chain-yolo` | vulnerable | `SC1` | `—` | Dependencies lack version pinning, allowing potential malicious package updates. Consider pinning versions. |
| `supply-chain-yolo` | vulnerable | `SC4` | `—` | Dependency has known vulnerabilities (CVEs). Using packages with unpatched security flaws exposes the environment to known exploits. |
| `supply-chain-yolo` | vulnerable | `SC1` | `—` | Dependencies lack version pinning, allowing potential malicious package updates. Consider pinning versions. |
| `supply-chain-yolo` | vulnerable | `SC4` | `—` | Dependency has known vulnerabilities (CVEs). Using packages with unpatched security flaws exposes the environment to known exploits. |

## Notes

- supply-chain-yolo: scanner exited with status 1
- matching policy: tool name exact match (3) > tool name substring (2) > detection signal match (1). Signals shorter than 3 characters are ignored. Each finding is attributed to at most one label, strongest match wins, ties broken by label id. Every unattributed finding counts as a false positive.

