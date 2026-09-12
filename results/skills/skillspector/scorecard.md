# Scorecard: `skillspector`

Generated 2026-09-12T15:14:52+00:00 against `/Users/river/Projects/mcp-vulnlab`.

## Summary

| metric | value |
|---|---|
| recall | 100.0% (6/6 labels) |
| findings | 64 |
| true positives | 6 |
| false positives | 58 (rate 90.6%) |

## Recall by category

| category | detected | total | recall | |
|---|---:|---:|---:|---|
| `data-exfiltration` | 1 | 1 | 100.0% | `##########` |
| `excessive-agency` | 1 | 1 | 100.0% | `##########` |
| `prompt-injection` | 1 | 1 | 100.0% | `##########` |
| `rogue-agent` | 1 | 1 | 100.0% | `##########` |
| `supply-chain` | 2 | 2 | 100.0% | `##########` |

## Per server

| server | kind | labels | detected | findings | false positives |
|---|---|---:|---:|---:|---:|
| `control-skill` | control | 0 | 0 | 1 | 1 |
| `skill-curl-bash` | vulnerable | 2 | 2 | 19 | 17 |
| `skill-env-exfil` | vulnerable | 1 | 1 | 4 | 3 |
| `skill-hidden-instructions` | vulnerable | 1 | 1 | 14 | 13 |
| `skill-overbroad-agency` | vulnerable | 1 | 1 | 10 | 9 |
| `skill-sudo-persist` | vulnerable | 1 | 1 | 16 | 15 |

## Missed labels (0)

None. This scanner detected every labeled weakness in the corpus.

## False positives

58 finding(s) matched no label. For a `control` server that is a false positive by definition.

| server | kind | rule | tool | message |
|---|---|---|---|---|
| `control-skill` | control | `EA2` | `—` | Skill enables autonomous high-impact decisions without human-in-the-loop verification. Critical operations (destructive commands, financial transactions, data d |
| `skill-curl-bash` | vulnerable | `SC2` | `—` | Remote code is downloaded and executed. This bypasses code review and could introduce malicious code. |
| `skill-curl-bash` | vulnerable | `SC2` | `—` | Remote code is downloaded and executed. This bypasses code review and could introduce malicious code. |
| `skill-curl-bash` | vulnerable | `SC2` | `—` | Remote code is downloaded and executed. This bypasses code review and could introduce malicious code. |
| `skill-curl-bash` | vulnerable | `SC2` | `—` | Remote code is downloaded and executed. This bypasses code review and could introduce malicious code. |
| `skill-curl-bash` | vulnerable | `SC2` | `—` | Remote code is downloaded and executed. This bypasses code review and could introduce malicious code. |
| `skill-curl-bash` | vulnerable | `SC2` | `—` | Remote code is downloaded and executed. This bypasses code review and could introduce malicious code. |
| `skill-curl-bash` | vulnerable | `SC2` | `—` | Remote code is downloaded and executed. This bypasses code review and could introduce malicious code. |
| `skill-curl-bash` | vulnerable | `TM2` | `—` | Tool calls are chained to bypass individual safety checks or escalate capabilities beyond what any single tool call would allow. |
| `skill-curl-bash` | vulnerable | `LP3` | `—` | Without declared permissions the skill's intent is opaque and cannot be validated. |
| `skill-curl-bash` | vulnerable | `SC1` | `—` | Dependencies lack version pinning, allowing potential malicious package updates. Consider pinning versions. |
| `skill-curl-bash` | vulnerable | `SC4` | `—` | Dependency has known vulnerabilities (CVEs). Using packages with unpatched security flaws exposes the environment to known exploits. |
| `skill-curl-bash` | vulnerable | `SC1` | `—` | Dependencies lack version pinning, allowing potential malicious package updates. Consider pinning versions. |
| `skill-curl-bash` | vulnerable | `SC4` | `—` | Dependency has known vulnerabilities (CVEs). Using packages with unpatched security flaws exposes the environment to known exploits. |
| `skill-curl-bash` | vulnerable | `SC1` | `—` | Dependencies lack version pinning, allowing potential malicious package updates. Consider pinning versions. |
| `skill-curl-bash` | vulnerable | `SC4` | `—` | Dependency has known vulnerabilities (CVEs). Using packages with unpatched security flaws exposes the environment to known exploits. |
| `skill-curl-bash` | vulnerable | `SC1` | `—` | Dependencies lack version pinning, allowing potential malicious package updates. Consider pinning versions. |
| `skill-curl-bash` | vulnerable | `SC4` | `—` | Dependency has known vulnerabilities (CVEs). Using packages with unpatched security flaws exposes the environment to known exploits. |
| `skill-env-exfil` | vulnerable | `AE1` | `—` | Referenced artifact was not completely inspected |
| `skill-env-exfil` | vulnerable | `LP3` | `—` | Without declared permissions the skill's intent is opaque and cannot be validated. |
| `skill-env-exfil` | vulnerable | `E1` | `—` | Data is being sent to an external URL. This could be legitimate telemetry or data exfiltration. Manual review is recommended. |
| `skill-hidden-instructions` | vulnerable | `YR4` | `—` | YARA rule matched a hack tool or exploit indicator (offensive tools, reconnaissance, privilege escalation, or exploit frameworks). |
| `skill-hidden-instructions` | vulnerable | `YR4` | `—` | YARA rule matched a hack tool or exploit indicator (offensive tools, reconnaissance, privilege escalation, or exploit frameworks). |
| `skill-hidden-instructions` | vulnerable | `P1` | `—` | This pattern attempts to override system instructions or ignore safety constraints. Without LLM analysis, manual review is recommended. |
| `skill-hidden-instructions` | vulnerable | `P1` | `—` | This pattern attempts to override system instructions or ignore safety constraints. Without LLM analysis, manual review is recommended. |
| `skill-hidden-instructions` | vulnerable | `P1` | `—` | This pattern attempts to override system instructions or ignore safety constraints. Without LLM analysis, manual review is recommended. |
| `skill-hidden-instructions` | vulnerable | `E4` | `—` | Code or instructions that leak agent conversation context to external services, potentially exposing sensitive user interactions. |
| `skill-hidden-instructions` | vulnerable | `E4` | `—` | Code or instructions that leak agent conversation context to external services, potentially exposing sensitive user interactions. |
| `skill-hidden-instructions` | vulnerable | `E4` | `—` | Code or instructions that leak agent conversation context to external services, potentially exposing sensitive user interactions. |
| `skill-hidden-instructions` | vulnerable | `P3` | `—` | Instructions found that direct the agent to transmit conversation context or user data to external services. |
| `skill-hidden-instructions` | vulnerable | `YR4` | `—` | YARA rule matched a hack tool or exploit indicator (offensive tools, reconnaissance, privilege escalation, or exploit frameworks). |
| `skill-hidden-instructions` | vulnerable | `YR4` | `—` | YARA rule matched a hack tool or exploit indicator (offensive tools, reconnaissance, privilege escalation, or exploit frameworks). |
| `skill-hidden-instructions` | vulnerable | `P1` | `—` | This pattern attempts to override system instructions or ignore safety constraints. Without LLM analysis, manual review is recommended. |
| `skill-hidden-instructions` | vulnerable | `AS3` | `—` | Skill enumerates or reads other installed skills. Access to other skills' SKILL.md files or the skills directory reveals prompt instructions, capabilities, and  |
| `skill-overbroad-agency` | vulnerable | `YR4` | `—` | YARA rule matched a hack tool or exploit indicator (offensive tools, reconnaissance, privilege escalation, or exploit frameworks). |
| `skill-overbroad-agency` | vulnerable | `YR4` | `—` | YARA rule matched a hack tool or exploit indicator (offensive tools, reconnaissance, privilege escalation, or exploit frameworks). |
| `skill-overbroad-agency` | vulnerable | `RA1` | `—` | Skill modifies its own code, configuration, or behavior at runtime. Self-modification enables an agent to escalate privileges, disable safety constraints, or in |
| `skill-overbroad-agency` | vulnerable | `EA2` | `—` | Skill enables autonomous high-impact decisions without human-in-the-loop verification. Critical operations (destructive commands, financial transactions, data d |
| `skill-overbroad-agency` | vulnerable | `EA2` | `—` | Skill enables autonomous high-impact decisions without human-in-the-loop verification. Critical operations (destructive commands, financial transactions, data d |
| `skill-overbroad-agency` | vulnerable | `AS3` | `—` | Skill enumerates or reads other installed skills. Access to other skills' SKILL.md files or the skills directory reveals prompt instructions, capabilities, and  |
| `skill-overbroad-agency` | vulnerable | `EA2` | `—` | Skill enables autonomous high-impact decisions without human-in-the-loop verification. Critical operations (destructive commands, financial transactions, data d |
| `skill-overbroad-agency` | vulnerable | `EA2` | `—` | Skill enables autonomous high-impact decisions without human-in-the-loop verification. Critical operations (destructive commands, financial transactions, data d |
| `skill-overbroad-agency` | vulnerable | `PE2` | `—` | Commands invoke sudo or root privileges. Verify this elevated access is necessary and justified. |
| `skill-sudo-persist` | vulnerable | `SC2` | `—` | Remote code is downloaded and executed. This bypasses code review and could introduce malicious code. |
| `skill-sudo-persist` | vulnerable | `LP3` | `—` | Without declared permissions the skill's intent is opaque and cannot be validated. |
| `skill-sudo-persist` | vulnerable | `PE2` | `—` | Commands invoke sudo or root privileges. Verify this elevated access is necessary and justified. |
| `skill-sudo-persist` | vulnerable | `RA2` | `—` | Skill establishes unauthorized persistence across sessions via cron jobs, startup scripts, or state files. Session persistence allows an attacker to maintain ac |
| `skill-sudo-persist` | vulnerable | `RA2` | `—` | Skill establishes unauthorized persistence across sessions via cron jobs, startup scripts, or state files. Session persistence allows an attacker to maintain ac |
| `skill-sudo-persist` | vulnerable | `RA2` | `—` | Skill establishes unauthorized persistence across sessions via cron jobs, startup scripts, or state files. Session persistence allows an attacker to maintain ac |
| `skill-sudo-persist` | vulnerable | `RA2` | `—` | Skill establishes unauthorized persistence across sessions via cron jobs, startup scripts, or state files. Session persistence allows an attacker to maintain ac |
| `skill-sudo-persist` | vulnerable | `RA2` | `—` | Skill establishes unauthorized persistence across sessions via cron jobs, startup scripts, or state files. Session persistence allows an attacker to maintain ac |
| `skill-sudo-persist` | vulnerable | `RA2` | `—` | Skill establishes unauthorized persistence across sessions via cron jobs, startup scripts, or state files. Session persistence allows an attacker to maintain ac |
| `skill-sudo-persist` | vulnerable | `RA2` | `—` | Skill establishes unauthorized persistence across sessions via cron jobs, startup scripts, or state files. Session persistence allows an attacker to maintain ac |
| `skill-sudo-persist` | vulnerable | `RA2` | `—` | Skill establishes unauthorized persistence across sessions via cron jobs, startup scripts, or state files. Session persistence allows an attacker to maintain ac |
| `skill-sudo-persist` | vulnerable | `RA2` | `—` | Skill establishes unauthorized persistence across sessions via cron jobs, startup scripts, or state files. Session persistence allows an attacker to maintain ac |
| `skill-sudo-persist` | vulnerable | `RA2` | `—` | Skill establishes unauthorized persistence across sessions via cron jobs, startup scripts, or state files. Session persistence allows an attacker to maintain ac |
| `skill-sudo-persist` | vulnerable | `RA2` | `—` | Skill establishes unauthorized persistence across sessions via cron jobs, startup scripts, or state files. Session persistence allows an attacker to maintain ac |
| `skill-sudo-persist` | vulnerable | `RA2` | `—` | Skill establishes unauthorized persistence across sessions via cron jobs, startup scripts, or state files. Session persistence allows an attacker to maintain ac |

## Notes

- skill-curl-bash: scanner exited with status 1
- skill-hidden-instructions: scanner exited with status 1
- skill-overbroad-agency: scanner exited with status 1
- skill-sudo-persist: scanner exited with status 1
- matching policy: tool name exact match (3) > tool name substring (2) > detection signal match (1). Signals shorter than 3 characters are ignored. Each finding is attributed to at most one label, strongest match wins, ties broken by label id. Every unattributed finding counts as a false positive.

