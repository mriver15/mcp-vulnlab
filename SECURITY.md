# Security policy and acceptable use

## What this repository is

MCP VulnLab is a **defensive security research** project. It exists so that
people building and buying MCP scanners can measure whether those scanners
actually work, using a shared, labeled testbed.

It contains software that is deliberately vulnerable. It does not contain
weaponized exploits.

## Scope of the vulnerabilities

Every challenge in `corpus/servers/` is bound by these rules:

1. **Self-contained.** Servers run over stdio, in-process, on the machine of the
   person running them. Nothing listens on a network port by default.
2. **No real targets.** No challenge contacts a third-party host, exfiltrates to
   a real endpoint, or names a real victim.
3. **Synthetic data only.** PII fixtures use obviously-fake records
   (`alice@example.invalid`, SSNs of `000-00-0000`).
4. **Proof-of-concept depth.** The "exploit" is the shortest thing that
   demonstrates the weakness — enough for a scanner to have a signal to detect.
   Not a general-purpose attack tool.
5. **Contained side effects.** Filesystem-writing challenges write inside a
   sandbox directory under the system temp dir, never to a path the user chose.
6. **Clearly labeled.** Every server directory has a README stating it is
   intentionally vulnerable, and every finding is listed in `exploits.json`.

If you find a challenge that violates any of these, that is a bug — please
report it (see below) and it will be fixed or removed.

## What is out of scope

- Adding real-world attack payloads, evasion techniques, or tooling whose
  primary purpose is to compromise systems you do not own.
- Scanning or testing third-party systems. This corpus is for scanning
  *itself*, locally.
- Supply-chain challenges that actually fetch and execute remote code. See
  `corpus/servers/supply-chain-yolo/README.md` for how the pattern is modeled
  without ever executing anything.

## Reporting a problem

Open a GitHub issue. For anything you believe is sensitive, use GitHub's private
vulnerability reporting on this repository instead of a public issue.

This is a research artifact maintained on a best-effort basis. There is no SLA.

## Reporting a vulnerability in a scanner

If the harness surfaces a genuine vulnerability in a third-party scanner, do not
file it here. Report it to that project's maintainers through their own security
process. Findings about *detection gaps* (a scanner missing a category) are
welcome here and are the whole point of the project.
