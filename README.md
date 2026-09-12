# MCP VulnLab

**An open-source evaluation corpus and benchmark harness for MCP security.**

[![CI](https://github.com/mriver15/mcp-vulnlab/actions/workflows/ci.yml/badge.svg)](https://github.com/mriver15/mcp-vulnlab/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

> The MCP security ecosystem has plenty of scanners and no shared testbed. This is the testbed.

Nine deliberately vulnerable MCP servers, 12 labeled exploitable weaknesses
across 6 threat categories, 3 benign controls for false-positive measurement, and
a harness that points any MCP scanner at the corpus and produces a
detection-rate scorecard. A parallel **skills corpus** does the same for agent
skills — 6 vulnerable skills, 6 labels across 5 categories, and a harness that
scores skill scanners.

---

## Summary

Seven scanners were measured against the corpus. The best recall is
`cisco-mcp-scanner` at **83.3%** (10/12 labels); the best precision is
`mcp-armor` at **50.0%** recall with a 57.1% false-positive rate, and it is the
only one to catch both prompt-injection labels with a local, offline model.
Snyk's scanner could not be automated headlessly, and the rest of the field is
either static/adjacent or a different tier (proxy firewalls, hosted gateways).

| scanner | recall | detected | false-positive rate |
|---|---:|---:|---:|
| `cisco-mcp-scanner` 4.8.4 | **83.3%** | 10/12 | 75.0% |
| `mcp-armor` 1.0.2 | **50.0%** | 6/12 | 57.1% |
| `skillspector` 2.11.2 (NVIDIA) | **25.0%** | 3/12 | 91.9% |
| `agent-audit` 0.19.2 | **8.3%** | 1/12 | 90.0% |
| `mcp-security-scanner` 0.1.5 | **0.0%** | 0/12 | 100.0% |
| `mcp-shield` 1.0.4 | **0.0%** | 0/12 | n/a |
| `snyk-agent-scan` 0.6.3 | *not run* | — | — |

The headline finding: **`MCPV-004` — a path-traversal defence explicitly
disabled, not absent — is missed by every scanner that ran.** Full breakdown,
per-category recall, caveats, and reproduction commands:
**[docs/scorecard.md](docs/scorecard.md)**. The raw scanner output behind these
numbers is committed under [`results/`](results/).

---

## Why this exists

There is no shortage of MCP scanners. NVIDIA, Snyk, Cisco and others all ship
one, and the gatekeeper space is crowded. What nobody ships is a way to tell how
good they are. Scan output is unlabeled, so "high severity finding" tells you
nothing about whether a tool found the real weakness or a plausible-looking
non-issue.

This repository is the missing half: **labeled ground truth plus a measurement
harness**, so a scanner's recall and false-positive rate become numbers that
someone else can reproduce.

Two design commitments follow from that:

1. **The corpus is the product.** Each challenge is genuinely exploitable, has
   reproduction steps that work, and carries a label specific enough that a
   human can decide whether a given finding corresponds to it.
2. **The measurement is conservative.** The matching policy (below) is chosen so
   that recall cannot be inflated. A benchmark that flatters scanners is
   worthless.

## Status

Honest accounting of what is and is not done:

| | State |
|---|---|
| Corpus — 9 servers, 12 labels, 6 categories, 3 controls | ✅ complete, schema-validated in CI |
| Harness — runner, adapters, scorer, reporter, CLI | ✅ complete, 106 tests |
| Corpus liveness — every server boots and exposes what its labels claim | ✅ enforced by CI |
| Scorecard reproducibility — identical output across runs | ✅ enforced by CI |
| **Real scanner runs (6 scanners)** | ✅ **done — see [docs/scorecard.md](docs/scorecard.md)** |

The first real measurement is in: **Cisco 83% recall, mcp-armor 50%, NVIDIA
SkillSpector 25%, agent-audit 8%, mcp-shield 0% (keyless), Snyk not automatable
headlessly** — and `MCPV-004`, the one label where a security control is
*deliberately disabled* rather than absent, is missed by every scanner that ran.
Full numbers and the caveats they require are in
[docs/scorecard.md](docs/scorecard.md).

## The corpus

| Server | Category | Labels | The weakness |
|---|---|---|---|
| `injection-echo` | prompt-injection | 2 | Tool output labelled "trusted" carries injected instructions |
| `exfil-write` | data-exfiltration | 2 | Unconfined path join; a resource that disables the SDK's traversal defence |
| `overbroad-glob` | overbroad-tool-schema | 2 | Schemas advertising whole-filesystem scope |
| `pii-leak` | pii-disclosure | 2 | Unmasked records; a substring search that dumps the table |
| `no-auth-file` | missing-auth | 2 | Identity logged but never checked; an ungated irreversible delete |
| `supply-chain-yolo` | supply-chain | 2 | Unverified remote code load; a fully floating dependency manifest |
| `control-*` (3 servers) | — | 0 | Benign false-positive controls |

Full inventory, severity model, and design rationale: **[corpus/README.md](corpus/README.md)**.

The controls are the sharpest part of the corpus. `control-gated-admin` returns a
masked `ssn_masked` field from a tool annotated `destructiveHint=True` — a
scanner that matches on capability names rather than control flow will flag
correctly-built code, and the scorecard will say so.

## The skills corpus

The same idea, applied to **agent skills** — the `SKILL.md` folders agents load
and follow with implicit trust. Six deliberately vulnerable skills across five
categories, plus one benign control:

| Skill | Category | The weakness |
|---|---|---|
| `skill-hidden-instructions` | prompt-injection | Exfiltration instruction hidden in an HTML comment |
| `skill-env-exfil` | data-exfiltration | Helper harvests the environment and POSTs it out |
| `skill-curl-bash` | supply-chain | `curl\|bash` remote exec + unpinned dependency manifest |
| `skill-sudo-persist` | rogue-agent | sudo + launchd persistence + shell-profile hook |
| `skill-overbroad-agency` | excessive-agency | Instructions grant unbounded, unconfirmed agency |
| `control-skill` | — | Benign false-positive control |

Research, taxonomy, and sources: **[docs/skills-vulnerabilities.md](docs/skills-vulnerabilities.md)**.
Inventory and conventions: **[corpus/skills/README.md](corpus/skills/README.md)**.

Score a skill scanner the same way, with `--skills`:

```sh
mcp-vulnlab validate --skills
mcp-vulnlab run --scanner skillspector --skills --out results     # -> results/skills/skillspector/
mcp-vulnlab run --scanner repo-forensics --skills --out results   # -> results/skills/repo-forensics/
mcp-vulnlab run --scanner agent-audit --skills --out results      # -> results/skills/agent-audit/
```

First result: SkillSpector recalls **6/6 skill labels (100%)**; `repo-forensics`
recalls **4/6** (misses only unpinned deps and unbounded agency); `agent-audit`
— a generic agent-code analyzer, not a skill scanner — finds just **1/6** with
zero false positives. See the skills scorecard in
[docs/scorecard.md](docs/scorecard.md).

## Quickstart

```sh
git clone https://github.com/mriver15/mcp-vulnlab
cd mcp-vulnlab
make setup            # uv venv + editable install with dev extras

mcp-vulnlab validate  # is the corpus well-formed?
mcp-vulnlab corpus    # what is in it?
mcp-vulnlab smoke     # does every challenge boot over stdio?
```

### Score a scanner

```sh
# Point any scanner at the corpus. Adapters live in scanners.yaml.
mcp-vulnlab run --scanner skillspector --out results/skillspector

# Several scanners at once, then compare them.
mcp-vulnlab run --scanner all
mcp-vulnlab report --in results/skillspector --in results/snyk-agent-scan
```

`run` writes `scorecard.json`, `scorecard.md`, and the raw scanner output it was
derived from under `results/<scanner>/raw/`. Keeping the raw output matters: a
disputed match can be audited without re-running anything.

### Works with no scanner installed

```sh
make selftest
```

This drives the whole pipeline with a bundled offline `replay` scanner that
replays a hand-authored transcript. **It is not a security scanner** and its
scorecard must never be published as a measurement — it exists so CI can prove
the harness works, reproducibly, with no third-party tooling.

## How scoring works

This section exists because a recall number without its matching rule is not a
reproducible number.

Each scanner finding is normalized to a common shape, then attributed to at most
one label by match strength:

| Strength | Rule |
|---:|---|
| 3 | Finding names the label's tool exactly (`tool` field, case-insensitive) |
| 2 | The label's tool name appears in the finding's text (resource templates match on their literal stem, so `report://{path}` matches `report://`) |
| 1 | The finding text contains one of the label's declared `detection.signals` |
| 0 | No match — the finding is an unmatched result |

Then:

- **A finding is attributed to at most one label.** If one vague finding could
  describe two labels, it counts for the strongest match only. This is why recall
  cannot be inflated by a single broad finding.
- **Strongest match wins; ties break by label id, then finding order.** Fully
  deterministic — the same inputs always produce the same scorecard, which CI
  enforces by running twice and diffing.
- **Every unattributed finding is a false positive.** On a control server that is
  true by definition. On a vulnerable server it means the scanner flagged
  something no label describes — still a report a human has to triage, so it
  still counts.
- **A scanner that could not run is scored as `not run`, not as 0% recall.**
  Absence of evidence is not evidence of absence, and conflating them is the
  easiest way to publish a wrong number.

Signals shorter than 3 characters are ignored, and each signal is a lowercase
substring chosen to be specific. A signal like `"file"` would match half the
corpus and inflate recall — `corpus/labels/README.md` calls this out as a rule.

## Scorecard

The headline table is in the [Summary](#summary) above; the full per-category
breakdown, the caveats these numbers require, and the reproduction commands are
in **[docs/scorecard.md](docs/scorecard.md)**.

The headline finding: **`MCPV-004` — a path-traversal defence explicitly
disabled, not absent — is missed by every scanner that ran.** Its mirror image is
`sidhpurwala`'s `mcp-security-scanner`, a spec-*conformance* pentest tool that
saw nothing because every challenge is spec-compliant — the vulnerabilities are
semantic, not protocol violations. Tools tuned to detect missing validation miss
disabled validation; tools tuned to check protocol conformance miss semantic
weaknesses. No scanner in this measurement does both.

These numbers are honest but not the last word, for reasons spelled out in
[docs/scorecard.md](docs/scorecard.md): SkillSpector was run static-only and
scans agent skills rather than MCP servers; `agent-audit` is a generic agent-code
analyzer; Cisco's FP rate is largely its "missing defence" readiness taxonomy;
`mcp-shield` emits a "Verified" checklist rather than findings without an API
key; Snyk could not be automated headlessly at all (v0.6.3).

The offline self-test below exists so the harness can be verified without any
third-party tooling:

```sh
make selftest    # replay scanner: 58.3% recall (7/12), 1 false positive
```

`replay` is **not a security scanner** — it replays a hand-authored transcript,
and its scorecard must never be presented as a measurement. Its only job is to
prove the runner → adapter → score → report path is deterministic, which CI
enforces by running it twice and diffing.

## Repository layout

```
corpus/
  servers/<slug>/           manifest.json, exploits.json, server.py, README.md
  labels/                   JSON Schemas + generated index.json
harness/
  corpus.py                 discovery, schema validation, index generation
  adapters.py               config-driven scanner output adapters
  runner.py                 subprocess orchestration + MCP smoke probe
  score.py                  matching policy: recall, false positives, per-category
  report.py                 markdown / text / JSON, incl. multi-scanner comparison
  replay.py                 offline scanner used by CI (not a real scanner)
  cli.py                    mcp-vulnlab validate | corpus | index | smoke | run | report
scanners.yaml               one declarative adapter profile per scanner
tests/                      94 tests; corpus invariants are the important ones
```

## Design decisions

Three places where this diverges from the obvious approach, and why:

**Python-only harness.** The original plan allowed a Node runner. Everything else
is Python, so one toolchain keeps CI to a single setup step, lets label validation
reuse the same `jsonschema` registry as the corpus, and keeps the runner in the
same process as the scorer. The adapters are declarative YAML, so adding a
scanner still means editing config rather than code.

**`MCPServer`, not `FastMCP`.** The MCP Python SDK 2.x renamed `FastMCP` to
`MCPServer` and changed several signatures. The corpus targets the current SDK,
because a security testbed written against a superseded API measures the wrong
thing. Dependency is pinned `mcp>=2,<3`.

**Config-driven adapters.** Writing bespoke Python per scanner hides the actual
finding — that every tool emits different JSON — behind three hand-written
parsers. Instead one adapter reads all the profiles, and `harness/adapters.py`
documents the escape hatch for tools that genuinely need custom handling. When a
scanner does need custom parsing, that is worth reporting as a finding.

## Ethics

Every challenge is deliberately vulnerable and clearly labeled. Scope rules are
enforced by the corpus tests and documented in [SECURITY.md](SECURITY.md):
self-contained stdio servers, no third-party targets, synthetic data only,
PoC-depth vulnerabilities, containment for all side effects.

The one pattern-modelling challenge (`supply-chain-yolo`) gates both of its
runtime sinks behind environment variables that the harness and CI never set, so
static analysis sees the full pattern while execution stays inert.

This is a defensive research artifact: it exists so people building and buying
MCP scanners can find out whether those scanners work.

## Roadmap

- Run the three named scanners and publish the real scorecard
- Grow the corpus to ≥ 12 servers, and add challenges for confused-deputy tool
  composition and cross-server context poisoning
- A second control category: servers that are verbose but not vulnerable, to
  probe whether scanners distinguish "risky-looking" from "exploitable"
- Publish `scanners.yaml` profiles upstream to each scanner project so the
  benchmark is runnable without hand-editing flags

## Contributing and license

Contributions welcome, especially **reports of what a scanner missed** — see
[CONTRIBUTING.md](CONTRIBUTING.md). A report saying "scanner X needed custom
parsing for reason Y" is a finding as valuable as a recall number.

MIT — see [LICENSE](LICENSE).
