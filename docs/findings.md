# Findings log

Running notes from building the corpus and harness. Each entry is tagged by how
much it is worth:

- **[verified]** — reproduced here, with the command or test that shows it
- **[observed]** — seen while working, not yet isolated
- **[hypothesis]** — a design assumption that still needs a real scanner run

This file is the seed of the project postmortem. When real scanner runs happen,
their results belong here too — including, especially, the ones that contradict
an assumption below.

---

## F1 — The MCP Python SDK defends path traversal, but not where you'd expect **[verified]**

`mcp` 2.x validates resource URI template parameters by default:

```python
ResourceSecurity(reject_path_traversal=True, reject_absolute_paths=True, reject_null_bytes=True)
```

That check runs on `@server.resource("scheme://{param}")` parameters. It does
**not** run on `@server.tool()` arguments. A tool that does
`open(user_supplied_path)` gets no protection from the SDK at all.

Verify:

```sh
.venv/bin/python -c "from mcp.server.mcpserver import ResourceSecurity; print(ResourceSecurity())"
```

Captured in the corpus as `MCPV-004` (resource, opted out) versus `MCPV-003`
(tool argument, never protected), in `corpus/servers/exfil-write/`.

**Why it matters:** a scanner author reading "the SDK handles traversal" would
conclude tool arguments are covered. They are not, and the two cases need
different detections.

## F2 — Disabling the SDK's defence is a one-line opt-out **[verified]**

```python
@server.resource("report://{path}", security=ResourceSecurity(exempt_params={"path"}))
```

`exempt_params` is a legitimate escape hatch for parameters that genuinely
contain separators. It is also a single keyword argument that turns off
path-traversal protection for the one parameter that most needs it, and it looks
like configuration rather than a security decision in review.

Verify: `corpus/servers/exfil-write/server.py`, label `MCPV-004`.

**Why it matters:** a scanner that only looks for *missing* validation will not
flag a *disabled* control. This is the class of bug most likely to be missed by
every tool in the corpus, and it is the finding I would most like real scanner
numbers on.

## F3 — Result models are snake_case while the wire format is camelCase **[verified]**

MCP's wire format is camelCase (`serverInfo`, `uriTemplate`), but the Python
SDK's result models are snake_case (`server_info`, `uri_template`). Getting this
wrong raises `AttributeError` inside a client call, which is easy to swallow with
a broad `except` and silently degrade into an empty result.

This cost me two debugging cycles while writing the smoke probe: `templates` came
back `[]` and looked like a server-side problem rather than a client-side typo.

**Why it matters, beyond my own bug:** anyone building scanner tooling against
this SDK will hit it. It is friction in exactly the place the ecosystem needs
more tooling.

## F4 — Scanner output formats are inconsistent **[hypothesis]**

The premise of the whole adapter design. Stated in the original plan, not yet
proven by running the three named scanners.

The prediction, and what would falsify it: I expect SARIF from at least one tool,
bespoke nested JSON from another, and human-readable text from a third. If all
three turn out to emit compatible structured output, `scanners.yaml` collapses to
one profile and this entry is wrong — which would itself be worth writing up.

## F5 — Speculative profiles were wrong until validated against real CLIs **[resolved]**

The original `skillspector`, `snyk-agent-scan`, and `cisco-mcp-scanner` profiles
were written from documentation and were all wrong in at least one way: the
SkillSpector flags (`--target`/`--output-format`) do not exist; Cisco needs the
`stdio` subcommand plus `--stdio-command`/`--stdio-arg` and nests findings per
analyzer; Snyk accepts only a config file, not a server command.

All three are now verified against real installs and corrected in
`scanners.yaml`. This entry stays as a lesson, not a prediction: a benchmark
whose adapter layer is written from docs rather than from a run will silently
mis-score every scanner. The harness design already contained the right
failure mode (a missing binary records `not run`, never 0%), which is what kept
the mistake from corrupting the numbers before it was caught.

## F6 — "Risky capability" and "vulnerability" are different things **[hypothesis]**

The control servers exist to test this. `control-gated-admin` exposes a
`destructiveHint=True` tool and returns an `ssn_masked` field — both are shapes a
naive detector would flag. `control-files` reads and writes files.

If scanners fire on these, their false-positive rate will be dominated by
capability matching rather than control-flow analysis, and that will show up
clearly in the per-server table. Worth measuring deliberately rather than hoping.

## F7 — Recall is dominated by the matching policy, not the scanner **[observed]**

Changing the attribution rule moves the headline number more than any scanner
behaviour will. Attributing one finding to multiple labels, or lowering the
signal-length floor, would raise measured recall substantially without any
scanner improving.

This is why `harness/score.py` documents its policy, records it in every
scorecard, and why `CONTRIBUTING.md` tells contributors to read it before
proposing a change. A benchmark whose scoring can be tuned upward until the
numbers look good has no value.

## F8 — snyk-agent-scan 0.6.3 cannot be driven headlessly **[verified]**

`uv tool install snyk-agent-scan` gives a working binary, but it fails every
automated run: it emits **no stdout**, writes only debug logs to stderr, and
exi~~Does any scanner flag a *disabled* control (`MCPV-004`, `MCPV-011`) as opposed
   to an absent one?~~ **Answered: no.** Both scanners that ran missed `MCPV-004`.
2. Do scanners distinguish `MCPV-009` (unauthenticated read, high) from
   `MCPV-010` (ungated destructive delete, critical), or do they emit one generic
   "missing auth" finding per server? Cisco detected both; SkillSpector detected
   one — the granularity question is still open.
3. Does anyone detect `MCPV-012` (floating dependency manifest), which is not
   attributable to a tool at all? SkillSpector did; Cisco did not.
4. How much does the prompt-injection category — the one with the least
   deterministic detection story — drag down every scanner's average? Partially
   answered for static-only runs; still open for full-capability runs.
5. Can `snyk-agent-scan` be made to emit machine-readable output at all
   (a Snyk account, a newer version, or a different invocation)ep is
   cloud-side and fails silently without it.

The harness records this as `not run` — which is the honest outcome and the one
the scoring design guarantees. A scanner that cannot be automated is a finding
about the ecosystem, not a licence to print a zero.

## F9 — SkillSpector is an agent-skill scanner; run static-only, it misses the injection labels and flags the corpus's own ground truth **[verified]**

Two independent confounds, both confirmed by inspecting the raw output:

1. `--no-llm` skips SkillSpector's three semantic analyzers, and those are the
   ones that detect description/behaviour mismatch — precisely `MCPV-001` (a tool
   description telling the model to trust injected instructions). The static-only
   0/2 prompt-injection result is therefore a capability ceiling of *this run*,
   not proof the tool cannot detect it. Full-capability runs need an API key.
2. SkillSpector scans the whole challenge directory, including `README.md` and
   `exploits.json`. Those files are the corpus's ground truth and are full of the
   exact security keywords the scanner matches — so it reports findings about
   the *documentation of* a vulnerability (`PE3 Privilege Escalation` on
   `README.md`, for example). 34 unmatched findings is the symptom; the cause is
   that directory-scoped scanning sees the labels as attack surface.

Both are methodology results worth publishing: they bound what a
directory-scoped, static-only skill scanner can measure against this corpus.

## F10 — Cisco's "missing defence" taxonomy produces a high measured FP rate on benign servers **[verified]**

`cisco-mcp-scanner` achieves 83.3% recall — the best of the three — but reports
findings on every server including all three controls. Its `readiness` and
`prompt_defense` analyzers emit "missing defence against X" entries for
essentially every tool, which by the harness's strict definition (a finding that
matches no label is a false positive) yields a 75% FP rate.

That is a definitional mismatch, not a scanner bug: Cisco's notion of a finding
("a hardening step was not taken") is broader than the corpus's notion of a
label ("an exploitable weakness exists"). The fair comparison is the per-category
recall table in `docs/scorecard.md`; the FP rate still deserves reporting because
it measures exactly the triage cost a security team pays for the extra coverage.

## F11 — The disabled control is invisible to every scanner that ran **[verified]**

`MCPV-004` — a path-traversal defence *explicitly disabled* via
`ResourceSecurity(exempt_params={"path"})` — was missed by both scanners that
ran. It is the single strongest result from the first measurement, and it
confirms F2: tools tuned to detect *missing* validation do not detect *disabled*
validation. See `docs/scorecard.md`.

## F12 — mcp-armor catches prompt injection with a local model, at the best precision **[verified]**

`mcp-armor` (v1.0.2) achieves 50% recall at a 57.1% FP rate — the lowest of any
scanner that actually detects things — and detects both prompt-injection labels,
including `MCPV-001` (the tool description that *tells* the model to trust
injected instructions). That is notable for two reasons: it runs a **local**
prompt-injection detection model (downloaded once from Hugging Face, ~290MB)
rather than calling a hosted API, so the result is reproducible offline; and it
identifies the *specific tool* (`operator_note`) carrying the injected
instructions, not just the category.

Its false positives are dominated by one rule, `Excessive Tool Permissions`,
which treats the server's interpreter path as a risky host permission and fires
on every server. That is a permission-model heuristic colliding with stdio
launching, and it is exactly the kind of mismatch a labeled corpus exists to
surface.

## F13 — agent-audit is a generic agent-code analyzer with low MCP-specific recall **[verified]**

`agent-audit` (v0.19.2) recalls 1/12 labels (8.3%) at a 90% FP rate. Its 53 rules
target generic agent-code smells (`AGENT-026` fires on any `@tool`-decorated
function whose string parameters lack validation, regardless of what the
function does). It is a legitimate tool, but it measures a different property
than this corpus labels, so its numbers should not be read as "agent-audit is
bad at MCP security" — they read "static agent-code heuristics do not substitute
for MCP-specific detection."

## F14 — mcp-shield's keyless output is a checklist, not a findings list **[verified]**

`mcp-shield` (v1.0.4) reports 0/12 with zero findings, and the raw output shows
why: without `--claude-api-key` it emits a per-tool "Verified" checklist with no
severity or finding vocabulary at all. Its 0% is a statement about its default
output format, not a verdict on the corpus. A findings-based scorecard cannot
measure a tool that does not emit findings; this is itself the kind of result the
benchmark exists to publish.

## F15 — Most of the "long tail" is not installable CLIs **[verified]**

Of the first ecosystem write-up, only `mcp-armor` (PyPI), `agent-audit`
(PyPI), and `mcp-shield` (npm) shipped a runnable CLI; `mcpSafetyScanner`,
`nova-proximity`, Tencent's scanner, and the traffic gateways (`pipelock`,
`ThinkWatch`) did not resolve to an installable scanner package. Several are
SaaS/gateway products by design, and a benchmark that scores CLIs against a
stdio corpus cannot cover a traffic-scanning proxy the same way. That is a scope
boundary worth stating, not hiding.

## F16 — A spec-compliance scanner sees nothing in a spec-compliant-but-dangerous corpus **[verified]**

`sidhpurwala-huzaifa/mcp-security-scanner` (0.1.5) is a live MCP *penetration
test* tool that runs protocol-conformance checks (auth, transport, tools,
prompts, resources) mapped to a schema. Across all 12 labels it recalled **0**,
and its only finding on every server was the same `BASE-01` capability-fingerprint
quirk. That is not a defect: the corpus challenges are built with the real SDK
and are spec-compliant *by construction* — their vulnerabilities are semantic
(injected instructions in a tool description, over-broad schemas, a disabled
control), not protocol violations.

This is the mirror image of F11/F2, and together they bound the field: signature
scanners miss disabled controls; conformance scanners miss semantic weaknesses.
A complete MCP security tool needs both, which is precisely what no single
scanner in this measurement provides.

## F17 — Two unrelated scanners both ship a binary named `mcp-scan` **[verified]**

`sidhpurwala-huzaifa/mcp-security-scanner` installs a console script named
`mcp-scan`, which collides with Invariant Labs' unrelated `mcp-scan` (npm v2.x).
The PyPI name `mcp-scan` is itself a redirect to `snyk-agent-scan`. Three
different projects, two of them sharing a binary name, across two registries —
the kind of confusion a labeled corpus is uniquely placed to call out. Profiles
here use distinct names (`mcp-security-scanner` vs a future `invariant-mcp-scan`)
to keep the scorecard unambiguous.

## F18 — The second write-up's tools are each unscored for a distinct reason **[verified]**

| Tool | Reason it is not scored here |
|---|---|
| `nova-proximity` (Nova-Hunting) | Live scan requires a streamable-HTTP endpoint; our challenges are stdio servers |
| `AI-Infra-Guard` (Tencent) | Docker/client-server red-teaming platform, not a one-shot CLI |
| `agentic-radar` (splx-ai) | Scans agentic-framework *code* (LangGraph/CrewAI/n8n); MCP is a code feature, not a server scan |
| `mcpSafetyScanner` | Requires an OpenAI API key |
| `repo-forensics` | Static repo/skill supply-chain audit, not a live MCP scan |
| `pipelock` | Runtime egress firewall (proxy mediation), a different tier |
| `medusa` (Pantheon) | Adjacent: Claude Code hooks, skills, secrets |

The scope boundary this draws is a finding, not an excuse: the corpus measures
tools that can point at an MCP server and emit findings; hosted gateways,
proxy firewalls, and agent-*code* analyzers need a different testbed.

---

## Open questions

1. Does any scanner flag a *disabled* control (`MCPV-004`, `MCPV-011`) as opposed
   to an absent one?
2. Do scanners distinguish `MCPV-009` (unauthenticated read, high) from
   `MCPV-010` (ungated destructive delete, critical), or do they emit one generic
   "missing auth" finding per server? The second would mean recall figures are an
   artefact of label granularity, not detection skill.
3. Does anyone detect `MCPV-012` (floating dependency manifest), which is not
   attributable to a tool at all?
4. How much does the prompt-injection category — the one with the least
   deterministic detection story — drag down every scanner's average?
