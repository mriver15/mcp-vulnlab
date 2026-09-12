# Contributing

Two ways to contribute, and the second one is more valuable.

## 1. Add a challenge

The corpus target is **≥ 12 servers across the 6 categories**, plus the controls.
Adding one is mechanical once you know the shape.

```sh
cp -r corpus/servers/exfil-write corpus/servers/my-new-challenge
cd corpus/servers/my-new-challenge
```

Then edit the four files:

**`manifest.json`** — set `slug` to exactly match the directory name, keep
`kind` as `vulnerable`, and make `categories` agree with the labels you write.

**`exploits.json`** — one entry per weakness. Follow the schema; the required
shape is:

```jsonc
{
  "id": "MCPV-013",            // next free id, permanent once used
  "slug": "my-new-challenge",  // must match the directory
  "title": "One line a reader can scan",
  "category": "missing-auth",  // one of the six
  "severity": "high",          // critical | high | medium | low
  "tool": "the_exact_tool_name",
  "description": "Mechanism. Two to four sentences.",
  "impact": "What the attacker gets. Concrete.",
  "exploit": {
    "vector": "How the attacker reaches it",
    "steps": ["Reproducible", "in order"],
    "poc": "The shortest thing that demonstrates it"
  },
  "detection": { "signals": ["lowercase substrings a finding might contain"] },
  "remediation": { "summary": "The fix", "config": "drop-in corrected code", "guardrail": "runtime control" },
  "references": ["https://..."],
  "cwe": ["CWE-862"],
  "tags": ["lowercase-tags"]
}
```

**`README.md`** — copy the structure: the `⚠ Intentionally vulnerable` banner,
what it does, *why* it is vulnerable, how to reproduce, how to fix. The word
"intentionally" must appear; a test enforces it.

**`server.py`** — write the vulnerable server with `MCPServer` from
`mcp.server.mcpserver`. stdio transport. Mark the vulnerable line with the label
id in a comment so a reader can connect code to ground truth.

### Then check it

```sh
mcp-vulnlab validate                        # schemas and cross-checks
mcp-vulnlab smoke --server my-new-challenge # does it boot and expose what you claimed?
mcp-vulnlab index                           # regenerate corpus/labels/index.json
pytest -q                                   # includes the label-exists check
```

### Rules that are not negotiable

1. **It must actually be exploitable.** If you cannot paste `exploit.steps` into
   an MCP client and observe the weakness, the label is not finished. A sloppy
   challenge undermines the whole benchmark.
2. **Self-contained.** stdio only, no network listeners, no third-party targets.
3. **Synthetic data only.** `example.invalid` emails, `000-00-xxxx` SSNs,
   published test card numbers.
4. **Contained side effects.** Filesystem writes go inside a sandbox directory
   under the system temp dir. Never target a path the user chose.
5. **PoC depth only.** The shortest demonstration a scanner can detect. Not a
   general-purpose attack tool. See [SECURITY.md](SECURITY.md).
6. **One weakness per label.** Two problems means two labels.

## 2. Report what a scanner missed (more valuable)

The corpus is only half the project. The other half is the measurement, and a
measurement needs real scanner runs.

If you have run an MCP scanner — SkillSpector, Snyk agent-scan, Cisco
mcp-scanner, or your own — against this corpus, open an issue with:

- the scanner name and **exact version**
- the command line you used
- the resulting `scorecard.json`

That is the input the published scorecard is built from. Even "it detected
nothing" is a datapoint, and a more interesting one than a high score.

### Adapters

Scanners all emit different JSON — that is the premise of the project, not a
surprise. Rather than write Python per tool, describe the scanner in
`scanners.yaml`:

```yaml
  - name: my-scanner
    command: ["my-scanner", "scan", "{entrypoint}", "--json"]
    output: json
    json_path: "$.results.findings"   # small JSONPath subset: $, $.a, $.a.b
    field_map:
      rule_id: ["id", "rule"]
      severity: ["level", "severity"]
      tool: ["tool_name", "target"]
      message: ["message", "description"]
```

For SARIF, add `sarif: true`. For a tool that only prints text, use
`output: text` with a named-group `regex:` block — that escape hatch exists
precisely because fighting a text-only scanner is not worth anyone's weekend.

If a scanner needs more than this, add the shim in `harness/adapters.py` and a
test in `tests/test_adapters.py`. Then say so in the issue: **"scanner X needed
custom parsing for reason Y" is itself a finding worth publishing.**

## Development

```sh
make setup      # uv venv + editable install with dev extras
make lint       # ruff check, ruff format --check, mypy
make test       # pytest
make selftest   # offline replay scan -> results/selftest
```

Notes for contributors:

- `corpus/servers/**` is excluded from most ruff rules on purpose. Corpus servers
  are intentionally bad code; linting them like library code is noise.
- The scorer's matching policy is deliberately conservative and is documented in
  `harness/score.py`. Read it before proposing a change to recall — an
  attribution rule that is easier to match against makes every scanner look
  better, which defeats the point.
- Keep `corpus/labels/index.json` regenerated. CI diffs it.

## Code of conduct

Be straightforward, be accurate, and do not overstate a scanner's failures. The
project's credibility rests on publishing numbers that are reproducible by
someone who distrusts us. If a recall figure is wrong, that is the highest
priority bug in the repository.
