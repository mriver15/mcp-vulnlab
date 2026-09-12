# The corpus: eleven deliberately vulnerable MCP servers

> **⚠ Everything in `servers/` is intentionally insecure. Do not deploy any of it.**
> See [SECURITY.md](../SECURITY.md) for the scope rules every challenge obeys.

## What a challenge is

One directory per challenge, self-contained — copy it out of the repo and it
still works:

```
corpus/servers/<slug>/
  manifest.json     launch spec + metadata      (schema: labels/manifest.schema.json)
  exploits.json     ground-truth labels         (schema: labels/exploits.schema.json)
  server.py         the MCP server              (fastMCP / MCPServer, stdio)
  README.md         warning, reproduction, fix
```

Labels live next to the server they describe. `corpus/labels/` holds the schemas
and the generated index, not the labels themselves. Reasoning is in
[labels/README.md](labels/README.md).

## Inventory

| Server | Category | Kind | Labels | The weakness |
|---|---|---|---|---|
| `injection-echo` | prompt-injection | vulnerable | 2 | Tool output labelled "trusted" carries injected instructions; a second tool reflects arguments verbatim |
| `exfil-write` | data-exfiltration | vulnerable | 2 | Unconfined path join allows arbitrary writes; a resource explicitly disables the SDK's traversal defence |
| `overbroad-glob` | overbroad-tool-schema | vulnerable | 2 | Schemas advertise whole-filesystem scope via an unrestricted glob root and a free-form path |
| `pii-leak` | pii-disclosure | vulnerable | 2 | Returns unmasked records; a substring search dumps the entire table |
| `no-auth-file` | missing-auth | vulnerable | 2 | Identity is logged but never checked; an irreversible delete has no gate |
| `supply-chain-yolo` | supply-chain | vulnerable | 2 | Remote source loaded with no integrity check; a fully floating dependency manifest |
| `tool-poisoning` | tool-poisoning | vulnerable | 1 | Tool described as read-only, but the implementation writes to the user's shell profile |
| `dangerous-shell-tool` | code-execution | vulnerable | 1 | A general-purpose shell tool with no command allowlist, sandbox, or confirmation gate |
| `control-files` | — | control | 0 | Sandboxed file access done correctly |
| `control-gated-admin` | — | control | 0 | Authorization, projection, masking, and a reversible gated delete |
| `control-echo` | — | control | 0 | Allowlisted input, escaped output, no reflection |

**14 labels across 8 categories, plus 3 controls.**

Controls are not filler. They are the only way to measure a scanner's false
positive rate, and they are built to be *tempting*: `control-files` reads and
writes files like the vulnerable challenges do, and `control-gated-admin`
returns a masked `ssn_masked` field from a tool annotated
`destructiveHint=True`. A scanner that matches on capability names rather than on
control flow will fire on both, and the scorecard will say so.

## Verify the corpus

```sh
mcp-vulnlab validate   # schemas, cross-checks, id uniqueness
mcp-vulnlab smoke      # launch every server over stdio and list what it exposes
mcp-vulnlab corpus     # inventory table
```

`validate` is the gate. It checks the schemas cannot express: `manifest.slug`
matching the directory name, ids unique corpus-wide, `categories` agreeing with
the labels actually present, controls carrying no labels, entrypoints existing.
CI runs it plus `smoke`, so a challenge that does not boot cannot merge.

The strongest quality check is
`tests/test_integration.py::test_every_label_names_a_surface_that_actually_exists`:
every label's `tool` field must name a tool, resource, or resource template the
server really exposes over MCP. A label pointing at a surface that does not exist
is unverifiable ground truth, which is worse than no label.

## Design notes

**Severity is per-server, not per-category.** A `missing-auth` finding on a
read-only health check is not `critical`. `MCPV-009` and `MCPV-010` are both
`missing-auth` in the same server and are graded `high` and `critical`, because
blast radius differs.

**One label, one weakness.** If a tool has two independent problems, that is two
labels. Bundling them makes recall unmeasurable, because a scanner that finds
half the problem scores the same as one that finds all of it.

**Some labels describe disabled controls rather than absent ones.** `MCPV-004`
and `MCPV-011` are the interesting cases: a control exists, and the server turns
it off. A scanner that only looks for *missing* validation will miss them, which
is a finding about the scanner worth publishing.

**Nothing dangerous actually runs.** `supply-chain-yolo` models a fetch-and-exec
pattern with both runtime sinks gated behind environment variables that the
harness and CI never set. Static analysis sees the full pattern; running it stays
inert.

## Adding a challenge

See [CONTRIBUTING.md](../CONTRIBUTING.md). The short version: copy a directory,
edit four files, run `mcp-vulnlab validate`, `mcp-vulnlab index`, and commit.
