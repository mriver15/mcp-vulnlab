"""Scanner output adapters.

The most predictable finding of this project is that every MCP scanner emits a
different JSON shape — and accepts a different kind of input. Rather than write
bespoke code per tool, each scanner is described declaratively in
`scanners.yaml` and parsed here by one config-driven adapter.

Capabilities, all driven by profile fields rather than per-scanner Python:

``json``
    Locate an array of finding objects with a small JSONPath subset, then map a
    normalized field set onto each object with a list of candidate key names.
    Set ``sarif: true`` for SARIF documents.

``flatten_from``
    Explode a nested `{name: result}` mapping into one merged object per entry.
    Used for scanners (e.g. Cisco) that nest findings per tool per analyzer.

``config_template``
    Some scanners only accept a client config file, never a server command.
    When set, the runner renders the template per challenge, writes it out, and
    substitutes the path for ``{config}`` in the argv.

``text``
    One finding per matching line, using a named-group regex. The escape hatch
    for tools that refuse to emit structured output.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from harness.model import Finding

#: Normalized field -> fallbacks used when a scanner omits it.
NORMALIZED_FIELDS = ("rule_id", "severity", "category", "tool", "message")

_SEVERITY_ALIASES = {
    "error": "high",
    "err": "high",
    "warning": "medium",
    "warn": "medium",
    "note": "low",
    "info": "low",
    "informational": "low",
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}

DEFAULT_FIELD_MAP: dict[str, list[str]] = {
    "rule_id": ["rule_id", "ruleId", "id", "check", "check_id", "name"],
    "severity": ["severity", "level", "risk", "priority"],
    "category": ["category", "type", "class", "technique", "owasp", "tags"],
    "tool": ["tool", "tool_name", "toolName", "sink", "target"],
    "message": ["message", "description", "title", "detail", "summary", "text"],
}

#: Matches `{word}` only — so `{'findings': []}` and `{2,8}` are left alone.
_BARE_PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]*)\}")

#: Placeholders that may appear in a command but are resolved later (or never).
_DEFERRED_PLACEHOLDERS = frozenset({"config"})

#: Every placeholder the substitution machinery knows about.
SUBSTITUTION_KEYS = ("python", "server_dir", "entrypoint", "slug", "config", "out_file")


class AdapterError(RuntimeError):
    """The scanner produced output this adapter cannot interpret."""


# --------------------------------------------------------------------------- #
# Placeholder substitution
# --------------------------------------------------------------------------- #


def substitution_values(
    *,
    server_dir: Path,
    entrypoint: Path,
    slug: str,
    python: str,
    config: Path | None = None,
    out_file: Path | None = None,
) -> dict[str, str]:
    """The canonical placeholder values, shared by argv and config rendering."""
    return {
        "python": python,
        "server_dir": str(server_dir),
        "entrypoint": str(entrypoint),
        "slug": slug,
        "config": str(config) if config is not None else "{config}",
        "out_file": str(out_file) if out_file is not None else "{out_file}",
    }


def _substitute_tree(node: Any, values: dict[str, str]) -> Any:
    """Recursively substitute placeholders inside a nested JSON-shaped template."""
    if isinstance(node, str):
        for name in SUBSTITUTION_KEYS:
            node = node.replace("{" + name + "}", values.get(name, ""))
        return node
    if isinstance(node, list):
        return [_substitute_tree(item, values) for item in node]
    if isinstance(node, dict):
        # Keys are substituted too: the Snyk template keys a server entry by "{slug}".
        return {
            _substitute_tree(key, values): _substitute_tree(value, values)
            for key, value in node.items()
        }
    return node


# --------------------------------------------------------------------------- #
# Profiles
# --------------------------------------------------------------------------- #


@dataclass
class ScannerProfile:
    """A declarative description of one scanner."""

    name: str
    command: list[str]
    description: str = ""
    output: str = "json"
    json_path: str = "$"
    sarif: bool = False
    field_map: dict[str, list[str]] = field(default_factory=lambda: dict(DEFAULT_FIELD_MAP))
    regex: dict[str, Any] | None = None

    #: Explode a nested `{name: result}` mapping into one object per entry, merged
    #: with its parent. Cisco's scanner nests findings per tool per analyzer.
    flatten_from: str | None = None

    #: With `flatten_from`, drop entries whose counter at this key is zero/absent,
    #: so analyzers reporting "no threats detected" do not become findings.
    skip_if_zero: str | None = None

    #: Some scanners only accept a client config file, never a server command.
    #: When set, the runner renders this template per challenge, writes it out, and
    #: substitutes the path for `{config}` in the argv.
    config_template: dict[str, Any] | None = None

    #: When true, the scanner writes its report to a file (the command is expected
    #: to include `{out_file}`) rather than to stdout. The runner reads that file
    #: back after the subprocess returns. Handles CLIs like `mcp-armor`, whose
    #: stdout is an ASCII banner and whose JSON lands in a separate file.
    output_to_file: bool = False

    #: Keep only items whose field at `field` equals `equals`. Some scanners emit
    #: a record per *check*, including passing ones (e.g. `passed: true`); this
    #: drops the passing records so they are not scored as findings.
    require: dict[str, Any] | None = None

    @property
    def needs_config(self) -> bool:
        return self.config_template is not None

    def render_command(
        self,
        *,
        server_dir: Path,
        entrypoint: Path,
        slug: str,
        python: str,
        config: Path | None = None,
        out_file: Path | None = None,
    ) -> list[str]:
        """Substitute placeholders in the configured argv.

        Substitution is literal rather than ``str.format``, because scanner
        arguments legitimately contain braces — JSON payloads, regexes, inline
        scripts. Unknown bare placeholders like ``{slgu}`` are still reported,
        since those are typos worth catching.
        """
        values = substitution_values(
            server_dir=server_dir,
            entrypoint=entrypoint,
            slug=slug,
            python=python,
            config=config,
            out_file=out_file,
        )
        known = set(values) | _DEFERRED_PLACEHOLDERS
        rendered: list[str] = []
        for part in self.command:
            for name in SUBSTITUTION_KEYS:
                if name in values:
                    part = part.replace("{" + name + "}", values[name])
            unknown = sorted(set(_BARE_PLACEHOLDER.findall(part)) - known)
            if unknown:
                raise AdapterError(
                    f"scanner {self.name!r}: unknown placeholder(s) {unknown} in command "
                    f"entry {part!r}. Valid placeholders: {sorted(known)}"
                )
            rendered.append(part)
        return rendered

    def render_config(
        self,
        *,
        server_dir: Path,
        entrypoint: Path,
        slug: str,
        python: str,
    ) -> dict[str, Any]:
        """Render `config_template` into a concrete client config document."""
        if self.config_template is None:
            raise AdapterError(f"scanner {self.name!r} has no config_template to render")
        values = substitution_values(
            server_dir=server_dir, entrypoint=entrypoint, slug=slug, python=python
        )
        return _substitute_tree(self.config_template, values)

    @classmethod
    def from_yaml(cls, raw: dict[str, Any]) -> ScannerProfile:
        if "name" not in raw or "command" not in raw:
            raise AdapterError(f"scanner profile is missing name or command: {raw!r}")
        field_map = {**DEFAULT_FIELD_MAP}
        field_map.update({key: list(value) for key, value in (raw.get("field_map") or {}).items()})
        return cls(
            name=raw["name"],
            command=list(raw["command"]),
            description=raw.get("description", ""),
            output=raw.get("output", "json"),
            json_path=raw.get("json_path", "$"),
            sarif=bool(raw.get("sarif", False)),
            field_map=field_map,
            require=raw.get("require"),
            regex=raw.get("regex"),
            flatten_from=raw.get("flatten_from"),
            skip_if_zero=raw.get("skip_if_zero"),
            config_template=raw.get("config_template"),
            output_to_file=bool(raw.get("output_to_file", False)),
        )


def load_profiles(path: Path) -> list[ScannerProfile]:
    """Load every scanner profile from a YAML file."""
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = document.get("scanners") or []
    if not isinstance(entries, list):
        raise AdapterError(f"{path}: expected a 'scanners:' list")
    return [ScannerProfile.from_yaml(entry) for entry in entries]


def select_profile(profiles: list[ScannerProfile], name: str) -> ScannerProfile:
    for profile in profiles:
        if profile.name == name:
            return profile
    known = ", ".join(sorted(p.name for p in profiles))
    raise AdapterError(f"unknown scanner {name!r}. Known scanners: {known}")


# --------------------------------------------------------------------------- #
# Field lookup helpers
# --------------------------------------------------------------------------- #


def _get_ci(obj: Any, key: str) -> Any:
    """Case-insensitive dict lookup."""
    if not isinstance(obj, dict):
        return None
    if key in obj:
        return obj[key]
    lowered = key.lower()
    for candidate_key, value in obj.items():
        if isinstance(candidate_key, str) and candidate_key.lower() == lowered:
            return value
    return None


def _pluck(obj: Any, dotted: str) -> Any:
    """Case-insensitive lookup of a dotted path. Lists are searched element-wise."""
    current = obj
    for part in dotted.split("."):
        if isinstance(current, list):
            for item in current:
                found = _pluck(item, part)
                if found is not None:
                    return found
            return None
        current = _get_ci(current, part)
        if current is None:
            return None
    return current


def _as_text(value: Any) -> str | None:
    """Flatten whatever a scanner put in a field into matchable text."""
    if value is None:
        return None
    if isinstance(value, str):
        return value.strip() or None
    if isinstance(value, (list, tuple)):
        joined = " ".join(filter(None, (_as_text(item) for item in value)))
        return joined or None
    if isinstance(value, dict):
        joined = " ".join(f"{key} {_as_text(item) or ''}".strip() for key, item in value.items())
        return joined.strip() or None
    return str(value)


def _normalize_severity(value: str | None) -> str | None:
    if not value:
        return None
    return _SEVERITY_ALIASES.get(value.strip().lower(), value.strip().lower())


def json_path(document: Any, path: str) -> Any:
    """A deliberately small JSONPath subset: `$`, `$.a`, `$.a.b`.

    No filters, no wildcards, no recursive descent. Scanners that need more than
    this in an adapter are a finding about scanners.
    """
    if not path or path == "$":
        return document
    current = document
    for part in (segment for segment in path.lstrip("$").split(".") if segment):
        if isinstance(current, list):
            collected: list[Any] = []
            for item in current:
                found = json_path(item, part)
                if isinstance(found, list):
                    collected.extend(found)
                elif found is not None:
                    collected.append(found)
            current = collected
        elif isinstance(current, dict):
            current = current.get(part)
        else:
            return None
        if current is None:
            return None
    return current


def _flatten_sarif(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Pull `runs[].results[]` out of a SARIF document, merging rule metadata."""
    results: list[dict[str, Any]] = []
    for run in document.get("runs") or []:
        if not isinstance(run, dict):
            continue
        driver = (run.get("tool") or {}).get("driver") or {}
        rules = {
            rule.get("id"): rule
            for rule in (driver.get("rules") or [])
            if isinstance(rule, dict) and rule.get("id")
        }
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            merged = dict(result)
            rule = rules.get(result.get("ruleId")) or {}
            merged["properties"] = {
                **(rule.get("properties") or {}),
                **(result.get("properties") or {}),
                "rule_name": rule.get("name") or rule.get("shortDescription"),
            }
            merged.setdefault("scanner_tool", driver.get("name"))
            results.append(merged)
    return results


def _flatten_nested(profile: ScannerProfile, items: list[Any]) -> list[Any]:
    """Explode `item[flatten_from]` into one merged object per nested entry.

    Each result keeps its parent's fields (so `tool_name` on the parent is still
    visible) and gains `analyzer` plus `rule_id` set to the nested key.
    """
    assert profile.flatten_from is not None
    flattened: list[Any] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        nested = item.get(profile.flatten_from)
        if not isinstance(nested, dict):
            continue
        parent = {key: value for key, value in item.items() if key != profile.flatten_from}
        for name, leaf in nested.items():
            if not isinstance(leaf, dict):
                leaf = {"message": str(leaf)}
            if profile.skip_if_zero and not leaf.get(profile.skip_if_zero):
                continue
            merged: dict[str, Any] = {**parent, **leaf, "analyzer": name, "rule_id": name}
            flattened.append(merged)
    return flattened


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


def _finding_from_item(profile: ScannerProfile, slug: str, item: Any) -> Finding:
    if not isinstance(item, dict):
        item = {"message": str(item)}

    values: dict[str, str | None] = {}
    for name in NORMALIZED_FIELDS:
        for candidate in profile.field_map.get(name, ()):
            text = _as_text(_pluck(item, candidate))
            if text:
                values[name] = text
                break
        else:
            values.setdefault(name, None)

    return Finding(
        scanner=profile.name,
        server=slug,
        message=values.get("message") or json.dumps(item, default=str)[:400],
        rule_id=values.get("rule_id"),
        severity=_normalize_severity(values.get("severity")),
        category=values.get("category"),
        tool=values.get("tool"),
        raw=item,
    )


def parse_json(profile: ScannerProfile, slug: str, stdout: str) -> list[Finding]:
    text = stdout.strip()
    if not text:
        return []
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AdapterError(
            f"scanner {profile.name!r} did not emit valid JSON ({exc}). "
            "If this tool only prints text, give its profile `output: text` with a "
            "`regex:` block instead."
        ) from exc

    if profile.sarif and isinstance(document, dict) and "runs" in document:
        items: Any = _flatten_sarif(document)
    else:
        items = json_path(document, profile.json_path)
        if items is None:
            raise AdapterError(
                f"scanner {profile.name!r}: json_path {profile.json_path!r} matched nothing. "
                "Top-level keys were: "
                f"{sorted(document) if isinstance(document, dict) else type(document).__name__}"
            )

    if isinstance(items, dict):
        items = [items]
    if not isinstance(items, list):
        raise AdapterError(
            f"scanner {profile.name!r}: json_path {profile.json_path!r} resolved to "
            f"{type(items).__name__}, expected a list or object"
        )

    if profile.flatten_from:
        items = _flatten_nested(profile, items)

    if profile.require:
        field_name = profile.require.get("field")
        expected = profile.require.get("equals")
        if field_name is not None:
            items = [item for item in items if _pluck(item, field_name) == expected]

    return [_finding_from_item(profile, slug, item) for item in items]


def parse_text(profile: ScannerProfile, slug: str, stdout: str) -> list[Finding]:
    spec = profile.regex or {}
    pattern = spec.get("pattern")
    if not pattern:
        raise AdapterError(
            f"scanner {profile.name!r}: output is 'text' but no regex.pattern is set"
        )

    flags = 0
    for name in spec.get("flags", ()):
        flag = getattr(re, str(name).upper(), None)
        if not isinstance(flag, int):
            raise AdapterError(f"scanner {profile.name!r}: unknown regex flag {name!r}")
        flags |= flag

    compiled = re.compile(pattern, flags)
    findings: list[Finding] = []
    for line in stdout.splitlines():
        match = compiled.search(line)
        if match is None:
            continue
        groups = {key: value for key, value in (match.groupdict() or {}).items() if value}
        findings.append(
            Finding(
                scanner=profile.name,
                server=slug,
                message=groups.get("message") or line.strip(),
                rule_id=groups.get("rule_id"),
                severity=_normalize_severity(groups.get("severity")),
                category=groups.get("category"),
                tool=groups.get("tool"),
                raw=groups,
            )
        )
    return findings


def parse_output(
    profile: ScannerProfile, slug: str, stdout: str, stderr: str = ""
) -> list[Finding]:
    """Turn one scanner invocation's output into normalized findings."""
    del stderr  # kept in the signature as an obvious extension point
    if profile.output == "text":
        return parse_text(profile, slug, stdout)
    if profile.output == "json":
        return parse_json(profile, slug, stdout)
    raise AdapterError(f"scanner {profile.name!r}: unknown output mode {profile.output!r}")
