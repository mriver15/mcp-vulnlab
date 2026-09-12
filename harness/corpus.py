"""Corpus discovery, schema validation, and index generation.

A challenge is a directory under `corpus/servers/` containing:

    manifest.json   launch spec + metadata   (schema: manifest.schema.json)
    exploits.json   ground-truth labels      (schema: exploits.schema.json)
    server.py       the MCP server itself
    README.md       the warning + reproduction steps

Labels are co-located with the server they describe so that a challenge is
self-contained. `corpus/labels/` holds the schemas and the generated index.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jsonschema
from referencing import Registry, Resource

from harness.model import CATEGORIES, MCP_CATEGORIES, Label, ServerSpec

#: schema $id -> filename inside corpus/labels/
SCHEMA_FILES: dict[str, str] = {
    "urn:mcp-vulnlab:label": "label.schema.json",
    "urn:mcp-vulnlab:exploits": "exploits.schema.json",
    "urn:mcp-vulnlab:manifest": "manifest.schema.json",
}

ENV_CORPUS_ROOT = "MCPVULNLAB_CORPUS"


# --------------------------------------------------------------------------- #
# Locations
# --------------------------------------------------------------------------- #


def repo_root(start: Path | None = None) -> Path:
    """Walk up from `start` until a directory containing corpus/servers is found."""
    override = os.environ.get(ENV_CORPUS_ROOT)
    if override:
        root = Path(override).resolve()
        return root if (root / "servers").is_dir() else root.parent

    here = (start or Path(__file__)).resolve()
    for candidate in (here, *here.parents):
        if (candidate / "corpus" / "servers").is_dir():
            return candidate
    raise FileNotFoundError(
        "could not locate the corpus: no 'corpus/servers' directory found in "
        f"{here} or any parent. Set {ENV_CORPUS_ROOT} to override."
    )


def servers_dir(root: Path | None = None) -> Path:
    return (root or repo_root()) / "corpus" / "servers"


def skills_dir(root: Path | None = None) -> Path:
    return (root or repo_root()) / "corpus" / "skills"


def labels_dir(root: Path | None = None) -> Path:
    return (root or repo_root()) / "corpus" / "labels"


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #


@dataclass
class ValidationIssue:
    """One problem found in the corpus. Collecting beats raising: CI prints them all."""

    server: str
    message: str

    def __str__(self) -> str:
        return f"{self.server}: {self.message}"


@dataclass
class ValidationReport:
    servers: int = 0
    labels: int = 0
    controls: int = 0
    issues: list[ValidationIssue] = field(default_factory=list)
    #: What to call one challenge in the human-readable summary ("servers"/"skills").
    noun: str = "servers"

    @property
    def ok(self) -> bool:
        return not self.issues

    def render(self) -> str:
        lines = [
            f"corpus: {self.servers} {self.noun} "
            f"({self.servers - self.controls} vulnerable, {self.controls} control), "
            f"{self.labels} labels"
        ]
        if self.ok:
            lines.append("validation: OK")
        else:
            lines.append(f"validation: {len(self.issues)} issue(s)")
            lines.extend(f"  - {issue}" for issue in self.issues)
        return "\n".join(lines)


def load_schemas(labels_directory: Path | None = None) -> dict[str, dict[str, Any]]:
    """Load the three schema documents, keyed by their $id."""
    directory = labels_directory or labels_dir()
    schemas: dict[str, dict[str, Any]] = {}
    for urn, filename in SCHEMA_FILES.items():
        path = directory / filename
        schemas[urn] = json.loads(path.read_text(encoding="utf-8"))
    return schemas


def _build_registry(schemas: dict[str, dict[str, Any]]) -> Registry:
    """URN-keyed registry so `$ref: urn:mcp-vulnlab:label` resolves anywhere."""
    registry: Registry = Registry()
    for urn, schema in schemas.items():
        registry = registry.with_resource(urn, Resource.from_contents(schema))
    return registry


def validator(urn: str, schemas: dict[str, dict[str, Any]]) -> jsonschema.Validator:
    return jsonschema.Draft202012Validator(schemas[urn], registry=_build_registry(schemas))


def _first_error(instance: Any, schema_validator: jsonschema.Validator) -> str | None:
    for error in sorted(schema_validator.iter_errors(instance), key=lambda e: list(e.path)):
        location = "/".join(str(part) for part in error.absolute_path) or "(root)"
        return f"{location}: {error.message}"
    return None


def _inspect_directory(
    directory: Path,
    schemas: dict[str, dict[str, Any]],
) -> tuple[ServerSpec | None, list[str]]:
    """Validate one challenge directory. Returns the spec (if loadable) and issues."""
    slug = directory.name
    problems: list[str] = []

    manifest_path = directory / "manifest.json"
    exploits_path = directory / "exploits.json"
    readme_path = directory / "README.md"

    for required in (manifest_path, exploits_path):
        if not required.exists():
            problems.append(f"missing {required.name}")
    if not readme_path.exists():
        problems.append("missing README.md (every challenge documents itself)")
    if problems:
        return None, problems

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return None, [f"manifest.json is not valid JSON: {exc}"]

    try:
        exploits_raw = json.loads(exploits_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return None, [f"exploits.json is not valid JSON: {exc}"]

    manifest_error = _first_error(manifest, validator("urn:mcp-vulnlab:manifest", schemas))
    if manifest_error:
        problems.append(f"manifest.json does not match its schema: {manifest_error}")

    exploits_error = _first_error(exploits_raw, validator("urn:mcp-vulnlab:exploits", schemas))
    if exploits_error:
        problems.append(f"exploits.json does not match its schema: {exploits_error}")

    if problems:
        return None, problems

    # -- cross-checks the schemas cannot express ---------------------------- #

    if manifest["slug"] != slug:
        problems.append(f"manifest.slug {manifest['slug']!r} != directory name {slug!r}")
    if exploits_raw["slug"] != slug:
        problems.append(f"exploits.slug {exploits_raw['slug']!r} != directory name {slug!r}")

    labels = [Label.from_json(slug, raw) for raw in exploits_raw["exploits"]]

    for label in labels:
        if not re.fullmatch(r"(MCPV|SKLV)-[0-9]{3}", label.id):  # cheap shape guard
            problems.append(f"{label.id}: id must look like MCPV-NNN or SKLV-NNN")
        if label.category not in CATEGORIES:
            problems.append(f"{label.id}: unknown category {label.category!r}")

    kind = manifest["kind"]
    if kind == "control" and labels:
        problems.append(f"kind is 'control' but {len(labels)} exploit(s) are declared")
    if kind == "vulnerable" and not labels:
        problems.append("kind is 'vulnerable' but no exploits are declared")

    declared = sorted(set(manifest.get("categories", ())))
    actual = sorted({label.category for label in labels})
    if declared and declared != actual:
        problems.append(f"manifest.categories {declared} disagrees with exploits.json {actual}")

    entrypoint = manifest.get("entrypoint", "server.py")
    if not (directory / entrypoint).is_file():
        problems.append(f"manifest.entrypoint {entrypoint!r} does not exist")

    spec = ServerSpec(
        slug=slug,
        directory=directory,
        title=manifest["title"],
        kind=kind,
        summary=manifest["summary"],
        entrypoint=entrypoint,
        args=list(manifest.get("args", ())),
        env=dict(manifest.get("env", {})),
        categories=declared,
        labels=labels,
    )
    return spec, problems


def validate_corpus(root: Path | None = None, *, directory: Path | None = None) -> ValidationReport:
    """Validate every challenge in a challenge directory. Never raises for corpus problems."""
    directory = directory or servers_dir(root)
    report = ValidationReport(noun=directory.name)

    if not directory.is_dir():
        report.issues.append(ValidationIssue("(corpus)", f"no challenge directory at {directory}"))
        return report

    try:
        schemas = load_schemas(labels_dir(root))
    except (OSError, json.JSONDecodeError) as exc:
        report.issues.append(ValidationIssue("(schemas)", f"could not load schemas: {exc}"))
        return report

    seen_ids: dict[str, str] = {}
    for candidate in sorted(p for p in directory.iterdir() if p.is_dir()):
        if candidate.name.startswith("."):
            continue
        report.servers += 1
        spec, problems = _inspect_directory(candidate, schemas)
        report.issues.extend(ValidationIssue(candidate.name, problem) for problem in problems)
        if spec is None:
            continue
        if spec.is_control:
            report.controls += 1
        report.labels += len(spec.labels)
        for label in spec.labels:
            if label.id in seen_ids:
                report.issues.append(
                    ValidationIssue(
                        candidate.name,
                        f"label id {label.id} is already used by {seen_ids[label.id]!r}",
                    )
                )
            else:
                seen_ids[label.id] = candidate.name

    return report


def discover_servers(
    root: Path | None = None, *, strict: bool = False, directory: Path | None = None
) -> list[ServerSpec]:
    """Load every challenge in a challenge directory.

    With `strict=True`, raise on the first validation failure. `directory`
    defaults to the MCP-server corpus; pass `skills_dir(root)` to load skills.
    """
    directory = directory or servers_dir(root)
    schemas = load_schemas(labels_dir(root))

    specs: list[ServerSpec] = []
    for candidate in sorted(p for p in directory.iterdir() if p.is_dir()):
        if candidate.name.startswith("."):
            continue
        spec, problems = _inspect_directory(candidate, schemas)
        if problems and strict:
            raise ValueError(f"{candidate.name}: {problems[0]}")
        if spec is not None:
            specs.append(spec)
    return specs


def validate_skills(root: Path | None = None) -> ValidationReport:
    """Validate the agent-skill corpus."""
    return validate_corpus(root, directory=skills_dir(root))


def discover_skills(root: Path | None = None, *, strict: bool = False) -> list[ServerSpec]:
    """Load every agent-skill challenge."""
    return discover_servers(root, strict=strict, directory=skills_dir(root))


# --------------------------------------------------------------------------- #
# Index
# --------------------------------------------------------------------------- #


def build_index(root: Path | None = None) -> dict[str, Any]:
    """Flatten the corpus into `corpus/labels/index.json`."""
    specs = discover_servers(root, strict=True)
    labels = [label for spec in specs for label in spec.labels]

    categories: dict[str, dict[str, Any]] = {
        category: {"labels": 0, "servers": []} for category in MCP_CATEGORIES
    }
    for spec in specs:
        for category in {label.category for label in spec.labels}:
            categories[category]["servers"].append(spec.slug)
    for label in labels:
        categories[label.category]["labels"] += 1

    return {
        "generated_by": "mcp-vulnlab index",
        "corpus": {
            "servers": len(specs),
            "vulnerable": sum(1 for spec in specs if not spec.is_control),
            "controls": sum(1 for spec in specs if spec.is_control),
            "labels": len(labels),
            "categories": len({label.category for label in labels}),
        },
        "categories": categories,
        "labels": [
            {
                "id": label.id,
                "server": label.server,
                "title": label.title,
                "category": label.category,
                "severity": label.severity,
                "tool": label.tool,
            }
            for label in sorted(labels, key=lambda item: item.id)
        ],
        "servers": [spec.to_json() for spec in specs],
    }


def write_index(root: Path | None = None, destination: Path | None = None) -> Path:
    target = destination or (labels_dir(root) / "index.json")
    target.write_text(json.dumps(build_index(root), indent=2) + "\n", encoding="utf-8")
    return target
