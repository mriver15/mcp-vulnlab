"""Shared fixtures.

Tests run against the real corpus by design. A benchmark whose own test suite
uses fake fixtures proves nothing about the corpus, and the corpus is the
product.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from harness.corpus import discover_servers, repo_root
from harness.model import Finding, Label, ServerSpec


@pytest.fixture(scope="session")
def root() -> Path:
    return repo_root()


@pytest.fixture(scope="session")
def specs() -> list[ServerSpec]:
    return discover_servers(strict=True)


@pytest.fixture(scope="session")
def vulnerable(specs: list[ServerSpec]) -> list[ServerSpec]:
    return [spec for spec in specs if not spec.is_control]


@pytest.fixture(scope="session")
def controls(specs: list[ServerSpec]) -> list[ServerSpec]:
    return [spec for spec in specs if spec.is_control]


def make_spec(
    slug: str = "demo",
    *,
    kind: str = "vulnerable",
    labels: list[Label] | None = None,
) -> ServerSpec:
    """A tiny hand-built challenge, for unit-testing the scorer in isolation.

    `directory` is a label rather than a real location — the scorer never touches
    the filesystem — so this path is deliberately relative and never created.
    """
    directory = Path("corpus/servers") / slug
    return ServerSpec(
        slug=slug,
        directory=directory,
        title=f"Demo {slug}",
        kind=kind,
        summary="synthetic spec for unit tests",
        entrypoint="server.py",
        categories=sorted({label.category for label in (labels or [])}),
        labels=labels or [],
    )


def make_label(
    label_id: str,
    *,
    tool: str = "do_thing",
    signals: list[str] | None = None,
    category: str = "prompt-injection",
    severity: str = "high",
    server: str = "demo",
) -> Label:
    return Label(
        id=label_id,
        server=server,
        title=f"Label {label_id}",
        category=category,
        severity=severity,
        tool=tool,
        description="synthetic label for unit tests",
        signals=[s.lower() for s in (signals or [])],
    )


def make_finding(
    *,
    server: str = "demo",
    tool: str | None = None,
    message: str = "",
    rule_id: str | None = "R-1",
    scanner: str = "unit",
) -> Finding:
    return Finding(
        scanner=scanner,
        server=server,
        tool=tool,
        message=message,
        rule_id=rule_id,
    )
