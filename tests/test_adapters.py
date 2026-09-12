"""Adapters are the seam where inconsistent scanner output becomes usable data."""

from __future__ import annotations

import json

import pytest

from harness.adapters import (
    AdapterError,
    ScannerProfile,
    _as_text,
    _pluck,
    json_path,
    load_profiles,
    parse_json,
    parse_output,
    parse_text,
    select_profile,
)

MINIMAL_ITEMS = [
    {"ruleId": "X-1", "level": "ERROR", "title": "tool foo is dangerous", "tool_name": "foo"},
    {"ruleId": "X-2", "severity": "warning", "description": "something else"},
]


def profile(**overrides: object) -> ScannerProfile:
    base = {
        "name": "test",
        "command": ["scanner", "--target", "{entrypoint}"],
        "json_path": "$",
        "field_map": {
            "rule_id": ["ruleId", "id"],
            "severity": ["severity", "level"],
            "tool": ["tool", "tool_name"],
            "message": ["message", "description", "title"],
        },
    }
    base.update(overrides)
    return ScannerProfile.from_yaml(base)


# --------------------------------------------------------------------------- #
# Lookup helpers
# --------------------------------------------------------------------------- #


def test_pluck_is_case_insensitive() -> None:
    assert _pluck({"RuleID": "R"}, "ruleid") == "R"


def test_pluck_walks_dotted_paths() -> None:
    assert _pluck({"a": {"b": {"c": 7}}}, "a.b.c") == 7


def test_pluck_searches_inside_lists() -> None:
    assert _pluck({"locations": [{"path": "/etc/passwd"}]}, "locations.path") == "/etc/passwd"


def test_pluck_returns_none_for_missing_paths() -> None:
    assert _pluck({"a": 1}, "a.b.c") is None
    assert _pluck("not-a-dict", "a") is None


def test_as_text_flattens_the_shapes_scanners_actually_emit() -> None:
    assert _as_text(None) is None
    assert _as_text("  padded  ") == "padded"
    assert _as_text(["a", "b"]) == "a b"
    assert _as_text({"k": "v"}) == "k v"
    assert _as_text(7) == "7"


def test_json_path_supports_the_documented_subset() -> None:
    document = {"results": {"issues": [1, 2]}}
    assert json_path(document, "$") is document
    assert json_path(document, "$.results.issues") == [1, 2]
    assert json_path(document, "$.nope") is None


def test_json_path_flattens_across_lists() -> None:
    document = {"runs": [{"results": [1, 2]}, {"results": [3]}]}
    assert json_path(document, "$.runs.results") == [1, 2, 3]


# --------------------------------------------------------------------------- #
# Command rendering
# --------------------------------------------------------------------------- #


def test_render_command_substitutes_placeholders() -> None:
    from pathlib import Path

    rendered = profile().render_command(
        server_dir=Path("/corpus/demo"),
        entrypoint=Path("/corpus/demo/server.py"),
        slug="demo",
        python="/usr/bin/python3",
    )
    assert rendered == ["scanner", "--target", "/corpus/demo/server.py"]


def test_render_command_reports_unknown_placeholders() -> None:
    bad = profile(command=["scanner", "{nonexistent}"])
    from pathlib import Path

    with pytest.raises(AdapterError, match="unknown placeholder"):
        bad.render_command(
            server_dir=Path("/x"), entrypoint=Path("/x/server.py"), slug="x", python="py"
        )


def test_render_command_leaves_non_placeholder_braces_alone() -> None:
    """Scanner argv legitimately contains JSON, regexes, and inline scripts.

    Running those through str.format either mangles them or raises on a key that
    was never a placeholder — so substitution is literal.
    """
    from pathlib import Path

    script = "import json;print(json.dumps({'findings': []}))"
    braces = profile(command=["{python}", "-c", script, "--target", "{entrypoint}"])
    rendered = braces.render_command(
        server_dir=Path("/x"), entrypoint=Path("/x/server.py"), slug="x", python="/usr/bin/python3"
    )
    assert rendered == ["/usr/bin/python3", "-c", script, "--target", "/x/server.py"]


def test_render_command_handles_a_regex_with_quantifiers() -> None:
    from pathlib import Path

    regex = profile(command=["scanner", "--pattern", r"^a{2,8}$"])
    rendered = regex.render_command(
        server_dir=Path("/x"), entrypoint=Path("/x/server.py"), slug="x", python="py"
    )
    assert rendered == ["scanner", "--pattern", r"^a{2,8}$"]


# --------------------------------------------------------------------------- #
# JSON parsing
# --------------------------------------------------------------------------- #


def test_parse_json_maps_fallback_field_names() -> None:
    findings = parse_json(profile(), "demo", json.dumps(MINIMAL_ITEMS))
    assert [f.rule_id for f in findings] == ["X-1", "X-2"]
    # "title" is the last-resort fallback for message in this profile.
    assert findings[0].message == "tool foo is dangerous"
    assert findings[0].tool == "foo"


def test_parse_json_normalizes_severity_aliases() -> None:
    findings = parse_json(profile(), "demo", json.dumps(MINIMAL_ITEMS))
    assert findings[0].severity == "high"  # ERROR
    assert findings[1].severity == "medium"  # warning


def test_parse_json_honours_json_path() -> None:
    payload = json.dumps({"data": {"findings": MINIMAL_ITEMS}})
    findings = parse_json(profile(json_path="$.data.findings"), "demo", payload)
    assert len(findings) == 2


def test_parse_json_accepts_a_bare_object() -> None:
    findings = parse_json(profile(), "demo", json.dumps(MINIMAL_ITEMS[0]))
    assert len(findings) == 1
    assert findings[0].rule_id == "X-1"


def test_parse_json_empty_output_is_no_findings() -> None:
    assert parse_json(profile(), "demo", "   \n ") == []


def test_parse_json_explains_itself_on_non_json() -> None:
    """This error message is the difference between a 5-minute and a 5-hour fix."""
    with pytest.raises(AdapterError, match="did not emit valid JSON"):
        parse_json(profile(), "demo", "CRITICAL: something bad\n")


def test_parse_json_reports_what_the_keys_actually_were() -> None:
    with pytest.raises(AdapterError, match="matched nothing"):
        parse_json(profile(json_path="$.does.not.exist"), "demo", json.dumps({"other": 1}))


def test_every_finding_records_its_server() -> None:
    findings = parse_json(profile(), "some-challenge", json.dumps(MINIMAL_ITEMS))
    assert {f.server for f in findings} == {"some-challenge"}


# --------------------------------------------------------------------------- #
# SARIF
# --------------------------------------------------------------------------- #


def test_sarif_results_are_flattened_with_rule_metadata() -> None:
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "some-scanner",
                        "rules": [{"id": "R-9", "properties": {"category": "auth"}}],
                    }
                },
                "results": [
                    {"ruleId": "R-9", "level": "error", "message": {"text": "missing auth"}}
                ],
            }
        ],
    }
    sarif_profile = profile(
        sarif=True,
        json_path="$.runs",
        field_map={
            "rule_id": ["ruleId"],
            "severity": ["level"],
            "category": ["properties.category"],
            "message": ["message.text"],
        },
    )
    findings = parse_json(sarif_profile, "demo", json.dumps(sarif))
    assert len(findings) == 1
    assert findings[0].rule_id == "R-9"
    assert findings[0].message == "missing auth"
    assert findings[0].category == "auth"  # inherited from the rule definition
    assert findings[0].severity == "high"


# --------------------------------------------------------------------------- #
# Text parsing
# --------------------------------------------------------------------------- #


def test_parse_text_extracts_named_groups() -> None:
    text_profile = profile(
        output="text",
        regex={
            "pattern": r"^(?P<severity>CRITICAL|HIGH|LOW)\s+(?P<tool>[\w.-]+)\s*:\s*(?P<message>.+)$",
            "flags": ["IGNORECASE"],
        },
    )
    stdout = "HIGH save_report: arbitrary file write\nnoise line\nlow ping: fine\n"
    findings = parse_text(text_profile, "demo", stdout)
    assert [f.tool for f in findings] == ["save_report", "ping"]
    assert findings[0].severity == "high"
    assert findings[1].severity == "low"


def test_parse_text_without_a_pattern_is_an_error() -> None:
    with pytest.raises(AdapterError, match=r"no regex\.pattern"):
        parse_text(profile(output="text"), "demo", "anything")


def test_parse_output_rejects_unknown_modes() -> None:
    with pytest.raises(AdapterError, match="unknown output mode"):
        parse_output(profile(output="xml"), "demo", "{}")


# --------------------------------------------------------------------------- #
# Profile loading
# --------------------------------------------------------------------------- #


def test_shipped_profiles_load(root) -> None:
    profiles = load_profiles(root / "scanners.yaml")
    names = {p.name for p in profiles}
    assert {"replay", "skillspector", "snyk-agent-scan", "cisco-mcp-scanner"} <= names


def test_shipped_profiles_all_have_an_executable(root) -> None:
    for entry in load_profiles(root / "scanners.yaml"):
        assert entry.command, f"{entry.name}: empty command"


def test_select_profile_names_the_alternatives(root) -> None:
    profiles = load_profiles(root / "scanners.yaml")
    with pytest.raises(AdapterError, match="Known scanners"):
        select_profile(profiles, "does-not-exist")


# --------------------------------------------------------------------------- #
# flatten_from — nested per-analyzer shapes (Cisco)
# --------------------------------------------------------------------------- #


def test_flatten_from_explodes_nested_findings() -> None:
    cisco = profile(
        json_path="$.scan_results",
        flatten_from="findings",
        skip_if_zero="total_findings",
        field_map={
            "tool": ["tool_name"],
            "severity": ["severity"],
            "message": ["threat_summary"],
        },
    )
    document = json.dumps(
        {
            "scan_results": [
                {
                    "tool_name": "operator_note",
                    "findings": {
                        "yara_analyzer": {
                            "total_findings": 0,
                            "severity": "SAFE",
                            "threat_summary": "No threats detected",
                        },
                        "readiness_analyzer": {
                            "total_findings": 1,
                            "severity": "HIGH",
                            "threat_summary": "no timeout",
                        },
                    },
                }
            ]
        }
    )
    findings = parse_json(cisco, "demo", document)
    assert len(findings) == 1  # the zero-count analyzer is skipped
    assert findings[0].tool == "operator_note"
    assert findings[0].rule_id == "readiness_analyzer"
    assert findings[0].severity == "high"
    assert findings[0].message == "no timeout"


def test_flatten_from_keeps_parent_fields_on_the_leaf() -> None:
    """The leaf knows the analyzer; the merged object must still know the tool."""
    cisco = profile(
        json_path="$.scan_results",
        flatten_from="findings",
        field_map={"tool": ["tool_name"], "message": ["threat_summary"]},
    )
    document = json.dumps(
        {
            "scan_results": [
                {"tool_name": "delete_file", "findings": {"yara_analyzer": {"threat_summary": "x"}}}
            ]
        }
    )
    findings = parse_json(cisco, "demo", document)
    assert findings[0].tool == "delete_file"


# --------------------------------------------------------------------------- #
# config_template — scanners that only accept a config file (Snyk)
# --------------------------------------------------------------------------- #


def test_config_template_renders_recursively() -> None:
    snyk = profile(
        command=["snyk-agent-scan", "--json", "{config}"],
        config_template={
            "mcpServers": {"{slug}": {"command": "{python}", "args": ["{entrypoint}"]}}
        },
    )
    assert snyk.needs_config is True
    from pathlib import Path

    rendered = snyk.render_config(
        server_dir=Path("/corpus/x"),
        entrypoint=Path("/corpus/x/server.py"),
        slug="x",
        python="/py",
    )
    assert rendered == {"mcpServers": {"x": {"command": "/py", "args": ["/corpus/x/server.py"]}}}


def test_render_command_substitutes_the_config_path() -> None:
    from pathlib import Path

    snyk = profile(
        command=["snyk-agent-scan", "--json", "{config}"],
        config_template={"mcpServers": {}},
    )
    config = Path("configs/x.json")
    argv = snyk.render_command(
        server_dir=Path("/corpus/x"),
        entrypoint=Path("/corpus/x/server.py"),
        slug="x",
        python="/py",
        config=config,
    )
    assert argv == ["snyk-agent-scan", "--json", "configs/x.json"]


def test_profiles_without_template_have_no_needs_config() -> None:
    assert profile().needs_config is False


def test_shipped_snyk_profile_declares_a_config_template(root) -> None:
    profiles = load_profiles(root / "scanners.yaml")
    snyk = select_profile(profiles, "snyk-agent-scan")
    assert snyk.needs_config is True
    assert "{config}" in snyk.command


# --------------------------------------------------------------------------- #
# require — keep only failing checks (spec-compliance scanners)
# --------------------------------------------------------------------------- #


def test_require_drops_passing_checks() -> None:
    conformance = profile(
        json_path="$.findings",
        require={"field": "passed", "equals": False},
        field_map={"rule_id": ["id"], "severity": ["severity"], "message": ["title"]},
    )
    document = json.dumps(
        {
            "findings": [
                {"id": "X-01", "title": "dangerous capability", "severity": "high", "passed": True},
                {"id": "BASE-01", "title": "fingerprint", "severity": "info", "passed": False},
            ]
        }
    )
    findings = parse_json(conformance, "demo", document)
    assert [f.rule_id for f in findings] == ["BASE-01"]


def test_require_keeps_everything_when_absent() -> None:
    document = json.dumps({"findings": [{"id": "A", "passed": False}, {"id": "B", "passed": True}]})
    findings = parse_json(profile(json_path="$.findings"), "demo", document)
    assert [f.rule_id for f in findings] == ["A", "B"]


def test_shipped_conformance_profile_requires_failed_checks(root) -> None:
    profiles = load_profiles(root / "scanners.yaml")
    conformance = select_profile(profiles, "mcp-security-scanner")
    assert conformance.require == {"field": "passed", "equals": False}
