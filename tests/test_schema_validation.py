import copy
import json
from pathlib import Path
from types import MappingProxyType
from typing import Any

from src.validation.schema_validation import load_schema, validate_structure

FIXTURE = Path("tests/fixtures/valid_minimal_network_event.json")


def load_event() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def immutable_mappings(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: immutable_mappings(child) for key, child in value.items()})
    if isinstance(value, list):
        return [immutable_mappings(child) for child in value]
    return value


def test_valid_event_has_no_structural_issues() -> None:
    assert validate_structure(load_event()) == ()


def test_valid_event_accepts_recursively_immutable_mappings() -> None:
    event = immutable_mappings(load_event())

    assert validate_structure(event) == ()
    assert validate_structure(event) == ()


def test_missing_required_section_reports_json_path() -> None:
    event = load_event()
    del event["traceability"]

    issues = validate_structure(event)

    assert any(issue.path == "$" and issue.rule == "required" for issue in issues)
    assert any("traceability" in issue.message for issue in issues)


def test_invalid_ip_and_port_are_both_reported() -> None:
    event = copy.deepcopy(load_event())
    event["source"]["ip"] = "999.1.1.1"
    event["source"]["port"] = 70000

    issues = validate_structure(event)

    assert any(issue.path == "$.source.ip" for issue in issues)
    assert any(issue.path == "$.source.port" for issue in issues)


def test_unknown_top_level_property_is_rejected() -> None:
    event = load_event()
    event["vendor_policy"] = "POL-1"

    issues = validate_structure(event)

    assert any(issue.path == "$" and issue.rule == "additionalProperties" for issue in issues)


def test_schema_load_returns_independent_dictionary() -> None:
    first = load_schema()
    second = load_schema()
    assert first == second
    assert first is not second
