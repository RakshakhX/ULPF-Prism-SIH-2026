import copy
import hashlib
import json
from pathlib import Path

from src.validation.semantic_validation import validate_semantics

FIXTURE = Path("tests/fixtures/valid_minimal_network_event.json")


def load_event() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def issue_paths(event: dict) -> set[str]:
    return {issue.path for issue in validate_semantics(event)}


def test_valid_event_has_no_semantic_issues() -> None:
    assert validate_semantics(load_event()) == ()


def test_timestamp_order_is_enforced_without_mutation() -> None:
    event = load_event()
    event["time"]["ingested_at"] = "2026-08-30T10:15:29Z"
    original = copy.deepcopy(event)

    assert "$.time" in issue_paths(event)
    assert event == original


def test_block_action_cannot_report_success() -> None:
    event = load_event()
    event["action"] = {"original": "Block", "normalized": "block", "outcome": "success"}

    assert "$.action.outcome" in issue_paths(event)


def test_known_severity_label_must_match_normalized_range() -> None:
    event = load_event()
    event["severity"] = {"original": "High", "normalized": 8, "label": "low"}

    assert "$.severity.label" in issue_paths(event)


def test_unknown_severity_requires_quality_warning() -> None:
    event = load_event()
    event["severity"]["label"] = "unknown"

    assert "$.severity.label" in issue_paths(event)


def test_authentication_result_must_match_action_outcome() -> None:
    event = load_event()
    event["event"]["category"] = "authentication"
    event["authentication"] = {"user": "alice", "result": "failure"}
    event["action"]["outcome"] = "success"

    assert "$.authentication.result" in issue_paths(event)


def test_partial_quality_requires_an_explanation() -> None:
    event = load_event()
    event["quality"]["status"] = "partial"

    assert "$.quality" in issue_paths(event)


def test_embedded_raw_content_hash_is_verified() -> None:
    event = load_event()
    event["traceability"]["raw_event"] = {
        "encoding": "utf-8",
        "content_type": "text/plain",
        "content": "original log",
    }

    assert "$.traceability.raw_sha256" in issue_paths(event)


def test_namespaced_extensions_are_accepted() -> None:
    event = load_event()
    event["extensions"] = {"example_vendor": {"policy_id": "POL-1"}}

    assert validate_semantics(event) == ()


def test_category_requirements_are_reported_for_incomplete_mappings() -> None:
    event = load_event()
    event["event"]["category"] = "intrusion_detection"

    assert "$.threat" in issue_paths(event)


def test_invalid_extension_namespaces_are_reported_deterministically() -> None:
    event = load_event()
    event["extensions"] = {"Bad-Vendor": {}, "also bad": {}}

    issues = validate_semantics(event)

    assert isinstance(issues, tuple)
    assert issues == tuple(sorted(issues))
    assert {issue.path for issue in issues} == {
        "$.extensions.Bad-Vendor",
        "$.extensions.also bad",
    }


def test_embedded_raw_content_with_matching_hash_is_accepted() -> None:
    event = load_event()
    content = "original log"
    event["traceability"]["raw_event"] = {
        "encoding": "utf-8",
        "content_type": "text/plain",
        "content": content,
    }
    event["traceability"]["raw_sha256"] = hashlib.sha256(
        content.encode("utf-8")
    ).hexdigest()

    assert validate_semantics(event) == ()


def test_partially_structured_mappings_do_not_raise() -> None:
    event = {
        "event": [],
        "time": "not-a-mapping",
        "action": None,
        "severity": {"normalized": True},
        "traceability": {"raw_event": ["not-a-mapping"]},
        "quality": {"warnings": None},
        "extensions": ["not-a-mapping"],
    }

    assert validate_semantics(event) == ()
