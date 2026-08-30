import copy
import json
from pathlib import Path

import pytest

import src.validation.validate_unified_event as validation_module
from src.validation.result import ValidationIssue
from src.validation.validate_unified_event import main, validate_event, validate_file

VALID_FIXTURE = Path("tests/fixtures/valid_minimal_network_event.json")


def test_validate_event_combines_structural_and_semantic_issues() -> None:
    event = json.loads(VALID_FIXTURE.read_text(encoding="utf-8"))
    event["source"]["port"] = 70000
    event["action"] = {"original": "Deny", "normalized": "deny", "outcome": "success"}

    result = validate_event(event)

    assert result.valid is False
    assert {issue.path for issue in result.issues} >= {"$.source.port", "$.action.outcome"}


def test_validate_event_deduplicates_issues_from_both_validators(monkeypatch) -> None:
    duplicate = ValidationIssue("$.event", "duplicate", "reported by both validators")
    monkeypatch.setattr(validation_module, "validate_structure", lambda event: (duplicate,))
    monkeypatch.setattr(validation_module, "validate_semantics", lambda event: (duplicate,))

    result = validate_event({})

    assert result.issues == (duplicate,)


def test_validate_event_does_not_mutate_input() -> None:
    event = json.loads(VALID_FIXTURE.read_text(encoding="utf-8"))
    original = copy.deepcopy(event)

    validate_event(event)

    assert event == original


def test_validate_file_accepts_valid_event() -> None:
    assert validate_file(VALID_FIXTURE).valid is True


def test_cli_returns_zero_for_valid_event(capsys) -> None:
    exit_code = main((str(VALID_FIXTURE),))
    output = capsys.readouterr()

    assert exit_code == 0
    assert output.out == f"VALID: {VALID_FIXTURE} conforms to UnifiedEvent Schema v1\n"
    assert output.err == ""


def test_cli_returns_one_and_prints_sorted_issues(tmp_path: Path, capsys) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text('{"schema_version": "1.0.0"}', encoding="utf-8")

    exit_code = main([str(invalid)])
    output = capsys.readouterr()

    assert exit_code == 1
    assert output.out == (
        f"INVALID: {invalid}\n"
        "- $ [required] 'action' is a required property\n"
        "- $ [required] 'authentication' is a required property\n"
        "- $ [required] 'destination' is a required property\n"
        "- $ [required] 'event' is a required property\n"
        "- $ [required] 'network' is a required property\n"
        "- $ [required] 'observer' is a required property\n"
        "- $ [required] 'quality' is a required property\n"
        "- $ [required] 'severity' is a required property\n"
        "- $ [required] 'source' is a required property\n"
        "- $ [required] 'threat' is a required property\n"
        "- $ [required] 'time' is a required property\n"
        "- $ [required] 'traceability' is a required property\n"
    )
    assert output.err == ""


def test_cli_returns_two_for_missing_file(tmp_path: Path, capsys) -> None:
    missing = tmp_path / "missing.json"

    exit_code = main([str(missing)])
    output = capsys.readouterr()

    assert exit_code == 2
    assert output.out == ""
    assert output.err.startswith(f"ERROR: unable to read {missing}:")


def test_cli_returns_two_for_malformed_json(tmp_path: Path, capsys) -> None:
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")

    exit_code = main([str(malformed)])
    output = capsys.readouterr()

    assert exit_code == 2
    assert output.out == ""
    assert output.err.startswith(f"ERROR: unable to read {malformed}:")


def test_cli_returns_two_for_non_object_json(tmp_path: Path, capsys) -> None:
    non_object = tmp_path / "non-object.json"
    non_object.write_text("[]", encoding="utf-8")

    exit_code = main([str(non_object)])
    output = capsys.readouterr()

    assert exit_code == 2
    assert output.out == ""
    assert output.err == (
        f"ERROR: unable to read {non_object}: top-level JSON value must be an object\n"
    )


def test_cli_returns_two_for_invalid_utf8(tmp_path: Path, capsys) -> None:
    invalid_utf8 = tmp_path / "invalid-utf8.json"
    invalid_utf8.write_bytes(b"\xff")

    exit_code = main([str(invalid_utf8)])
    output = capsys.readouterr()

    assert exit_code == 2
    assert output.out == ""
    assert output.err.startswith(f"ERROR: unable to read {invalid_utf8}:")


def test_cli_propagates_unexpected_validator_value_error(monkeypatch, capsys) -> None:
    def raise_unexpected_value_error(event):
        raise ValueError("validator defect")

    monkeypatch.setattr(validation_module, "validate_structure", raise_unexpected_value_error)

    with pytest.raises(ValueError, match="validator defect"):
        main([str(VALID_FIXTURE)])

    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == ""
