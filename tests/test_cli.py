import json
from pathlib import Path

from src.validation.validate_unified_event import main, validate_event, validate_file

VALID_FIXTURE = Path("tests/fixtures/valid_minimal_network_event.json")


def test_validate_event_combines_structural_and_semantic_issues() -> None:
    event = json.loads(VALID_FIXTURE.read_text(encoding="utf-8"))
    event["source"]["port"] = 70000
    event["action"] = {"original": "Deny", "normalized": "deny", "outcome": "success"}

    result = validate_event(event)

    assert result.valid is False
    assert {issue.path for issue in result.issues} >= {"$.source.port", "$.action.outcome"}


def test_validate_file_accepts_valid_event() -> None:
    assert validate_file(VALID_FIXTURE).valid is True


def test_cli_returns_zero_for_valid_event(capsys) -> None:
    exit_code = main([str(VALID_FIXTURE)])
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
    assert output.out.startswith(f"INVALID: {invalid}\n")
    assert "- $ [required]" in output.out


def test_cli_returns_two_for_missing_file(tmp_path: Path, capsys) -> None:
    missing = tmp_path / "missing.json"

    exit_code = main([str(missing)])
    output = capsys.readouterr()

    assert exit_code == 2
    assert output.err.startswith(f"ERROR: unable to read {missing}:")
