from dataclasses import FrozenInstanceError

import pytest

from src.validation.result import ValidationIssue, ValidationResult


def test_result_without_issues_is_valid() -> None:
    assert ValidationResult().valid is True


def test_result_with_issue_is_invalid() -> None:
    issue = ValidationIssue(path="$.event.id", rule="format", message="must be a UUID")
    result = ValidationResult(issues=(issue,))

    assert result.valid is False
    assert result.issues == (issue,)


def test_validation_issue_is_immutable() -> None:
    issue = ValidationIssue(path="$", rule="required", message="missing event")

    with pytest.raises(FrozenInstanceError):
        issue.path = "$.event"  # type: ignore[misc]
