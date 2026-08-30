from pathlib import Path

import pytest

from src.validation.validate_unified_event import validate_file

INVALID_DIRECTORY = Path("tests/fixtures/invalid_unified_events")

CASES = [
    ("missing_traceability.json", "$"),
    ("invalid_ip.json", "$.source.ip"),
    ("invalid_port.json", "$.source.port"),
    ("invalid_severity.json", "$.severity.normalized"),
    ("invalid_sha256.json", "$.traceability.raw_sha256"),
    ("timestamp_order.json", "$.time"),
    ("missing_network_endpoint.json", "$.destination.ip"),
    ("missing_threat.json", "$"),
    ("missing_authentication.json", "$"),
    ("unnamespaced_extension.json", "$.extensions"),
    ("raw_hash_mismatch.json", "$.traceability.raw_sha256"),
    ("unknown_top_level_property.json", "$"),
]


@pytest.mark.parametrize(("filename", "expected_path"), CASES)
def test_invalid_fixture_fails_for_expected_path(filename: str, expected_path: str) -> None:
    result = validate_file(INVALID_DIRECTORY / filename)

    assert result.valid is False
    assert expected_path in {issue.path for issue in result.issues}
