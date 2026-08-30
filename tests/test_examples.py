from pathlib import Path

import pytest

from src.validation.validate_unified_event import validate_file

EXAMPLE_DIRECTORY = Path("examples/unified_events")
EXPECTED_EXAMPLES = {
    "firewall_allow.json",
    "firewall_deny.json",
    "ids_threat_detected.json",
    "vpn_authentication_failed.json",
    "proxy_request_blocked.json",
    "router_acl_deny.json",
    "waf_attack_blocked.json",
}


def test_exact_example_set_exists() -> None:
    assert {path.name for path in EXAMPLE_DIRECTORY.glob("*.json")} == EXPECTED_EXAMPLES


@pytest.mark.parametrize("filename", sorted(EXPECTED_EXAMPLES))
def test_official_example_is_valid(filename: str) -> None:
    result = validate_file(EXAMPLE_DIRECTORY / filename)
    assert result.valid, result.issues
