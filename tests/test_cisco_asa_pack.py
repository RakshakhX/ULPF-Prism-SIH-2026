import pytest

from core.cisco_asa_pack import CiscoASASourcePack
from core.models import ParseStatus


@pytest.fixture
def pack():
    return CiscoASASourcePack()


def test_detect_valid_asa(pack):
    """Test that the pack correctly identifies a Cisco ASA syslog message."""
    raw = b'<166>Oct 12 2023 14:23:01 asa-fw1 : %ASA-4-106023: Deny tcp src outside:10.0.0.1/123 dst inside:10.0.0.2/456 by access-group "OUT"'
    result = pack.detect(raw)
    assert result.matched is True
    assert result.confidence > 0.90


def test_detect_invalid_asa(pack):
    """Test that the pack rejects unrelated logs."""
    raw = b"<134>1 2023-10-12T14:23:20Z fw-edge filterlog 1 - - 5,,,100,igb0,match,pass,in"
    result = pack.detect(raw)
    assert result.matched is False


def test_parse_106023_success(pack):
    """Test full extraction of a known message ID (106023)."""
    raw = (
        b"<166>Oct 12 2023 14:23:01 asa-fw1 : %ASA-4-106023: "
        b"Deny tcp src outside:203.0.113.5/54321 "
        b'dst inside:10.0.0.5/443 by access-group "OUTSIDE_IN"'
    )
    event = pack.parse(raw)

    assert event.parse_status == ParseStatus.SUCCESS
    assert event.vendor == "Cisco"
    assert event.product == "ASA"
    assert event.extracted_fields["message_id"] == "106023"
    assert event.extracted_fields["event_type"] == "acl_deny"
    assert event.extracted_fields["src_ip"] == "203.0.113.5"
    assert event.extracted_fields["dst_port"] == "443"

    # Losslessness check: Ensure the original bytes are preserved
    assert event.raw_event.byte_length == len(raw)


def test_parse_unknown_message_id_is_partial(pack):
    """Test that unknown message IDs extract the header but downgrade to PARTIAL with a warning."""
    raw = b"<166>Oct 12 2023 14:23:10 asa-fw1 : %ASA-5-999999: Some future message format"
    event = pack.parse(raw)

    assert event.parse_status == ParseStatus.PARTIAL
    assert event.extracted_fields["message_id"] == "999999"
    assert event.extracted_fields["severity"] == 5
    assert event.has_errors is True
    assert event.parse_errors[0].code == "ASA_UNKNOWN_MESSAGE_ID"

    # Losslessness check
    assert event.raw_event.byte_length == len(raw)


def test_parse_garbage_payload_is_failed(pack):
    """Test that complete garbage gracefully fails without crashing and preserves the payload."""
    raw = b"This is completely invalid garbage data with no ASA tags."
    event = pack.parse(raw)

    assert event.parse_status == ParseStatus.FAILED
    assert event.has_errors is True
    assert event.parse_errors[0].code == "ASA_HEADER_NO_MATCH"

    # Losslessness check
    assert event.raw_event.byte_length == len(raw)
