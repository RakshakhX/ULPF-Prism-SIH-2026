import pytest

from core.cisco_asa_pack import CiscoASASourcePack
from src.contracts import ParseStatus, RawEventEnvelope


@pytest.fixture
def pack() -> CiscoASASourcePack:
    return CiscoASASourcePack()


def envelope(raw: bytes) -> RawEventEnvelope:
    return RawEventEnvelope.from_bytes(raw, source_id="asa-1", transport="udp")


def test_detect_valid_asa(pack: CiscoASASourcePack) -> None:
    raw = envelope(
        b"<166>Oct 12 2023 14:23:01 asa-fw1 : %ASA-4-106023: "
        b"Deny tcp src outside:10.0.0.1/123 dst inside:10.0.0.2/456 "
        b'by access-group "OUT"'
    )
    assert pack.detect(raw) > 0.90


def test_detect_invalid_asa(pack: CiscoASASourcePack) -> None:
    raw = envelope(
        b"<134>1 2023-10-12T14:23:20Z fw-edge filterlog 1 - - 5,,,100,igb0,match,pass,in"
    )
    assert pack.detect(raw) == 0.0


def test_parse_106023_success_preserves_canonical_evidence(
    pack: CiscoASASourcePack,
) -> None:
    raw = envelope(
        b"<166>Oct 12 2023 14:23:01 asa-fw1 : %ASA-4-106023: "
        b"Deny tcp src outside:203.0.113.5/54321 "
        b'dst inside:10.0.0.5/443 by access-group "OUTSIDE_IN"'
    )
    event = pack.parse(raw)

    assert event.status is ParseStatus.SUCCESS
    assert event.vendor == "Cisco"
    assert event.product == "ASA"
    assert event.extracted_fields["message_id"] == "106023"
    assert event.extracted_fields["event_type"] == "acl_deny"
    assert event.extracted_fields["src_ip"] == "203.0.113.5"
    assert event.extracted_fields["dst_port"] == "443"
    assert event.event_id == raw.event_id
    assert event.raw_event == raw


def test_parse_unknown_message_id_is_partial(pack: CiscoASASourcePack) -> None:
    raw = envelope(b"<166>Oct 12 2023 14:23:10 asa-fw1 : %ASA-5-999999: Some future message format")
    event = pack.parse(raw)

    assert event.status is ParseStatus.PARTIAL
    assert event.extracted_fields["message_id"] == "999999"
    assert event.issues[0].code == "ASA_UNKNOWN_MESSAGE_ID"
    assert event.raw_event == raw


def test_parse_garbage_payload_is_failed_without_losing_bytes(
    pack: CiscoASASourcePack,
) -> None:
    raw = envelope(b"This is invalid garbage\xff with no ASA header")
    event = pack.parse(raw)

    assert event.status is ParseStatus.FAILED
    assert event.issues[0].code == "ASA_HEADER_NO_MATCH"
    assert event.raw_event.raw_bytes() == raw.raw_bytes()
