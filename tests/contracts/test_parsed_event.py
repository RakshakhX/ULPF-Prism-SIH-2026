from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from src.contracts import RawEventEnvelope
from src.contracts.parsed_event import (
    ParsedEvent,
    ParseIssue,
    ParseIssueSeverity,
    ParseStatus,
)


def test_successful_parse_preserves_fields_and_raw_envelope() -> None:
    raw = RawEventEnvelope.from_bytes(
        b"%ASA-6-302013: Built outbound TCP connection",
        source_id="edge-fw-1",
        transport="udp",
    )

    parsed = ParsedEvent(
        event_id=raw.event_id,
        parsed_at=datetime.now(UTC),
        vendor="Cisco",
        product="ASA",
        product_version=None,
        parser_id="cisco-asa-syslog",
        parser_version="1.0.0",
        source_pack_id="cisco_asa",
        source_pack_version="1.0.0",
        detected_format="syslog",
        status=ParseStatus.SUCCESS,
        extracted_fields={"asa.message_id": "302013", "network.transport": "tcp"},
        raw_event=raw,
    )

    restored = ParsedEvent.model_validate_json(parsed.model_dump_json())
    assert restored.extracted_fields == {
        "asa.message_id": "302013",
        "network.transport": "tcp",
    }
    assert restored.raw_event.raw_bytes() == raw.raw_bytes()
    assert restored.event_id == raw.event_id


def test_unrecognized_parse_keeps_complete_raw_envelope_and_structured_issue() -> None:
    raw = RawEventEnvelope.from_bytes(
        b"garbled\xff",
        source_id="edge-fw-1",
        transport="udp",
    )

    parsed = ParsedEvent.unrecognized(raw, "no source pack matched")

    assert parsed.raw_event == raw
    assert parsed.status is ParseStatus.UNRECOGNIZED
    assert parsed.vendor is None
    assert parsed.issues == (
        ParseIssue(
            code="NO_SOURCE_PACK_MATCH",
            message="no source pack matched",
            severity=ParseIssueSeverity.ERROR,
        ),
    )


def test_parse_failure_can_retain_partial_fields_and_multiple_issues() -> None:
    raw = RawEventEnvelope.from_bytes(
        b"date=bad srcip=192.0.2.20 action=deny",
        source_id="edge-fw-2",
        transport="file",
    )

    parsed = ParsedEvent(
        event_id=raw.event_id,
        parsed_at=datetime.now(UTC),
        vendor="Fortinet",
        product="FortiGate",
        product_version=None,
        parser_id="fortigate-kv",
        parser_version="1.0.0",
        source_pack_id="fortinet_fortigate",
        source_pack_version="1.0.0",
        detected_format="key_value",
        status=ParseStatus.PARTIAL,
        issues=(
            ParseIssue(
                code="INVALID_TIMESTAMP",
                message="date field could not be parsed",
                severity=ParseIssueSeverity.WARNING,
                field="date",
            ),
        ),
        extracted_fields={"srcip": "192.0.2.20", "action": "deny"},
        raw_event=raw,
    )

    assert parsed.extracted_fields["action"] == "deny"
    assert parsed.issues[0].field == "date"
    assert parsed.raw_event.raw_sha256 == raw.raw_sha256


def test_event_identity_must_match_preserved_raw_event() -> None:
    raw = RawEventEnvelope.from_bytes(
        b"event",
        source_id="edge-fw-1",
        transport="api",
    )

    with pytest.raises(ValidationError, match="must match raw_event.event_id"):
        ParsedEvent(
            event_id=uuid4(),
            parsed_at=datetime.now(UTC),
            vendor=None,
            product=None,
            product_version=None,
            parser_id="fallback",
            parser_version="1.0.0",
            source_pack_id=None,
            source_pack_version=None,
            detected_format="unknown",
            status=ParseStatus.FAILED,
            raw_event=raw,
        )
