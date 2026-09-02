import base64
import hashlib
from datetime import timedelta

import pytest
from pydantic import ValidationError

from src.contracts.raw_event import RawEventEnvelope


def test_non_utf8_bytes_survive_json_round_trip() -> None:
    raw = b"\x00\xff\x80ASA\n"

    event = RawEventEnvelope.from_bytes(
        raw,
        source_id="fw-1",
        source_ip="192.0.2.10",
        transport="udp",
    )
    restored = RawEventEnvelope.model_validate_json(event.model_dump_json())

    assert restored.raw_bytes() == raw
    assert restored.raw_size == 7
    assert restored.raw_sha256 == "37252664dc6ab932c364d3e2e462d8fb694678d45b100714d8e6e7e4bb5470a5"
    assert restored.raw_payload_b64 == base64.b64encode(raw).decode("ascii")
    assert restored.ingested_at.utcoffset() == timedelta(0)


def test_deserialization_rejects_hash_mismatch() -> None:
    event = RawEventEnvelope.from_bytes(
        b"original",
        source_id="fw-1",
        transport="file",
    )

    with pytest.raises(ValidationError, match="raw evidence size or SHA-256 mismatch"):
        RawEventEnvelope.model_validate(
            {**event.model_dump(), "raw_sha256": "0" * 64}
        )


def test_deserialization_rejects_size_mismatch() -> None:
    event = RawEventEnvelope.from_bytes(
        b"event",
        source_id="fw-1",
        transport="tcp",
    )

    with pytest.raises(ValidationError, match="raw evidence size or SHA-256 mismatch"):
        RawEventEnvelope.model_validate({**event.model_dump(), "raw_size": 6})


def test_deserialization_rejects_invalid_base64() -> None:
    raw = b"event"

    with pytest.raises(ValidationError, match="valid Base64"):
        RawEventEnvelope.model_validate(
            {
                "contract_version": "1.0.0",
                "event_id": "c4994634-5632-4bee-ab2c-ef9b24645bc4",
                "ingested_at": "2026-09-02T00:00:00Z",
                "source_id": "fw-1",
                "source_ip": None,
                "transport": "api",
                "raw_payload_b64": "not-base64!",
                "raw_size": len(raw),
                "raw_sha256": hashlib.sha256(raw).hexdigest(),
                "collector_id": "collector-1",
                "collector_version": "1.0.0",
                "metadata": {},
            }
        )


def test_contract_is_immutable_and_rejects_unknown_fields() -> None:
    event = RawEventEnvelope.from_bytes(
        b"event",
        source_id="fw-1",
        transport="replay",
    )

    with pytest.raises(ValidationError, match="Instance is frozen"):
        event.raw_size = 0  # type: ignore[misc]

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RawEventEnvelope.model_validate({**event.model_dump(), "unexpected": True})


@pytest.mark.parametrize(
    "invalid_timestamp",
    ["2026-09-02T10:00:00", "2026-09-02T10:00:00+05:30"],
)
def test_contract_rejects_non_utc_ingestion_timestamp(invalid_timestamp: str) -> None:
    event = RawEventEnvelope.from_bytes(
        b"event",
        source_id="fw-1",
        transport="udp",
    )

    with pytest.raises(ValidationError, match="ingested_at must be an aware UTC timestamp"):
        RawEventEnvelope.model_validate(
            {**event.model_dump(), "ingested_at": invalid_timestamp}
        )
