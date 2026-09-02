"""Lossless raw-event contract for collection, transport, and replay."""

from __future__ import annotations

import base64
import binascii
import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Self
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator, model_validator


class RawEventEnvelope(BaseModel):
    """Immutable evidence envelope that verifies its bytes on every load."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    contract_version: Literal["1.0.0"] = "1.0.0"
    event_id: UUID
    ingested_at: datetime
    source_id: str
    source_ip: IPvAnyAddress | None = None
    transport: Literal["udp", "tcp", "file", "api", "replay"]
    raw_payload_b64: str
    raw_size: int = Field(ge=0)
    raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    collector_id: str
    collector_version: str
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("ingested_at")
    @classmethod
    def require_utc_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("ingested_at must be an aware UTC timestamp")
        return value

    @classmethod
    def from_bytes(
        cls,
        raw: bytes,
        *,
        source_id: str,
        transport: Literal["udp", "tcp", "file", "api", "replay"],
        source_ip: str | None = None,
        collector_id: str = "ulpf-collector",
        collector_version: str = "0.1.0",
        metadata: dict[str, Any] | None = None,
    ) -> Self:
        """Create an envelope without attempting to decode or alter ``raw``."""

        return cls(
            event_id=uuid4(),
            ingested_at=datetime.now(UTC),
            source_id=source_id,
            source_ip=source_ip,
            transport=transport,
            raw_payload_b64=base64.b64encode(raw).decode("ascii"),
            raw_size=len(raw),
            raw_sha256=hashlib.sha256(raw).hexdigest(),
            collector_id=collector_id,
            collector_version=collector_version,
            metadata={} if metadata is None else metadata,
        )

    def raw_bytes(self) -> bytes:
        """Return the exact evidence bytes represented by this envelope."""

        try:
            return base64.b64decode(self.raw_payload_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("raw_payload_b64 must contain valid Base64") from exc

    @model_validator(mode="after")
    def verify_evidence(self) -> Self:
        """Reject corrupted serialized evidence before it enters the pipeline."""

        raw = self.raw_bytes()
        if len(raw) != self.raw_size or hashlib.sha256(raw).hexdigest() != self.raw_sha256:
            raise ValueError("raw evidence size or SHA-256 mismatch")
        return self
