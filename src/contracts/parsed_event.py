"""Canonical result of source detection and vendor-specific parsing."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.contracts.raw_event import RawEventEnvelope


class ParseStatus(StrEnum):
    """Outcome of a parser attempt without hiding partial information."""

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    UNRECOGNIZED = "unrecognized"


class ParseIssueSeverity(StrEnum):
    """Importance of a structured parsing issue."""

    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ParseIssue(BaseModel):
    """Machine-readable explanation of missing or invalid parsed data."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    code: str
    message: str
    severity: ParseIssueSeverity
    field: str | None = None


class ParsedEvent(BaseModel):
    """Strict parsed contract that always retains the complete raw envelope."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    contract_version: Literal["1.0.0"] = "1.0.0"
    event_id: UUID
    parsed_at: datetime
    vendor: str | None
    product: str | None
    product_version: str | None
    parser_id: str
    parser_version: str
    source_pack_id: str | None
    source_pack_version: str | None
    detected_format: str
    status: ParseStatus
    issues: tuple[ParseIssue, ...] = ()
    extracted_fields: dict[str, Any] = Field(default_factory=dict)
    raw_event: RawEventEnvelope

    @classmethod
    def unrecognized(cls, raw_event: RawEventEnvelope, reason: str) -> Self:
        """Represent an unknown format as data instead of dropping the event."""

        return cls(
            event_id=raw_event.event_id,
            parsed_at=datetime.now(UTC),
            vendor=None,
            product=None,
            product_version=None,
            parser_id="ulpf.source-pack-registry",
            parser_version="1.0.0",
            source_pack_id=None,
            source_pack_version=None,
            detected_format="unknown",
            status=ParseStatus.UNRECOGNIZED,
            issues=(
                ParseIssue(
                    code="NO_SOURCE_PACK_MATCH",
                    message=reason,
                    severity=ParseIssueSeverity.ERROR,
                ),
            ),
            raw_event=raw_event,
        )

    @model_validator(mode="after")
    def verify_event_identity(self) -> Self:
        """Prevent parsed data from pointing at the wrong source evidence."""

        if self.event_id != self.raw_event.event_id:
            raise ValueError("event_id must match raw_event.event_id")
        return self
