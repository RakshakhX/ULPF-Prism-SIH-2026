#!/usr/bin/env python3
"""
models.py — ULPF parsing engine data contract

This module defines the non-negotiable contract every Source Pack parses
into: `ParsedEvent`. Two properties of this contract are load-bearing for
the whole framework and must never be relaxed by an individual pack:

1. LOSSLESSNESS. The original bytes a Source Pack received are always
   captured verbatim in `raw_event` (base64 + sha256 + byte length), even
   on a total parse failure. A parser is never allowed to have a failure
   mode that drops or mutates the source payload — that payload is the
   forensic record and the only thing that makes replay/reprocessing
   possible after a Source Pack bug is fixed.

2. ERRORS ARE DATA, NOT EXCEPTIONS THAT LOSE EVENTS. `ParseError` entries
   accumulate on `ParsedEvent.parse_errors`; they never replace or discard
   the raw payload. `parse_status` tells a downstream consumer how much to
   trust `extracted_fields` (SUCCESS / PARTIAL / FAILED / UNRECOGNIZED)
   without ever making the raw event unavailable.
"""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


# --------------------------------------------------------------------------
# Status / severity vocabulary
# --------------------------------------------------------------------------
class ParseStatus(str, Enum):
    SUCCESS = "success"            # matched a pack, all expected fields extracted cleanly
    PARTIAL = "partial"            # matched a pack, some fields extracted, some missing/malformed
    FAILED = "failed"              # matched a pack, but its parser could not extract anything usable
    UNRECOGNIZED = "unrecognized"  # no Source Pack claimed this payload at all


class ParseErrorSeverity(str, Enum):
    WARNING = "warning"    # e.g. an optional/enrichment field was missing
    ERROR = "error"        # a required field could not be extracted
    CRITICAL = "critical"  # the payload could not be interpreted at all


# --------------------------------------------------------------------------
# Structured parse error — accumulated, never replaces raw_event
# --------------------------------------------------------------------------
class ParseError(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: str = Field(..., description="Stable machine-readable error code, e.g. 'HEADER_NO_MATCH'.")
    message: str = Field(..., description="Human-readable explanation.")
    severity: ParseErrorSeverity = ParseErrorSeverity.ERROR
    field: Optional[str] = Field(default=None, description="Name of the field affected, if applicable.")
    detail: Optional[str] = Field(default=None, description="Extra diagnostic detail (regex tried, exception text, etc).")


# --------------------------------------------------------------------------
# Verbatim raw event capture — immutable, always present
# --------------------------------------------------------------------------
class RawEvent(BaseModel):
    """
    Exact, immutable capture of the bytes a Source Pack was handed.

    Stored as base64 rather than `bytes` directly so this model round-trips
    cleanly through JSON (the framework's on-wire format for parsed-event /
    dead-letter topics) without any encoding ambiguity, and so arbitrary
    binary/garbled payloads (the exact kind of input a poison event
    consists of) can never break serialization of the contract itself.
    """
    model_config = ConfigDict(frozen=True)

    payload_b64: str
    byte_length: int
    sha256: str = Field(..., description="Deterministic content hash — doubles as the framework's event_id.")

    encoding_hint: Optional[str] = Field(default=None, description="Best-guess text encoding, e.g. 'utf-8'.")
    source_topic: Optional[str] = None
    source_partition: Optional[int] = None
    source_offset: Optional[int] = None
    source_key: Optional[str] = None
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def from_bytes(cls, raw: bytes, **kwargs: Any) -> "RawEvent":
        return cls(
            payload_b64=base64.b64encode(raw).decode("ascii"),
            byte_length=len(raw),
            sha256=hashlib.sha256(raw).hexdigest(),
            **kwargs,
        )

    def decoded_text(self, encoding: str = "utf-8", errors: str = "replace") -> str:
        """Best-effort text view. Never the source of truth — `payload_b64` is."""
        return base64.b64decode(self.payload_b64).decode(encoding, errors=errors)


# --------------------------------------------------------------------------
# ParsedEvent — the contract every Source Pack outputs
# --------------------------------------------------------------------------
class ParsedEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    event_id: str = Field(..., description="Deterministic ID — sha256 of the raw payload.")

    vendor: Optional[str] = Field(default=None, description="e.g. 'Cisco'. None if UNRECOGNIZED.")
    product: Optional[str] = Field(default=None, description="e.g. 'ASA'. None if UNRECOGNIZED.")
    source_pack_id: Optional[str] = Field(default=None, description="Registry ID of the pack that handled this event.")
    source_pack_version: Optional[str] = None

    parse_status: ParseStatus
    parse_errors: list[ParseError] = Field(default_factory=list)

    extracted_fields: dict[str, Any] = Field(
        default_factory=dict,
        description="Normalized fields the Source Pack was able to extract. May be partial or empty; "
                    "always safe to trust only as far as parse_status/parse_errors indicate.",
    )

    raw_event: RawEvent = Field(..., description="Verbatim original payload. Always present, never modified.")

    parsed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # -- convenience helpers -----------------------------------------------
    @field_validator("vendor", "product", "source_pack_id", "source_pack_version")
    @classmethod
    def _blank_to_none(cls, v: Optional[str]) -> Optional[str]:
        if isinstance(v, str) and not v.strip():
            return None
        return v

    @property
    def has_errors(self) -> bool:
        return len(self.parse_errors) > 0

    @property
    def is_usable(self) -> bool:
        """SUCCESS or PARTIAL both yield at least some trustworthy extracted_fields."""
        return self.parse_status in (ParseStatus.SUCCESS, ParseStatus.PARTIAL)

    def add_error(
        self,
        code: str,
        message: str,
        *,
        severity: ParseErrorSeverity = ParseErrorSeverity.ERROR,
        field: Optional[str] = None,
        detail: Optional[str] = None,
    ) -> None:
        """
        Record a parse problem without discarding anything already extracted
        or touching raw_event. If this is the first error on an otherwise
        successful parse, status downgrades to PARTIAL (never silently stays
        SUCCESS with a hidden error attached).
        """
        self.parse_errors.append(
            ParseError(code=code, message=message, severity=severity, field=field, detail=detail)
        )
        if self.parse_status == ParseStatus.SUCCESS:
            self.parse_status = ParseStatus.PARTIAL

    # -- standard construction paths ----------------------------------------
    @classmethod
    def unrecognized(cls, raw: bytes, *, reason: str = "no Source Pack matched this payload", **raw_kwargs: Any) -> "ParsedEvent":
        """No pack in the registry claimed this payload. Raw bytes are still preserved."""
        raw_event = RawEvent.from_bytes(raw, **raw_kwargs)
        return cls(
            event_id=raw_event.sha256,
            parse_status=ParseStatus.UNRECOGNIZED,
            raw_event=raw_event,
            parse_errors=[ParseError(code="NO_SOURCE_PACK_MATCH", message=reason, severity=ParseErrorSeverity.WARNING)],
        )

    @classmethod
    def failed(
        cls,
        raw: bytes,
        *,
        vendor: Optional[str],
        product: Optional[str],
        source_pack_id: Optional[str],
        source_pack_version: Optional[str],
        error: ParseError,
        extracted_fields: Optional[dict[str, Any]] = None,
        **raw_kwargs: Any,
    ) -> "ParsedEvent":
        """A pack claimed this payload but could not extract anything usable from it."""
        raw_event = RawEvent.from_bytes(raw, **raw_kwargs)
        return cls(
            event_id=raw_event.sha256,
            vendor=vendor,
            product=product,
            source_pack_id=source_pack_id,
            source_pack_version=source_pack_version,
            parse_status=ParseStatus.FAILED,
            parse_errors=[error],
            extracted_fields=extracted_fields or {},
            raw_event=raw_event,
        )

    @classmethod
    def success(
        cls,
        raw: bytes,
        *,
        vendor: str,
        product: str,
        source_pack_id: str,
        source_pack_version: str,
        extracted_fields: dict[str, Any],
        **raw_kwargs: Any,
    ) -> "ParsedEvent":
        raw_event = RawEvent.from_bytes(raw, **raw_kwargs)
        return cls(
            event_id=raw_event.sha256,
            vendor=vendor,
            product=product,
            source_pack_id=source_pack_id,
            source_pack_version=source_pack_version,
            parse_status=ParseStatus.SUCCESS,
            extracted_fields=extracted_fields,
            raw_event=raw_event,
        )
