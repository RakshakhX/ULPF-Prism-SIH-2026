"""
core/models.py

Data contracts for the Universal Log Pre-processing Framework (ULPF).

RawEventEnvelope  -> what the collection layer hands to the engine.
ParsedEvent       -> what the engine hands downstream, after a Source Pack
                     has normalized the raw payload into structured fields.

Pydantic is used (rather than plain dataclasses) because these models sit at
a system boundary: we want validation, JSON-schema export, and easy
serialization for message-bus transport (Kafka/SQS/etc).
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# --------------------------------------------------------------------------
# Enums
# --------------------------------------------------------------------------

class LogFormat(str, enum.Enum):
    SYSLOG = "syslog"
    JSON = "json"
    KEY_VALUE = "key_value"
    CSV = "csv"
    CEF = "cef"
    REGEX = "regex"
    UNKNOWN = "unknown"


class ParsingStatus(str, enum.Enum):
    SUCCESS = "success"
    PARTIAL = "partial"          # some fields extracted, some rules failed
    UNPARSED_FALLBACK = "unparsed_fallback"  # no pack matched / parser errored
    ERROR = "error"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


# --------------------------------------------------------------------------
# Input contract
# --------------------------------------------------------------------------

class RawEventEnvelope(BaseModel):
    """
    The unit of work handed to the engine by the collection layer.
    `raw_payload` is intentionally kept as a raw string (collectors are
    responsible for decoding bytes -> str with the right encoding) so the
    engine never has to guess encodings.
    """

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    raw_payload: str
    source_ip: Optional[str] = None
    collector_id: Optional[str] = None
    listener_port: Optional[int] = None

    # Optional hints the collector may already know (e.g. it listened on a
    # syslog UDP port, or received a webhook with Content-Type: application/json).
    # Source Packs use these as *hints*, not hard truths.
    content_type_hint: Optional[str] = None
    vendor_hint: Optional[str] = None
    product_hint: Optional[str] = None

    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("raw_payload")
    @classmethod
    def _not_empty(cls, v: str) -> str:
        if v is None:
            raise ValueError("raw_payload cannot be None")
        return v


# --------------------------------------------------------------------------
# Output contract
# --------------------------------------------------------------------------

class ParsedEvent(BaseModel):
    """
    Normalized output of the parsing engine. `fields` carries the
    source-pack-specific extracted attributes (a flat, namespaced dict),
    while common/normalized top-level attributes are promoted for
    cross-source correlation (timestamp, severity, host, etc).

    `raw_event` preserves the original envelope so downstream consumers
    (SIEM, enrichment, storage) can always fall back to source-of-truth data.
    """

    event_id: str
    parsed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Routing / provenance
    source_pack_id: Optional[str] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    pack_version: Optional[str] = None
    format_detected: LogFormat = LogFormat.UNKNOWN

    # Normalized common fields (best-effort, may be None)
    event_timestamp: Optional[datetime] = None
    host: Optional[str] = None
    severity: Severity = Severity.UNKNOWN
    event_category: Optional[str] = None
    message: Optional[str] = None

    # Source-specific extracted attributes, namespaced e.g. {"syslog.pid": "1234"}
    fields: Dict[str, Any] = Field(default_factory=dict)

    # Processing outcome
    status: ParsingStatus = ParsingStatus.SUCCESS
    errors: List[str] = Field(default_factory=list)

    # Full original envelope preserved for traceability / replay
    raw_event: RawEventEnvelope

    model_config = {
        "json_encoders": {datetime: lambda dt: dt.isoformat()}
    }
