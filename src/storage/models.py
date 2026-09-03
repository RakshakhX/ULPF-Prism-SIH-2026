"""Transport-neutral analytical storage records and write accounting."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class EventRow:
    event_id: str
    observed_at: datetime
    ingested_at: datetime
    normalized_at: datetime
    vendor: str
    product: str
    category: str
    event_type: str
    action: str
    severity: int
    severity_label: str
    source_ip: str
    source_port: int | None
    destination_ip: str
    destination_port: int | None
    quality_status: str
    raw_event_id: str
    raw_sha256: str
    source_pack_name: str
    source_pack_version: str
    parser_name: str
    parser_version: str
    normalized_json: str


@dataclass(frozen=True)
class QuarantineRow:
    event_id: str
    raw_sha256: str
    payload_json: str
    error_codes: tuple[str, ...]
    quarantined_at: datetime


@dataclass(frozen=True)
class WriteResult:
    accepted_count: int
    valid_count: int
    quarantine_count: int
    failed_count: int
    errors: tuple[str, ...] = ()
