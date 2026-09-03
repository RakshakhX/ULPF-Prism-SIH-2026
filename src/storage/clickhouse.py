"""ClickHouse row mapping and batch writes for canonical UnifiedEvents."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Protocol

from src.storage.models import EventRow, QuarantineRow, WriteResult
from src.validation.validate_unified_event import validate_event

EVENTS_TABLE = "ulpf.events_v1"
QUARANTINE_TABLE = "ulpf.quarantine_v1"

EVENT_COLUMNS = tuple(EventRow.__dataclass_fields__)
QUARANTINE_COLUMNS = tuple(QuarantineRow.__dataclass_fields__)


class ClickHouseClient(Protocol):
    def insert(self, table: str, data: list[list[Any]], column_names: list[str]) -> None: ...


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("UnifiedEvent timestamp must be a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("UnifiedEvent timestamp must include a timezone")
    return parsed.astimezone(UTC)


def _compact_json(event: dict[str, Any]) -> str:
    return json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def map_unified_event(event: dict[str, Any]) -> EventRow:
    """Project common search columns while retaining the complete normalized JSON."""

    event_meta = event["event"]
    time_meta = event["time"]
    observer = event["observer"]
    action = event["action"]
    severity = event["severity"]
    trace = event["traceability"]
    source = event.get("source", {})
    destination = event.get("destination", {})
    return EventRow(
        event_id=str(event_meta["id"]),
        observed_at=_timestamp(time_meta["observed_at"]),
        ingested_at=_timestamp(time_meta["ingested_at"]),
        normalized_at=_timestamp(time_meta["normalized_at"]),
        vendor=str(observer["vendor"]),
        product=str(observer["product"]),
        category=str(event_meta["category"]),
        event_type=str(event_meta["type"]),
        action=str(action["normalized"]),
        severity=int(severity["normalized"]),
        severity_label=str(severity["label"]),
        source_ip=str(source.get("ip", "")),
        source_port=source.get("port"),
        destination_ip=str(destination.get("ip", "")),
        destination_port=destination.get("port"),
        quality_status=str(event["quality"]["status"]),
        raw_event_id=str(trace["raw_event_id"]),
        raw_sha256=str(trace["raw_sha256"]),
        source_pack_name=str(trace["source_pack"]["name"]),
        source_pack_version=str(trace["source_pack"]["version"]),
        parser_name=str(trace["parser"]["name"]),
        parser_version=str(trace["parser"]["version"]),
        normalized_json=_compact_json(event),
    )


def _values(record: EventRow | QuarantineRow) -> list[Any]:
    values: list[Any] = []
    for field_name in record.__dataclass_fields__:
        value = getattr(record, field_name)
        values.append(list(value) if isinstance(value, tuple) else value)
    return values


def _quarantine(event: dict[str, Any], errors: tuple[str, ...]) -> QuarantineRow:
    trace = event.get("traceability", {})
    return QuarantineRow(
        event_id=str(event.get("event", {}).get("id", "")),
        raw_sha256=str(trace.get("raw_sha256", "")),
        payload_json=_compact_json(event),
        error_codes=errors,
        quarantined_at=datetime.now(UTC),
    )


class ClickHouseEventStore:
    """Write schema-valid events and isolate invalid records in quarantine."""

    def __init__(self, client: ClickHouseClient) -> None:
        self.client = client

    def write_batch(self, events: list[dict[str, Any]]) -> WriteResult:
        valid_rows: list[EventRow] = []
        quarantine_rows: list[QuarantineRow] = []
        for event in events:
            validation = validate_event(event)
            quality_status = event.get("quality", {}).get("status")
            if validation.valid and quality_status != "invalid":
                valid_rows.append(map_unified_event(event))
                continue
            codes = tuple(f"{issue.path}:{issue.rule}" for issue in validation.issues)
            if quality_status == "invalid":
                codes += ("$.quality.status:invalid",)
            quarantine_rows.append(_quarantine(event, codes))

        valid_count = 0
        quarantine_count = 0
        failed_count = 0
        errors: list[str] = []
        if valid_rows:
            try:
                self.client.insert(
                    EVENTS_TABLE,
                    [_values(row) for row in valid_rows],
                    list(EVENT_COLUMNS),
                )
                valid_count = len(valid_rows)
            except Exception as error:
                failed_count += len(valid_rows)
                errors.append(str(error))
        if quarantine_rows:
            try:
                self.client.insert(
                    QUARANTINE_TABLE,
                    [_values(row) for row in quarantine_rows],
                    list(QUARANTINE_COLUMNS),
                )
                quarantine_count = len(quarantine_rows)
            except Exception as error:
                failed_count += len(quarantine_rows)
                errors.append(str(error))

        return WriteResult(
            accepted_count=valid_count + quarantine_count,
            valid_count=valid_count,
            quarantine_count=quarantine_count,
            failed_count=failed_count,
            errors=tuple(errors),
        )
