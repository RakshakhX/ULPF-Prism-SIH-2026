"""ClickHouse row mapping and batch writes for canonical UnifiedEvents."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import unquote, urlparse

from src.storage.models import EventRow, QuarantineRow, WriteResult
from src.validation.validate_unified_event import validate_event

EVENTS_TABLE = "ulpf.events_v1"
QUARANTINE_TABLE = "ulpf.quarantine_v1"

EVENT_COLUMNS = tuple(EventRow.__dataclass_fields__)
QUARANTINE_COLUMNS = tuple(QuarantineRow.__dataclass_fields__)


class ClickHouseClient(Protocol):
    def insert(self, table: str, data: list[list[Any]], column_names: list[str]) -> None: ...

    def query(self, query: str, parameters: dict[str, Any] | None = None) -> Any: ...


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

    def quarantine_payload(self, payload: bytes, error_code: str) -> WriteResult:
        """Persist bytes that cannot be decoded as a UnifiedEvent JSON object."""

        row = QuarantineRow(
            event_id="",
            raw_sha256="",
            payload_json=payload.decode("utf-8", errors="replace"),
            error_codes=(error_code,),
            quarantined_at=datetime.now(UTC),
        )
        try:
            self.client.insert(
                QUARANTINE_TABLE,
                [_values(row)],
                list(QUARANTINE_COLUMNS),
            )
        except Exception as error:
            return WriteResult(0, 0, 0, 1, (str(error),))
        return WriteResult(1, 0, 1, 0)

    def search(
        self,
        *,
        query: str | None = None,
        vendor: str | None = None,
        category: str | None = None,
        action: str | None = None,
        severity: str | None = None,
        quality_status: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Search projected fields while binding every caller-controlled value."""

        clauses: list[str] = []
        parameters: dict[str, Any] = {}
        filters = {
            "vendor": vendor,
            "category": category,
            "action": action,
            "severity_label": severity,
            "quality_status": quality_status,
        }
        for column, value in filters.items():
            if value is None or value.lower() == "all":
                continue
            parameter = "severity" if column == "severity_label" else column
            clauses.append(f"lowerUTF8({column}) = lowerUTF8({{{parameter}:String}})")
            parameters[parameter] = value
        if query:
            clauses.append("positionCaseInsensitive(normalized_json, {query:String}) > 0")
            parameters["query"] = query
        if start_time is not None:
            clauses.append("observed_at >= {start_time:DateTime64(6)}")
            parameters["start_time"] = start_time
        if end_time is not None:
            clauses.append("observed_at < {end_time:DateTime64(6)}")
            parameters["end_time"] = end_time
        parameters["limit"] = min(max(limit, 1), 500)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        statement = (
            f"SELECT normalized_json FROM {EVENTS_TABLE} FINAL{where} "
            "ORDER BY observed_at DESC LIMIT {limit:UInt32}"
        )
        result = self.client.query(statement, parameters=parameters)
        return [json.loads(row[0]) for row in result.result_rows]

    def get_by_event_id(self, event_id: str) -> dict[str, Any] | None:
        return self._one(
            f"SELECT normalized_json FROM {EVENTS_TABLE} FINAL "
            "WHERE event_id = {event_id:UUID} ORDER BY normalized_at DESC LIMIT 1",
            {"event_id": event_id},
        )

    def get_by_raw_hash(self, raw_sha256: str) -> dict[str, Any] | None:
        return self._one(
            f"SELECT normalized_json FROM {EVENTS_TABLE} FINAL "
            "WHERE raw_sha256 = {raw_sha256:String} ORDER BY normalized_at DESC LIMIT 1",
            {"raw_sha256": raw_sha256},
        )

    @property
    def event_count(self) -> int:
        """Count logical event IDs rather than physical replacement rows."""

        result = self.client.query(f"SELECT uniqExact(event_id) FROM {EVENTS_TABLE}")
        return int(result.result_rows[0][0]) if result.result_rows else 0

    def list_events(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return recent valid normalized events for data-lake export."""

        return self.search(limit=limit)

    def get_aggregations(self) -> dict[str, Any]:
        """Return the same dashboard projection as the in-memory demo store."""

        summary = self.client.query(
            f"SELECT uniqExact(event_id), "
            "countIf(action IN ('allow', 'connect', 'authenticate')), "
            "countIf(action IN ('deny', 'block')) "
            f"FROM {EVENTS_TABLE} FINAL"
        ).result_rows
        total, allow_count, deny_count = summary[0] if summary else (0, 0, 0)

        sources_result = self.client.query(
            f"SELECT vendor, product, count() FROM {EVENTS_TABLE} FINAL "
            "GROUP BY vendor, product ORDER BY count() DESC"
        ).result_rows
        severity_result = self.client.query(
            f"SELECT severity_label, count() FROM {EVENTS_TABLE} FINAL "
            "GROUP BY severity_label"
        ).result_rows
        quality_result = self.client.query(
            f"SELECT quality_status, count() FROM {EVENTS_TABLE} FINAL "
            "GROUP BY quality_status"
        ).result_rows

        decisions = int(allow_count) + int(deny_count)
        allow_percent = (int(allow_count) / decisions * 100) if decisions else 0.0
        deny_percent = (int(deny_count) / decisions * 100) if decisions else 0.0
        severities = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
            "unknown": 0,
        }
        severities.update({str(label): int(count) for label, count in severity_result})
        quality = {"valid": 0, "partial": 0, "invalid": 0, "unknown": 0}
        quality.update({str(status): int(count) for status, count in quality_result})
        return {
            "total_events": int(total),
            "events_by_source": {
                f"{vendor} {product}": int(count)
                for vendor, product, count in sources_result
            },
            "allow_vs_deny": {
                "allow_count": int(allow_count),
                "deny_count": int(deny_count),
                "allow_percent": round(allow_percent, 1),
                "deny_percent": round(deny_percent, 1),
            },
            "severity_distribution": severities,
            "quality_metrics": quality,
        }

    def _one(self, statement: str, parameters: dict[str, Any]) -> dict[str, Any] | None:
        result = self.client.query(statement, parameters=parameters)
        if not result.result_rows:
            return None
        return json.loads(result.result_rows[0][0])


def create_clickhouse_client(url: str) -> ClickHouseClient:
    """Create the official client from one explicit HTTP(S) endpoint."""

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("ULPF_CLICKHOUSE_URL must be an http:// or https:// endpoint")
    try:
        import clickhouse_connect
    except ImportError as error:  # pragma: no cover - depends on optional installation
        raise RuntimeError("install the 'storage' extra to use ClickHouse") from error

    database = parsed.path.strip("/") or "ulpf"
    return clickhouse_connect.get_client(
        host=parsed.hostname,
        port=parsed.port or (8443 if parsed.scheme == "https" else 8123),
        username=unquote(parsed.username) if parsed.username else "default",
        password=unquote(parsed.password) if parsed.password else "",
        database=database,
        secure=parsed.scheme == "https",
    )
