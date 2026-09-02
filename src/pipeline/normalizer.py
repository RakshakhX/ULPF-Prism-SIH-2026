"""Compatibility entry point backed by the canonical universal normalizer."""

from __future__ import annotations

import base64
from datetime import UTC
from typing import Any
from uuid import UUID

from core.cisco_asa_pack import ParsedEvent as CiscoParsedEvent
from core.models import ParsedEvent as CoreParsedEvent
from src.contracts import (
    ParsedEvent,
    ParseIssue,
    ParseIssueSeverity,
    ParseStatus,
    RawEventEnvelope,
)
from src.normalization import UniversalNormalizer, default_registry

_STATUS_BY_VALUE = {
    "success": ParseStatus.SUCCESS,
    "partial": ParseStatus.PARTIAL,
    "failed": ParseStatus.FAILED,
    "error": ParseStatus.FAILED,
    "unrecognized": ParseStatus.UNRECOGNIZED,
    "unparsed_fallback": ParseStatus.UNRECOGNIZED,
}


def _canonical_from_legacy(parsed: CiscoParsedEvent | CoreParsedEvent) -> ParsedEvent:
    """Adapt old in-process models without adding or guessing source data."""

    if isinstance(parsed, CiscoParsedEvent):
        raw_bytes = base64.b64decode(parsed.raw_event.payload_b64)
        source_pack_id = parsed.source_pack_id
        source_pack_version = parsed.source_pack_version
        vendor = parsed.vendor
        product = parsed.product
        status_value = parsed.parse_status.value
        extracted = dict(parsed.extracted_fields)
        issue_values = [
            (error.code, error.message, error.severity.value, error.field)
            for error in parsed.parse_errors
        ]
        parsed_at = parsed.parsed_at
        legacy_event_id = parsed.event_id
    else:
        raw_bytes = parsed.raw_event.raw_payload.encode("utf-8")
        source_pack_id = parsed.source_pack_id
        source_pack_version = parsed.pack_version
        vendor = parsed.vendor
        product = parsed.product
        status_value = parsed.status.value
        extracted = dict(parsed.fields)
        issue_values = [("LEGACY_PARSE_ERROR", message, "error", None) for message in parsed.errors]
        parsed_at = parsed.parsed_at
        legacy_event_id = parsed.event_id

    if source_pack_id == "cisco_asa":
        parser_id = "cisco.asa.syslog"
    else:
        parser_id = "unknown.legacy_parser"
        issue_values.append(
            (
                "LEGACY_PARSER_PROVENANCE_UNKNOWN",
                "Legacy parsed input did not record parser identity",
                "warning",
                None,
            )
        )

    raw_event = RawEventEnvelope.from_bytes(
        raw_bytes,
        source_id=source_pack_id or "legacy-source",
        transport="api",
        collector_id="legacy-pipeline-adapter",
        collector_version="1.0.0",
    )
    try:
        preserved_event_id = UUID(str(legacy_event_id))
    except ValueError:
        extracted["_legacy_event_id"] = str(legacy_event_id)
        issue_values.append(
            (
                "LEGACY_EVENT_ID_NOT_UUID",
                "Legacy event ID was preserved in extensions because it is not a UUID",
                "warning",
                "event_id",
            )
        )
    else:
        raw_event = raw_event.model_copy(update={"event_id": preserved_event_id})
    issues = tuple(
        ParseIssue(
            code=code,
            message=message,
            severity=ParseIssueSeverity(severity),
            field=field,
        )
        for code, message, severity, field in issue_values
    )
    return ParsedEvent(
        event_id=raw_event.event_id,
        parsed_at=parsed_at if parsed_at.tzinfo is not None else parsed_at.replace(tzinfo=UTC),
        vendor=vendor,
        product=product,
        product_version=None,
        parser_id=parser_id,
        parser_version=source_pack_version or "0.0.0",
        source_pack_id=source_pack_id,
        source_pack_version=source_pack_version,
        detected_format="syslog" if source_pack_id == "cisco_asa" else "unknown",
        status=_STATUS_BY_VALUE.get(status_value, ParseStatus.FAILED),
        issues=issues,
        extracted_fields=extracted,
        raw_event=raw_event,
    )


def normalize_cisco_asa_event(
    parsed: CiscoParsedEvent | CoreParsedEvent | ParsedEvent | dict[str, Any],
) -> dict[str, Any]:
    """Normalize old or canonical parsed input through one lossless path."""

    if isinstance(parsed, (CiscoParsedEvent, CoreParsedEvent)):
        parsed = _canonical_from_legacy(parsed)
    if not isinstance(parsed, ParsedEvent):
        raise ValueError(f"Unsupported parsed event type: {type(parsed)}")
    return UniversalNormalizer(default_registry()).normalize(parsed)
