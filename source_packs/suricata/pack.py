"""Strict, lossless parser for supported Suricata EVE JSON families."""

from __future__ import annotations

import ipaddress
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.exceptions import FormatParsingError
from core.source_pack import SourcePackBase
from src.contracts import (
    ParsedEvent,
    ParseIssue,
    ParseIssueSeverity,
    ParseStatus,
    RawEventEnvelope,
)

SUPPORTED_EVENT_TYPES = frozenset({"alert", "flow", "dns", "http"})


class SuricataEveSourcePack(SourcePackBase):
    """Parse supported EVE records and retain their complete decoded object."""

    def __init__(self, manifest_path: Path | None = None) -> None:
        super().__init__(manifest_path or Path(__file__).with_name("manifest.yaml"))

    def parse(self, envelope: RawEventEnvelope) -> ParsedEvent:
        try:
            payload = json.loads(envelope.raw_bytes().decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise FormatParsingError(f"Suricata EVE payload is not valid JSON: {error}") from error
        if not isinstance(payload, dict):
            raise FormatParsingError("Suricata EVE payload must be a JSON object")

        issues = self._validate(payload)
        fields = self._extract_fields(payload)
        return ParsedEvent(
            event_id=envelope.event_id,
            parsed_at=datetime.now(UTC),
            vendor=self.vendor,
            product=self.product,
            product_version=self._text(payload.get("suricata_version")),
            parser_id="suricata.eve.json",
            parser_version="1.0.0",
            source_pack_id=self.pack_id,
            source_pack_version=self.pack_version,
            detected_format="json",
            status=ParseStatus.FAILED if issues else ParseStatus.SUCCESS,
            issues=tuple(issues),
            extracted_fields=fields,
            raw_event=envelope,
        )

    @staticmethod
    def _text(value: Any) -> str | None:
        return value if isinstance(value, str) and value else None

    @staticmethod
    def _issue(code: str, message: str, field: str) -> ParseIssue:
        return ParseIssue(
            code=code,
            message=message,
            severity=ParseIssueSeverity.ERROR,
            field=field,
        )

    def _validate(self, payload: dict[str, Any]) -> list[ParseIssue]:
        issues: list[ParseIssue] = []
        event_type = payload.get("event_type")
        if event_type not in SUPPORTED_EVENT_TYPES:
            issues.append(
                self._issue(
                    "SURICATA_EVENT_TYPE_INVALID",
                    "event_type must be one of alert, flow, dns or http",
                    "event_type",
                )
            )

        timestamp = payload.get("timestamp")
        if not isinstance(timestamp, str):
            issues.append(
                self._issue("SURICATA_TIMESTAMP_MISSING", "timestamp is required", "timestamp")
            )
        else:
            try:
                parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                if parsed_timestamp.tzinfo is None:
                    raise ValueError("timezone is required")
            except ValueError:
                issues.append(
                    self._issue(
                        "SURICATA_TIMESTAMP_INVALID",
                        "timestamp must be an ISO 8601 value with timezone",
                        "timestamp",
                    )
                )

        for field_name in ("src_ip", "dest_ip"):
            value = payload.get(field_name)
            try:
                if not isinstance(value, str):
                    raise ValueError
                ipaddress.ip_address(value)
            except ValueError:
                issues.append(
                    self._issue(
                        "SURICATA_IP_INVALID",
                        f"{field_name} must be a valid IPv4 or IPv6 address",
                        field_name,
                    )
                )

        for field_name in ("src_port", "dest_port"):
            if field_name not in payload:
                continue
            value = payload[field_name]
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535:
                issues.append(
                    self._issue(
                        "SURICATA_PORT_INVALID",
                        f"{field_name} must be an integer from 0 to 65535",
                        field_name,
                    )
                )

        if event_type in SUPPORTED_EVENT_TYPES and not isinstance(payload.get(event_type), dict):
            issues.append(
                self._issue(
                    "SURICATA_EVENT_BODY_MISSING",
                    f"{event_type} event body must be a JSON object",
                    str(event_type),
                )
            )
        return issues

    @staticmethod
    def _extract_fields(payload: dict[str, Any]) -> dict[str, Any]:
        fields = {"eve": payload}
        for name in (
            "timestamp",
            "flow_id",
            "event_type",
            "src_ip",
            "src_port",
            "dest_ip",
            "dest_port",
            "proto",
            "app_proto",
            "direction",
            "in_iface",
            "out_iface",
            "community_id",
            "suricata_version",
            "alert",
            "flow",
            "dns",
            "http",
        ):
            if name in payload:
                fields[name] = payload[name]
        return fields
