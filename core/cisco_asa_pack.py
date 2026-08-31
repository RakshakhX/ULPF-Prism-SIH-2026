#!/usr/bin/env python3
"""
cisco_asa_pack.py — Cisco ASA syslog Source Pack

This implementation is intentionally compatible with both the repository's
legacy source-pack contract and the modern core contract used in the current
branch. The file avoids hard dependencies on missing legacy modules and keeps
all the lossless parse/error semantics the issue expects.
"""
from __future__ import annotations

import base64
import hashlib
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from pydantic import BaseModel, ConfigDict, Field

from core.models import ParseErrorSeverity, ParseStatus

PACK_ID = "cisco_asa"
PACK_VERSION = "1.0.0"

# ASA syslog severities follow standard syslog numbering (0=emergency .. 7=debug)
_SEVERITY_NAMES = {
    0: "emergency",
    1: "alert",
    2: "critical",
    3: "error",
    4: "warning",
    5: "notice",
    6: "informational",
    7: "debug",
}

# -- detection --------------------------------------------------------------
_ASA_TAG_RE = re.compile(r"%ASA-\d-\d{6}:")

# -- full header parse --------------------------------------------------------
_HEADER_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>\s*)?"
    r"(?:(?P<timestamp>[A-Za-z]{3}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2})\s+)?"
    r"(?:(?P<hostname>\S+)\s*:\s*)?"
    r"%ASA-(?P<severity>\d)-(?P<message_id>\d{6}):\s*"
    r"(?P<message>.*)$"
)

# -- message-ID-specific field extractors ------------------------------------
_DENY_106023_RE = re.compile(
    r"^(?P<action>Deny)\s+(?P<protocol>\S+)\s+src\s+"
    r"(?P<src_interface>\S+):(?P<src_ip>[0-9a-fA-F.:]+)(?:/(?P<src_port>\d+))?\s+"
    r"dst\s+(?P<dst_interface>\S+):(?P<dst_ip>[0-9a-fA-F.:]+)(?:/(?P<dst_port>\d+))?\s+"
    r'by\s+access-group\s+"(?P<acl_name>[^"]+)"'
)

_TEARDOWN_302013_302014_RE = re.compile(
    r"^(?P<action>Built|Teardown)\s+(?P<direction>inbound|outbound)\s+"
    r"(?P<protocol>\S+)\s+connection\s+(?P<connection_id>\d+)\s+for\s+"
    r"(?P<src_interface>\S+):(?P<src_ip>[0-9a-fA-F.:]+)/(?P<src_port>\d+)\s*"
    r"(?:\([^)]*\))?\s*to\s+"
    r"(?P<dst_interface>\S+):(?P<dst_ip>[0-9a-fA-F.:]+)/(?P<dst_port>\d+)"
)

_ACL_106100_RE = re.compile(
    r'^access-list\s+(?P<acl_name>\S+)\s+(?P<action>permitted|denied)\s+'
    r"(?P<protocol>\S+)\s+(?P<src_interface>\S+)/(?P<src_ip>[0-9a-fA-F.:]+)"
    r"\((?P<src_port>\d+)\)\s*->\s*"
    r"(?P<dst_interface>\S+)/(?P<dst_ip>[0-9a-fA-F.:]+)\((?P<dst_port>\d+)\)"
)


def _parse_106023(message: str) -> dict[str, Any]:
    match = _DENY_106023_RE.match(message)
    if not match:
        raise ValueError("message body does not match the expected 106023 (ACL deny) layout")
    fields = match.groupdict()
    fields["event_type"] = "acl_deny"
    return fields


def _parse_302013_302014(message: str) -> dict[str, Any]:
    match = _TEARDOWN_302013_302014_RE.match(message)
    if not match:
        raise ValueError("message body does not match the expected 302013/302014 (connection built/teardown) layout")
    fields = match.groupdict()
    fields["event_type"] = "connection_lifecycle"
    return fields


def _parse_106100(message: str) -> dict[str, Any]:
    match = _ACL_106100_RE.match(message)
    if not match:
        raise ValueError("message body does not match the expected 106100 (ACL hit) layout")
    fields = match.groupdict()
    fields["event_type"] = "acl_hit"
    return fields


_MESSAGE_PARSERS: dict[str, Callable[[str], dict[str, Any]]] = {
    "106023": _parse_106023,
    "302013": _parse_302013_302014,
    "302014": _parse_302013_302014,
    "106100": _parse_106100,
}


@dataclass(frozen=True)
class DetectionResult:
    matched: bool
    confidence: float
    reason: str = ""


class SourcePackMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)

    pack_id: str
    vendor: str
    product: str
    version: str
    description: str = ""
    supported_versions: list[str] = Field(default_factory=list)
    supported_formats: list[str] = Field(default_factory=list)


class ParseError(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: str
    message: str
    severity: ParseErrorSeverity = ParseErrorSeverity.ERROR
    field: Optional[str] = None
    detail: Optional[str] = None


class RawEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    payload_b64: str
    byte_length: int
    sha256: str
    encoding_hint: Optional[str] = None
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
        return base64.b64decode(self.payload_b64).decode(encoding, errors=errors)


class ParsedEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    event_id: str
    vendor: Optional[str] = None
    product: Optional[str] = None
    source_pack_id: Optional[str] = None
    source_pack_version: Optional[str] = None
    parse_status: ParseStatus
    parse_errors: list[ParseError] = Field(default_factory=list)
    extracted_fields: dict[str, Any] = Field(default_factory=dict)
    raw_event: RawEvent
    parsed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def has_errors(self) -> bool:
        return bool(self.parse_errors)

    def add_error(
        self,
        code: str,
        message: str,
        *,
        severity: ParseErrorSeverity = ParseErrorSeverity.ERROR,
        field: Optional[str] = None,
        detail: Optional[str] = None,
    ) -> None:
        self.parse_errors.append(
            ParseError(code=code, message=message, severity=severity, field=field, detail=detail)
        )
        if self.parse_status == ParseStatus.SUCCESS:
            self.parse_status = ParseStatus.PARTIAL

    @classmethod
    def unrecognized(cls, raw: bytes, *, reason: str = "no Source Pack matched this payload", **raw_kwargs: Any) -> "ParsedEvent":
        raw_event = RawEvent.from_bytes(raw, **raw_kwargs)
        return cls(
            event_id=raw_event.sha256,
            parse_status=ParseStatus.UNRECOGNIZED,
            parse_errors=[ParseError(code="NO_SOURCE_PACK_MATCH", message=reason, severity=ParseErrorSeverity.WARNING)],
            raw_event=raw_event,
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


class SourcePack(ABC):
    @property
    @abstractmethod
    def metadata(self) -> SourcePackMetadata: ...

    @abstractmethod
    def detect(self, raw: bytes) -> DetectionResult: ...

    @abstractmethod
    def parse(self, raw: bytes, **context) -> ParsedEvent: ...


class SourcePackRegistry:
    def __init__(self, min_confidence: float = 0.5):
        self._packs: dict[str, SourcePack] = {}
        self.min_confidence = min_confidence

    def register(self, pack: SourcePack) -> None:
        pack_id = pack.metadata.pack_id
        if pack_id in self._packs:
            raise ValueError(f"a Source Pack with id={pack_id!r} is already registered")
        self._packs[pack_id] = pack

    def route(self, raw: bytes, **context) -> ParsedEvent:
        best_pack: Optional[SourcePack] = None
        best_confidence = 0.0
        detection_notes: list[str] = []

        for pack in self._packs.values():
            try:
                result = pack.detect(raw)
            except Exception as exc:  # pragma: no cover - defensive path
                detection_notes.append(f"{pack.metadata.pack_id}: detect() raised {exc!r}")
                continue

            if result.matched:
                detection_notes.append(f"{pack.metadata.pack_id}: confidence={result.confidence:.2f} ({result.reason})")
                if result.confidence > best_confidence:
                    best_pack = pack
                    best_confidence = result.confidence

        if best_pack is None or best_confidence < self.min_confidence:
            reason = (
                "no registered Source Pack matched"
                if not detection_notes
                else f"no match above min_confidence={self.min_confidence}: {'; '.join(detection_notes)}"
            )
            return ParsedEvent.unrecognized(raw, reason=reason, **context)

        try:
            parsed = best_pack.parse(raw, **context)
        except Exception as exc:
            return ParsedEvent.failed(
                raw,
                vendor=best_pack.metadata.vendor,
                product=best_pack.metadata.product,
                source_pack_id=best_pack.metadata.pack_id,
                source_pack_version=best_pack.metadata.version,
                error=ParseError(
                    code="SOURCE_PACK_EXCEPTION",
                    message=f"Source Pack '{best_pack.metadata.pack_id}' raised during parse(): {exc}",
                    severity=ParseErrorSeverity.CRITICAL,
                    detail=repr(exc),
                ),
                **context,
            )

        return parsed


class CiscoASASourcePack(SourcePack):
    """Vendor: Cisco. Product: ASA. Parses fixed-format ASA syslog messages."""

    @property
    def metadata(self) -> SourcePackMetadata:
        return SourcePackMetadata(
            pack_id=PACK_ID,
            vendor="Cisco",
            product="ASA",
            version=PACK_VERSION,
            description="Parses Cisco ASA syslog (%ASA-<severity>-<message_id>: ...) messages...",
            supported_versions=["*"],
            supported_formats=["Syslog"],
        )

    def detect(self, raw: bytes) -> DetectionResult:
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            return DetectionResult(matched=False, confidence=0.0, reason="undecodable payload")

        if _ASA_TAG_RE.search(text):
            return DetectionResult(matched=True, confidence=0.98, reason="found %ASA-N-NNNNNN: tag")

        if "ASA-" in text and re.search(r"ASA-\d-\d{6}", text):
            return DetectionResult(matched=True, confidence=0.4, reason="found degraded ASA-N-NNNNNN tag (missing '%')")

        return DetectionResult(matched=False, confidence=0.0, reason="no ASA syslog tag found")

    def parse(self, raw: bytes, **context) -> ParsedEvent:
        try:
            text = raw.decode("utf-8")
            encoding_hint = "utf-8"
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
            encoding_hint = "utf-8 (replaced invalid bytes)"

        header_match = _HEADER_RE.match(text.strip())
        if not header_match:
            return ParsedEvent.failed(
                raw,
                vendor=self.metadata.vendor,
                product=self.metadata.product,
                source_pack_id=self.metadata.pack_id,
                source_pack_version=self.metadata.version,
                error=ParseError(
                    code="ASA_HEADER_NO_MATCH",
                    message="Payload matched ASA detection but did not match the expected '%ASA-<severity>-<message_id>: <message>' header grammar.",
                    severity=ParseErrorSeverity.CRITICAL,
                    detail=text[:200],
                ),
                encoding_hint=encoding_hint,
                **context,
            )

        header = header_match.groupdict()
        severity_int = int(header["severity"])
        extracted: dict[str, Any] = {
            "priority": header.get("pri"),
            "timestamp_raw": header.get("timestamp"),
            "hostname": header.get("hostname"),
            "severity": severity_int,
            "severity_name": _SEVERITY_NAMES.get(severity_int, "unknown"),
            "message_id": header["message_id"],
            "message_text": header["message"],
        }

        event = ParsedEvent.success(
            raw,
            vendor=self.metadata.vendor,
            product=self.metadata.product,
            source_pack_id=self.metadata.pack_id,
            source_pack_version=self.metadata.version,
            extracted_fields=extracted,
            encoding_hint=encoding_hint,
            **context,
        )

        message_parser = _MESSAGE_PARSERS.get(header["message_id"])
        if message_parser is None:
            event.add_error(
                code="ASA_UNKNOWN_MESSAGE_ID",
                message=f"No field-layout parser registered for ASA message ID {header['message_id']}; only header fields were extracted.",
                severity=ParseErrorSeverity.WARNING,
                field="message_id",
            )
            return event

        try:
            detail_fields = message_parser(header["message"])
            event.extracted_fields.update(detail_fields)
        except ValueError as exc:
            event.add_error(
                code="ASA_MESSAGE_BODY_NO_MATCH",
                message=str(exc),
                severity=ParseErrorSeverity.ERROR,
                field="message",
                detail=header["message"][:200],
            )

        return event


if __name__ == "__main__":
    import json

    registry = SourcePackRegistry()
    registry.register(CiscoASASourcePack())

    samples = {
        "well-formed 106023 deny": (
            b'<166>Oct 12 2023 14:23:01 asa-fw1 : %ASA-4-106023: Deny tcp src '
            b'outside:203.0.113.5/54321 dst inside:10.0.0.5/443 by access-group "OUTSIDE_IN"'
        ),
        "well-formed 302013 built": (
            b'<166>Oct 12 2023 14:23:05 asa-fw1 : %ASA-6-302013: Built inbound TCP connection '
            b'123456 for outside:203.0.113.5/54321 (203.0.113.5/54321) to inside:10.0.0.5/443'
        ),
        "known tag, unknown message id": (
            b'<166>Oct 12 2023 14:23:10 asa-fw1 : %ASA-5-999999: Some future message format we do not know yet'
        ),
        "known tag, malformed body": (
            b'<166>Oct 12 2023 14:23:15 asa-fw1 : %ASA-4-106023: this is not a deny line at all'
        ),
        "not ASA at all": (
            b'<134>1 2023-10-12T14:23:20Z fw-edge filterlog 1 - - 5,,,100,igb0,match,pass,in'
        ),
        "garbage bytes": b"\x00\x01\xff\xfe not even text \x80\x81",
    }

    for label, raw in samples.items():
        parsed = registry.route(raw, source_topic="raw-event")
        print(f"--- {label} ---")
        print(json.dumps(parsed.model_dump(mode="json"), indent=2, default=str))
        print()
