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
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from core.models import ParseErrorSeverity, ParseStatus
from src.contracts import (
    ParsedEvent as CanonicalParsedEvent,
)
from src.contracts import (
    ParseIssue as CanonicalParseIssue,
)
from src.contracts import (
    ParseIssueSeverity as CanonicalIssueSeverity,
)
from src.contracts import (
    ParseStatus as CanonicalParseStatus,
)
from src.contracts import (
    RawEventEnvelope as CanonicalRawEventEnvelope,
)

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
        raise ValueError(
            "message body does not match the expected 302013/302014 "
            "(connection built/teardown) layout"
        )
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
    field: str | None = None
    detail: str | None = None


class RawEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    payload_b64: str
    byte_length: int
    sha256: str
    encoding_hint: str | None = None
    source_topic: str | None = None
    source_partition: int | None = None
    source_offset: int | None = None
    source_key: str | None = None
    received_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @classmethod
    def from_bytes(cls, raw: bytes, **kwargs: Any) -> RawEvent:
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
    vendor: str | None = None
    product: str | None = None
    source_pack_id: str | None = None
    source_pack_version: str | None = None
    parse_status: ParseStatus
    parse_errors: list[ParseError] = Field(default_factory=list)
    extracted_fields: dict[str, Any] = Field(default_factory=dict)
    raw_event: RawEvent
    parsed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def has_errors(self) -> bool:
        return bool(self.parse_errors)

    def add_error(
        self,
        code: str,
        message: str,
        *,
        severity: ParseErrorSeverity = ParseErrorSeverity.ERROR,
        field: str | None = None,
        detail: str | None = None,
    ) -> None:
        self.parse_errors.append(
            ParseError(code=code, message=message, severity=severity, field=field, detail=detail)
        )
        if self.parse_status == ParseStatus.SUCCESS:
            self.parse_status = ParseStatus.PARTIAL

    @classmethod
    def unrecognized(
        cls,
        raw: bytes,
        *,
        reason: str = "no Source Pack matched this payload",
        **raw_kwargs: Any,
    ) -> ParsedEvent:
        raw_event = RawEvent.from_bytes(raw, **raw_kwargs)
        return cls(
            event_id=raw_event.sha256,
            parse_status=ParseStatus.UNRECOGNIZED,
            parse_errors=[
                ParseError(
                    code="NO_SOURCE_PACK_MATCH",
                    message=reason,
                    severity=ParseErrorSeverity.WARNING,
                )
            ],
            raw_event=raw_event,
        )

    @classmethod
    def failed(
        cls,
        raw: bytes,
        *,
        vendor: str | None,
        product: str | None,
        source_pack_id: str | None,
        source_pack_version: str | None,
        error: ParseError,
        extracted_fields: dict[str, Any] | None = None,
        **raw_kwargs: Any,
    ) -> ParsedEvent:
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
    ) -> ParsedEvent:
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
        best_pack: SourcePack | None = None
        best_confidence = 0.0
        detection_notes: list[str] = []

        for pack in self._packs.values():
            try:
                result = pack.detect(raw)
            except Exception as exc:  # pragma: no cover - defensive path
                detection_notes.append(f"{pack.metadata.pack_id}: detect() raised {exc!r}")
                continue

            if result.matched:
                detection_notes.append(
                    f"{pack.metadata.pack_id}: confidence={result.confidence:.2f} "
                    f"({result.reason})"
                )
                if result.confidence > best_confidence:
                    best_pack = pack
                    best_confidence = result.confidence

        if best_pack is None or best_confidence < self.min_confidence:
            reason = (
                "no registered Source Pack matched"
                if not detection_notes
                else (
                    f"no match above min_confidence={self.min_confidence}: "
                    f"{'; '.join(detection_notes)}"
                )
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
                    message=(
                        f"Source Pack '{best_pack.metadata.pack_id}' "
                        f"raised during parse(): {exc}"
                    ),
                    severity=ParseErrorSeverity.CRITICAL,
                    detail=repr(exc),
                ),
                **context,
            )

        return parsed


class CiscoASASourcePack(SourcePack):
    """Vendor: Cisco. Product: ASA. Parses fixed-format ASA syslog messages."""

    pack_id = PACK_ID
    priority = 100

    def __init__(self, manifest_path=None) -> None:
        self.manifest_path = manifest_path

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

    def detect(
        self,
        envelope: CanonicalRawEventEnvelope | bytes,
    ) -> float | DetectionResult:
        """Detect ASA input using the canonical or transitional legacy API.

        The source-pack registry passes a :class:`RawEventEnvelope` and expects
        a numeric confidence.  The existing demo runner still passes bytes and
        expects ``DetectionResult``; keeping that adapter here prevents the
        contract migration from breaking the working vertical slice.
        """

        raw = envelope if isinstance(envelope, bytes) else envelope.raw_bytes()
        confidence = self._detection_confidence(raw)

        if isinstance(envelope, bytes):
            return DetectionResult(
                matched=confidence > 0.0,
                confidence=confidence,
                reason="Cisco ASA message tag detected" if confidence else "no ASA tag detected",
            )
        return confidence

    @staticmethod
    def _detection_confidence(raw: bytes) -> float:
        text = raw.decode("utf-8", errors="replace")

        if _ASA_TAG_RE.search(text):
            return 0.98

        if "ASA-" in text and re.search(r"ASA-\d-\d{6}", text):
            return 0.4

        return 0.0

    def parse(
        self,
        envelope: CanonicalRawEventEnvelope | bytes,
        **context: Any,
    ) -> CanonicalParsedEvent | ParsedEvent:
        """Parse with the canonical contract while adapting legacy byte callers."""

        if isinstance(envelope, bytes):
            canonical_envelope = CanonicalRawEventEnvelope.from_bytes(
                envelope,
                source_id=str(context.get("source_id", "legacy-cisco-runner")),
                transport="api",
            )
            canonical_event = self._parse_canonical(canonical_envelope)
            return self._to_legacy_event(canonical_event, envelope)

        return self._parse_canonical(envelope)

    def _parse_canonical(
        self,
        envelope: CanonicalRawEventEnvelope,
    ) -> CanonicalParsedEvent:
        raw = envelope.raw_bytes()
        text = raw.decode("utf-8", errors="replace")

        header_match = _HEADER_RE.match(text.strip())
        if not header_match:
            return self._canonical_event(
                envelope,
                CanonicalParseStatus.FAILED,
                {},
                (
                    CanonicalParseIssue(
                    code="ASA_HEADER_NO_MATCH",
                        message="Payload does not match the Cisco ASA syslog header grammar",
                        severity=CanonicalIssueSeverity.ERROR,
                    ),
                ),
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

        issues: list[CanonicalParseIssue] = []
        status = CanonicalParseStatus.SUCCESS

        message_parser = _MESSAGE_PARSERS.get(header["message_id"])
        if message_parser is None:
            status = CanonicalParseStatus.PARTIAL
            issues.append(
                CanonicalParseIssue(
                    code="ASA_UNKNOWN_MESSAGE_ID",
                    message=f"No parser registered for ASA message ID {header['message_id']}",
                    severity=CanonicalIssueSeverity.WARNING,
                    field="message_id",
                )
            )
        else:
            try:
                extracted.update(message_parser(header["message"]))
            except ValueError as exc:
                status = CanonicalParseStatus.PARTIAL
                issues.append(
                    CanonicalParseIssue(
                        code="ASA_MESSAGE_BODY_NO_MATCH",
                        message=str(exc),
                        severity=CanonicalIssueSeverity.ERROR,
                        field="message",
                    )
                )

        return self._canonical_event(envelope, status, extracted, tuple(issues))

    @staticmethod
    def _to_legacy_event(
        event: CanonicalParsedEvent,
        raw: bytes,
    ) -> ParsedEvent:
        """Translate canonical output for the pre-migration demo normalizer."""

        status_map = {
            CanonicalParseStatus.SUCCESS: ParseStatus.SUCCESS,
            CanonicalParseStatus.PARTIAL: ParseStatus.PARTIAL,
            CanonicalParseStatus.FAILED: ParseStatus.FAILED,
            CanonicalParseStatus.UNRECOGNIZED: ParseStatus.UNRECOGNIZED,
        }
        severity_map = {
            CanonicalIssueSeverity.WARNING: ParseErrorSeverity.WARNING,
            CanonicalIssueSeverity.ERROR: ParseErrorSeverity.ERROR,
            CanonicalIssueSeverity.CRITICAL: ParseErrorSeverity.CRITICAL,
        }

        return ParsedEvent(
            event_id=str(event.event_id),
            vendor=event.vendor,
            product=event.product,
            source_pack_id=event.source_pack_id,
            source_pack_version=event.source_pack_version,
            parse_status=status_map[event.status],
            parse_errors=[
                ParseError(
                    code=issue.code,
                    message=issue.message,
                    severity=severity_map[issue.severity],
                    field=issue.field,
                )
                for issue in event.issues
            ],
            extracted_fields=dict(event.extracted_fields),
            raw_event=RawEvent.from_bytes(raw),
            parsed_at=event.parsed_at,
        )

    def _canonical_event(
        self,
        envelope: CanonicalRawEventEnvelope,
        status: CanonicalParseStatus,
        extracted_fields: dict[str, Any],
        issues: tuple[CanonicalParseIssue, ...],
    ) -> CanonicalParsedEvent:
        from datetime import UTC

        return CanonicalParsedEvent(
            event_id=envelope.event_id,
            parsed_at=datetime.now(UTC),
            vendor="Cisco",
            product="ASA",
            product_version=None,
            parser_id="cisco.asa.syslog",
            parser_version=PACK_VERSION,
            source_pack_id=PACK_ID,
            source_pack_version=PACK_VERSION,
            detected_format="syslog",
            status=status,
            issues=issues,
            extracted_fields=extracted_fields,
            raw_event=envelope,
        )


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
            b"<166>Oct 12 2023 14:23:10 asa-fw1 : %ASA-5-999999: "
            b"Some future message format we do not know yet"
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
