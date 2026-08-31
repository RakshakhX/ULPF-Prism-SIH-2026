"""
source_packs/fortinet_fortigate/pack.py

Extends SourcePackBase with FortiGate-specific normalization that goes
beyond simple declarative field mapping:

  1. Timestamp: FortiGate splits date/time across two separate raw fields
     (`date=2026-08-30 time=14:20:00`) rather than one combined value, so
     the declarative `source:` mapping alone can't produce a usable
     datetime. This pack combines them into `ParsedEvent.event_timestamp`
     directly, without needing to modify the core engine's coercion logic.

  2. Severity: FortiGate uses syslog-style severity *names* (emergency,
     alert, critical, error, warning, notice, information, debug) rather
     than the normalized Severity enum values the core engine expects.
     This pack translates them.

  3. Host / message / category promotion: `ParsedEvent.host`,
     `.message`, and `.event_category` are filled from the most relevant
     available FortiGate field (traffic/utm logs carry `msg` rarely,
     event logs carry `logdesc`; category combines `type`+`subtype`).

The declarative `fields` dict itself (see manifest.yaml) is left
untouched by these overrides — it always reflects the raw, unmodified
values extracted per the manifest's field-mapping rules.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from core.models import ParsedEvent, RawEventEnvelope, Severity
from core.source_pack import SourcePackBase

# FortiOS syslog-style severity names -> normalized ULPF Severity
_LEVEL_TO_SEVERITY = {
    "emergency": Severity.CRITICAL,
    "alert": Severity.CRITICAL,
    "critical": Severity.CRITICAL,
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "notice": Severity.MEDIUM,
    "information": Severity.INFO,
    "debug": Severity.INFO,
}


class FortinetFortigatePack(SourcePackBase):
    """FortiGate key=value Source Pack with vendor-specific normalization."""

    def __init__(self, manifest_path: Path = None):
        manifest_path = manifest_path or (Path(__file__).parent / "manifest.yaml")
        super().__init__(manifest_path)

    def parse(self, envelope: RawEventEnvelope) -> ParsedEvent:
        parsed_event = super().parse(envelope)

        # The raw key=value dict is re-derived here (cheap — same parser,
        # same payload) purely to reach `date`/`time`, which aren't part
        # of the declarative fields list (only their combination matters).
        from core.parsers import get_parser
        raw_kv = get_parser(self.format_type).parse(envelope.raw_payload, **self.format_options)

        parsed_event.event_timestamp = self._combine_timestamp(raw_kv.get("date"), raw_kv.get("time"))
        parsed_event.severity = self._map_severity(parsed_event.fields.get("level"))
        parsed_event.host = parsed_event.fields.get("hostname")
        parsed_event.event_category = self._build_category(
            parsed_event.fields.get("event_type"), parsed_event.fields.get("event_subtype")
        )
        parsed_event.message = (
            parsed_event.fields.get("message")
            or parsed_event.fields.get("log_description")
            or parsed_event.fields.get("attack_signature")
        )

        return parsed_event

    # -- helpers --------------------------------------------------------------

    @staticmethod
    def _combine_timestamp(date_str, time_str):
        if not date_str or not time_str:
            return None
        try:
            return datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            return None

    @staticmethod
    def _map_severity(level: str) -> Severity:
        if not level:
            return Severity.UNKNOWN
        return _LEVEL_TO_SEVERITY.get(level.strip().lower(), Severity.UNKNOWN)

    @staticmethod
    def _build_category(event_type, event_subtype):
        if event_type and event_subtype:
            return f"{event_type}.{event_subtype}"
        return event_type
