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

from datetime import UTC, datetime
from pathlib import Path

from core.source_pack import SourcePackBase
from src.contracts import ParsedEvent, RawEventEnvelope

# FortiOS syslog-style severity names -> normalized ULPF Severity
_LEVEL_TO_SEVERITY = {
    "emergency": "critical",
    "alert": "critical",
    "critical": "critical",
    "error": "high",
    "warning": "medium",
    "notice": "medium",
    "information": "info",
    "debug": "info",
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
        raw_text = envelope.raw_bytes().decode("utf-8", errors="replace")
        raw_kv = get_parser(self.format_type).parse(raw_text, **self.format_options)

        fields = dict(parsed_event.extracted_fields)
        timestamp = self._combine_timestamp(raw_kv.get("date"), raw_kv.get("time"))
        if timestamp is not None:
            fields["event_timestamp"] = timestamp.isoformat()
        fields["severity_normalized"] = self._map_severity(fields.get("level"))
        fields["event_category_normalized"] = self._build_category(
            fields.get("event_type"), fields.get("event_subtype")
        )
        return parsed_event.model_copy(update={"extracted_fields": fields})

    # -- helpers --------------------------------------------------------------

    @staticmethod
    def _combine_timestamp(date_str, time_str):
        if not date_str or not time_str:
            return None
        try:
            return datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=UTC
            )
        except ValueError:
            return None

    @staticmethod
    def _map_severity(level: str) -> str:
        if not level:
            return "unknown"
        return _LEVEL_TO_SEVERITY.get(level.strip().lower(), "unknown")

    @staticmethod
    def _build_category(event_type, event_subtype):
        if event_type and event_subtype:
            return f"{event_type}.{event_subtype}"
        return event_type
