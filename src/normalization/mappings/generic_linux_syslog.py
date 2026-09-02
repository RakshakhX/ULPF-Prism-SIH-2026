"""Generic Linux Syslog to UnifiedEvent mapping."""

from __future__ import annotations

from src.contracts import ParsedEvent
from src.normalization.mappings.common import event_type, syslog_severity
from src.normalization.models import MappingResult


class GenericLinuxSyslogMapping:
    source_pack_id = "generic_linux_syslog"
    version = "1.0.0"

    def map(self, event: ParsedEvent) -> MappingResult:
        fields = event.extracted_fields
        severity, warnings = syslog_severity(fields.get("severity"))
        hostname = fields.get("hostname")
        process = fields.get("process")
        observer = {"type": "unknown"}
        if isinstance(hostname, str) and hostname:
            observer["hostname"] = hostname

        event_section = {
            "category": "system",
            "type": event_type(process, "system_log"),
            "name": f"Linux Syslog{f' ({process})' if process else ''}",
        }
        missing: list[str] = []
        message = fields.get("message")
        if isinstance(message, str) and message:
            event_section["message"] = message
        else:
            missing.append("event.message")

        return MappingResult(
            event=event_section,
            observer=observer,
            action={"original": "unknown", "normalized": "unknown", "outcome": "unknown"},
            severity=severity,
            consumed_fields=frozenset({"hostname", "process", "message", "severity"}),
            missing_fields=tuple(missing),
            warnings=warnings,
        )
