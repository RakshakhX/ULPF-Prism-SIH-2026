"""
source_packs/generic_linux_syslog/pack.py

For most packs, the declarative manifest.yaml is sufficient and
core.source_pack.SourcePackBase is used as-is (the registry loads it
directly — see core/registry.py). This file exists to show the extension
point: a pack can subclass SourcePackBase to add custom logic (e.g. vendor-
specific severity translation, timestamp normalization, or multi-step
parsing) that goes beyond simple declarative field mapping.

To activate a custom pack class instead of the generic base, the registry
would import this module and instantiate GenericLinuxSyslogPack instead of
SourcePackBase. This starter pack keeps default behavior but demonstrates
the override pattern with a small enhancement: mapping syslog facility
codes to human-readable names.
"""

from __future__ import annotations

from pathlib import Path

from core.source_pack import SourcePackBase
from src.contracts import ParsedEvent, RawEventEnvelope

_FACILITY_NAMES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth",
    5: "syslog", 6: "lpr", 7: "news", 8: "uucp", 9: "cron",
    10: "authpriv", 11: "ftp", 16: "local0", 17: "local1",
    18: "local2", 19: "local3", 20: "local4", 21: "local5",
    22: "local6", 23: "local7",
}


class GenericLinuxSyslogPack(SourcePackBase):
    """Adds a human-readable facility name on top of the generic base behavior."""

    def __init__(self, manifest_path: Path = None):
        manifest_path = manifest_path or (Path(__file__).parent / "manifest.yaml")
        super().__init__(manifest_path)

    def parse(self, envelope: RawEventEnvelope) -> ParsedEvent:
        parsed_event = super().parse(envelope)
        fields = dict(parsed_event.extracted_fields)
        facility_code = fields.get("syslog_facility")
        if isinstance(facility_code, str) and facility_code.isdigit():
            facility_code = int(facility_code)
        if isinstance(facility_code, int):
            fields["syslog_facility_name"] = _FACILITY_NAMES.get(facility_code, "unknown")
        return parsed_event.model_copy(update={"extracted_fields": fields})
