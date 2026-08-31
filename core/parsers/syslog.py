"""
core/parsers/syslog.py

Handles the two syslog header dialects seen in the wild:

  RFC 3164 (BSD syslog):
    <34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8
    <PRI>MMM DD HH:MM:SS HOSTNAME TAG: MSG

  RFC 5424:
    <34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed
    <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict

from core.exceptions import FormatParsingError
from core.parsers.base import BaseFormatParser

_PRI_RE = re.compile(r"^<(?P<pri>\d{1,3})>")

_RFC5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d)\s"
    r"(?P<timestamp>\S+)\s"
    r"(?P<hostname>\S+)\s"
    r"(?P<appname>\S+)\s"
    r"(?P<procid>\S+)\s"
    r"(?P<msgid>\S+)\s"
    r"(?P<structured_data>(-|\[.*?\](?:\[.*?\])*))\s?"
    r"(?P<message>.*)$"
)

# RFC3164: <PRI>Mmm dd hh:mm:ss host tag[pid]: message
_RFC3164_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s"
    r"(?P<hostname>\S+)\s"
    r"(?P<tag>[^:\[\s]+)"
    r"(?:\[(?P<pid>\d+)\])?"
    r":?\s?"
    r"(?P<message>.*)$"
)


class SyslogParser(BaseFormatParser):
    format_name = "syslog"

    def can_parse(self, raw_payload: str, **options: Any) -> bool:
        return bool(_PRI_RE.match(raw_payload.strip()))

    def parse(self, raw_payload: str, **options: Any) -> Dict[str, Any]:
        text = raw_payload.strip()

        m5424 = _RFC5424_RE.match(text)
        if m5424:
            data = m5424.groupdict()
            pri = int(data["pri"])
            data["facility"] = pri // 8
            data["severity_code"] = pri % 8
            data["variant"] = "rfc5424"
            return data

        m3164 = _RFC3164_RE.match(text)
        if m3164:
            data = m3164.groupdict()
            pri = int(data["pri"])
            data["facility"] = pri // 8
            data["severity_code"] = pri % 8
            data["variant"] = "rfc3164"
            data["appname"] = data.get("tag")
            data["procid"] = data.get("pid")
            return data

        raise FormatParsingError(f"Payload does not match RFC3164 or RFC5424 syslog header: {text[:80]!r}")

    @staticmethod
    def severity_code_to_name(code: int) -> str:
        # Standard syslog severity levels (0=Emergency .. 7=Debug)
        mapping = {
            0: "critical", 1: "critical", 2: "critical",
            3: "high", 4: "medium", 5: "medium",
            6: "info", 7: "info",
        }
        return mapping.get(code, "unknown")
