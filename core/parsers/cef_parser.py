"""
core/parsers/cef_parser.py

Common Event Format (ArcSight CEF), used widely by security appliances:

  CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

  Example:
  CEF:0|Palo Alto Networks|PAN-OS|10.1|threat|Suspicious DNS Query|5|src=10.0.0.1 dst=8.8.8.8 act=allowed

The pipe-delimited header fields may contain escaped pipes (\\|); the
Extension is a key=value block (reuses the same grammar as kv_parser).
"""

from __future__ import annotations

import re
from typing import Any, Dict

from core.exceptions import FormatParsingError
from core.parsers.base import BaseFormatParser
from core.parsers.kv_parser import KeyValueParser

_HEADER_FIELDS = [
    "cef_version",
    "device_vendor",
    "device_product",
    "device_version",
    "signature_id",
    "name",
    "severity",
]

_UNESCAPED_PIPE_SPLIT = re.compile(r"(?<!\\)\|")


class CEFFormatParser(BaseFormatParser):
    format_name = "cef"

    def __init__(self) -> None:
        self._kv_parser = KeyValueParser()

    def can_parse(self, raw_payload: str, **options: Any) -> bool:
        return raw_payload.strip().startswith("CEF:")

    def parse(self, raw_payload: str, **options: Any) -> Dict[str, Any]:
        text = raw_payload.strip()
        if not text.startswith("CEF:"):
            raise FormatParsingError("Payload is not a CEF event (missing 'CEF:' prefix)")

        body = text[len("CEF:"):]
        parts = _UNESCAPED_PIPE_SPLIT.split(body, maxsplit=7)

        if len(parts) < 8:
            raise FormatParsingError(
                f"CEF payload does not have the required 8 pipe-delimited fields (found {len(parts)})"
            )

        result: Dict[str, Any] = {}
        for field_name, value in zip(_HEADER_FIELDS, parts[:7]):
            result[field_name] = value.replace("\\|", "|")

        extension = parts[7]
        try:
            result["extension"] = self._kv_parser.parse(extension)
        except FormatParsingError:
            # Extension block is technically optional/malformed in some
            # devices — don't fail the whole event over it.
            result["extension"] = {}

        return result
