"""
core/parsers/json_parser.py

Straightforward JSON parser. Handles the common enterprise-logging quirk of
a JSON object being preceded by a syslog-style header (e.g. some firewalls
emit "<134>Oct 11 ... app: {json here}") by locating the first '{' or '['.
"""

from __future__ import annotations

import json
from typing import Any, Dict

from core.exceptions import FormatParsingError
from core.parsers.base import BaseFormatParser


class JSONFormatParser(BaseFormatParser):
    format_name = "json"

    def can_parse(self, raw_payload: str, **options: Any) -> bool:
        stripped = raw_payload.strip()
        return stripped.startswith("{") or stripped.startswith("[") or ("{" in stripped and "}" in stripped)

    def parse(self, raw_payload: str, **options: Any) -> Dict[str, Any]:
        text = raw_payload.strip()

        # Fast path: whole payload is JSON.
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
            return {"value": parsed}
        except json.JSONDecodeError:
            pass

        # Slow path: strip a leading non-JSON prefix (e.g. syslog header)
        # and try again from the first '{'.
        brace_index = text.find("{")
        if brace_index == -1:
            raise FormatParsingError("No JSON object found in payload")

        candidate = text[brace_index:]
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
            return {"value": parsed}
        except json.JSONDecodeError as exc:
            raise FormatParsingError(f"Payload is not valid JSON: {exc}") from exc
