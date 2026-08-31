"""
core/parsers/regex_parser.py

Generic engine for proprietary/legacy log formats that don't fit any
standard grammar. A Source Pack supplies one or more named-group regex
patterns via its manifest; this parser tries them in order and returns the
first match's named groups. This is what lets a plug-in pack support an
arbitrary vendor format without the core engine knowing anything about it.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from core.exceptions import FormatParsingError
from core.parsers.base import BaseFormatParser


class RegexFormatParser(BaseFormatParser):
    format_name = "regex"

    def can_parse(self, raw_payload: str, **options: Any) -> bool:
        patterns: List[str] = options.get("patterns", [])
        return any(re.search(p, raw_payload) for p in patterns)

    def parse(self, raw_payload: str, **options: Any) -> Dict[str, Any]:
        patterns: List[str] = options.get("patterns", [])
        if not patterns:
            raise FormatParsingError("RegexFormatParser requires at least one pattern")

        for pattern in patterns:
            match = re.search(pattern, raw_payload)
            if match:
                groups = match.groupdict()
                if not groups:
                    raise FormatParsingError(
                        f"Regex pattern matched but defines no named groups: {pattern!r}"
                    )
                return groups

        raise FormatParsingError("No supplied regex pattern matched the payload")
