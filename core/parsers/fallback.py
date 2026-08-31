"""
core/parsers/fallback.py

Last-resort parser. Never raises. Guarantees the engine can always produce
a ParsedEvent — with the full raw text preserved as `message` — instead of
dropping or crashing on logs nothing recognizes.
"""

from __future__ import annotations

from typing import Any, Dict

from core.parsers.base import BaseFormatParser


class FallbackParser(BaseFormatParser):
    format_name = "unknown"

    def can_parse(self, raw_payload: str, **options: Any) -> bool:
        return True  # always accepts — this is the parser of last resort

    def parse(self, raw_payload: str, **options: Any) -> Dict[str, Any]:
        return {"message": raw_payload}
