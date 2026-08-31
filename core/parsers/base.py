"""
core/parsers/base.py

All format parsers implement this interface. A format parser's only job is
to turn a raw string into a flat-ish dict of structured data — it knows
nothing about vendors, Source Packs, or field-mapping semantics. That
separation is what lets the same JSON parser, for instance, be reused by
many different Source Packs.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseFormatParser(ABC):
    """Interface every format parser (syslog, json, kv, csv, cef, regex...) implements."""

    #: Machine-readable name matching core.models.LogFormat where applicable.
    format_name: str = "unknown"

    @abstractmethod
    def parse(self, raw_payload: str, **options: Any) -> Dict[str, Any]:
        """
        Parse raw_payload into a dict of extracted key/value data.

        Must raise core.exceptions.FormatParsingError (or a subclass) on
        failure rather than returning partial/garbage data silently — the
        engine relies on the exception to decide when to fall back.
        """
        raise NotImplementedError

    def can_parse(self, raw_payload: str, **options: Any) -> bool:
        """
        Cheap best-effort check used during format auto-detection. Default
        implementation tries a full parse and reports success/failure;
        subclasses are encouraged to override with a cheaper heuristic
        (e.g. a leading-character check) when possible.
        """
        try:
            self.parse(raw_payload, **options)
            return True
        except Exception:
            return False
