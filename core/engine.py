"""
core/engine.py

The ULPF core parsing engine. Workflow per envelope:

    RawEventEnvelope
        -> Source detection      (registry.match)
        -> Source Pack selection (highest-priority matching pack)
        -> Format parser          (pack.parse -> core.parsers.get_parser)
        -> Field extraction       (pack's declarative field rules)
        -> ParsedEvent

If no pack matches, or the matched pack raises during parsing, the engine
falls back to FallbackParser so a ParsedEvent is *always* produced and the
pipeline never crashes or silently drops data on unrecognized/malformed
input.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from core.exceptions import ULPFError
from core.models import LogFormat, ParsedEvent, ParsingStatus, RawEventEnvelope
from core.parsers.fallback import FallbackParser
from core.registry import SourcePackRegistry

logger = logging.getLogger("ulpf.engine")


class ParsingEngine:
    def __init__(self, packs_dir: Path | str = "source_packs"):
        self.registry = SourcePackRegistry(Path(packs_dir))
        self._fallback_parser = FallbackParser()

    def reload_packs(self) -> None:
        self.registry.reload()

    def process(self, envelope: RawEventEnvelope) -> ParsedEvent:
        """
        Process a single RawEventEnvelope end-to-end. Never raises — any
        failure downgrades to a fallback ParsedEvent so upstream callers
        (queue consumers, HTTP handlers) don't need defensive try/except
        around every call.
        """
        pack = None
        try:
            pack = self.registry.match(envelope)
        except Exception as exc:  # detection itself blew up
            logger.error("Source detection failed for event %s: %s", envelope.event_id, exc)

        if pack is None:
            logger.debug("No Source Pack matched event %s — using fallback parser", envelope.event_id)
            return self._fallback_event(envelope, reason="no_matching_source_pack")

        try:
            return pack.parse(envelope)
        except ULPFError as exc:
            logger.warning(
                "Source Pack '%s' failed to parse event %s: %s", pack.pack_id, envelope.event_id, exc
            )
            return self._fallback_event(envelope, reason=str(exc), pack_id=pack.pack_id)
        except Exception as exc:  # truly unexpected — still never crash the engine
            logger.exception(
                "Unexpected error in Source Pack '%s' for event %s", pack.pack_id, envelope.event_id
            )
            return self._fallback_event(envelope, reason=f"unexpected_error: {exc}", pack_id=pack.pack_id)

    def _fallback_event(
        self, envelope: RawEventEnvelope, reason: str, pack_id: Optional[str] = None
    ) -> ParsedEvent:
        parsed_dict = self._fallback_parser.parse(envelope.raw_payload)
        return ParsedEvent(
            event_id=envelope.event_id,
            source_pack_id=pack_id,
            format_detected=LogFormat.UNKNOWN,
            message=parsed_dict.get("message"),
            fields=parsed_dict,
            status=ParsingStatus.UNPARSED_FALLBACK,
            errors=[reason],
            raw_event=envelope,
        )
