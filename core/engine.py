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

from core.exceptions import ULPFError
from core.registry import SourcePackRegistry
from src.contracts import (
    ParsedEvent,
    ParseIssue,
    ParseIssueSeverity,
    ParseStatus,
    RawEventEnvelope,
)

logger = logging.getLogger("ulpf.engine")


class ParsingEngine:
    def __init__(self, packs_dir: Path | str = "source_packs"):
        self.registry = SourcePackRegistry(Path(packs_dir))

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
            logger.debug(
                "No Source Pack matched event %s — using fallback parser",
                envelope.event_id,
            )
            return ParsedEvent.unrecognized(envelope, "no matching source pack")

        try:
            return pack.parse(envelope)
        except ULPFError as exc:
            logger.warning(
                "Source Pack '%s' failed to parse event %s: %s",
                pack.pack_id,
                envelope.event_id,
                exc,
            )
            return self._failed_event(envelope, str(exc), pack.pack_id)
        except Exception as exc:  # truly unexpected — still never crash the engine
            logger.exception(
                "Unexpected error in Source Pack '%s' for event %s", pack.pack_id, envelope.event_id
            )
            return self._failed_event(envelope, f"unexpected_error: {exc}", pack.pack_id)

    def _failed_event(
        self, envelope: RawEventEnvelope, reason: str, pack_id: str
    ) -> ParsedEvent:
        from datetime import UTC, datetime

        return ParsedEvent(
            event_id=envelope.event_id,
            parsed_at=datetime.now(UTC),
            vendor=None,
            product=None,
            product_version=None,
            parser_id="ulpf.source-pack-registry",
            parser_version="1.0.0",
            source_pack_id=pack_id,
            source_pack_version=None,
            detected_format="unknown",
            status=ParseStatus.FAILED,
            issues=(
                ParseIssue(
                    code="SOURCE_PACK_FAILED",
                    message=reason,
                    severity=ParseIssueSeverity.ERROR,
                ),
            ),
            raw_event=envelope,
        )
