#!/usr/bin/env python3
"""
source_pack.py — ULPF Source Pack framework

Defines the plugin contract every vendor/product parser ("Source Pack")
implements, plus a `SourcePackRegistry` that performs detection-based
routing: given raw bytes, ask every registered pack how confident it is
that it owns this payload, route to the best match, and — critically —
never let a pack's own bug turn into a lost event. A pack that raises
during `parse()` is caught by the registry and converted into a `FAILED`
`ParsedEvent` with the raw payload still attached, exactly like a pack
that returns a clean `FAILED` result itself.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict

from models import ParseError, ParseErrorSeverity, ParsedEvent

log = logging.getLogger("ulpf.source_pack")


class SourcePackMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)

    pack_id: str          
    vendor: str            
    product: str            
    version: str            
    description: str = ""
    # Add these two lines:
    supported_versions: list[str] = Field(default_factory=list)
    supported_formats: list[str] = Field(default_factory=list)


@dataclass(frozen=True)
class DetectionResult:
    matched: bool
    confidence: float   # 0.0-1.0; registry picks the highest-confidence match above threshold
    reason: str = ""


class SourcePack(ABC):
    """
    Base class every vendor/product parser implements.

    Contract:
      * `metadata` — static identity of this pack (vendor/product/version).
      * `detect(raw)` — cheap, side-effect-free check: "could this pack own
        this payload?" Must NOT raise; return DetectionResult(matched=False)
        on anything it isn't sure about. Detection is deliberately separate
        from parsing so the registry can cheaply poll every pack without
        paying full parse cost, and so a low-confidence match from one pack
        doesn't shadow a high-confidence match from another.
      * `parse(raw, **context)` — does the actual extraction. MAY raise;
        the registry guarantees a raised exception here still results in a
        well-formed FAILED ParsedEvent with the raw payload intact. A pack
        implementation is still encouraged to catch its own known failure
        modes and return `ParsedEvent.failed(...)` directly so it can
        attach a precise error code instead of a generic one.
    """

    @property
    @abstractmethod
    def metadata(self) -> SourcePackMetadata: ...

    @abstractmethod
    def detect(self, raw: bytes) -> DetectionResult: ...

    @abstractmethod
    def parse(self, raw: bytes, **context) -> ParsedEvent: ...


class SourcePackRegistry:
    """
    Holds every registered Source Pack and performs detection-based routing.

    `route()` is the single entry point the framework's worker should call:
    it always returns a well-formed ParsedEvent, never raises, and never
    drops the raw payload — regardless of whether zero packs matched, the
    matched pack's parser raised, or everything worked perfectly.
    """

    def __init__(self, min_confidence: float = 0.5):
        self._packs: dict[str, SourcePack] = {}
        self.min_confidence = min_confidence

    def register(self, pack: SourcePack) -> None:
        pack_id = pack.metadata.pack_id
        if pack_id in self._packs:
            raise ValueError(f"a Source Pack with id={pack_id!r} is already registered")
        self._packs[pack_id] = pack
        log.info("registered source pack: %s (%s %s v%s)",
                 pack_id, pack.metadata.vendor, pack.metadata.product, pack.metadata.version)

    def route(self, raw: bytes, **context) -> ParsedEvent:
        best_pack: SourcePack | None = None
        best_confidence = 0.0
        detection_notes: list[str] = []

        for pack in self._packs.values():
            try:
                result = pack.detect(raw)
            except Exception as e:  # detect() must never take down routing
                log.exception("detect() raised in pack=%s — treating as no match", pack.metadata.pack_id)
                detection_notes.append(f"{pack.metadata.pack_id}: detect() raised {e!r}")
                continue

            if result.matched:
                detection_notes.append(f"{pack.metadata.pack_id}: confidence={result.confidence:.2f} ({result.reason})")
                if result.confidence > best_confidence:
                    best_pack, best_confidence = pack, result.confidence

        if best_pack is None or best_confidence < self.min_confidence:
            reason = (
                "no registered Source Pack matched"
                if not detection_notes
                else f"no match above min_confidence={self.min_confidence}: {'; '.join(detection_notes)}"
            )
            return ParsedEvent.unrecognized(raw, reason=reason, **context)

        try:
            parsed = best_pack.parse(raw, **context)
        except Exception as e:
            # A bug inside a pack's parser must never lose the event. Convert
            # it into a well-formed FAILED ParsedEvent with the raw payload
            # still attached, same as if the pack had handled it itself.
            log.exception("parse() raised in pack=%s for a payload it claimed to own",
                          best_pack.metadata.pack_id)
            return ParsedEvent.failed(
                raw,
                vendor=best_pack.metadata.vendor,
                product=best_pack.metadata.product,
                source_pack_id=best_pack.metadata.pack_id,
                source_pack_version=best_pack.metadata.version,
                error=ParseError(
                    code="SOURCE_PACK_EXCEPTION",
                    message=f"Source Pack '{best_pack.metadata.pack_id}' raised during parse(): {e}",
                    severity=ParseErrorSeverity.CRITICAL,
                    detail=repr(e),
                ),
                **context,
            )

        return parsed
