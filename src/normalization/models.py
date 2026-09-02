"""Contracts shared by vendor mappings and the universal normalizer."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from src.contracts import ParsedEvent


@dataclass(frozen=True)
class MappingResult:
    """Vendor mapping output before common provenance and quality assembly."""

    event: dict[str, Any]
    observer: dict[str, Any]
    action: dict[str, Any]
    severity: dict[str, Any]
    source: dict[str, Any] | None = None
    destination: dict[str, Any] | None = None
    network: dict[str, Any] | None = None
    threat: dict[str, Any] | None = None
    authentication: dict[str, Any] | None = None
    http: dict[str, Any] | None = None
    observed_at: datetime | None = None
    consumed_fields: frozenset[str] = field(default_factory=frozenset)
    missing_fields: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


class NormalizationMapping(Protocol):
    """Plug-in boundary for one Source Pack's normalization rules."""

    source_pack_id: str
    version: str

    def map(self, event: ParsedEvent) -> MappingResult: ...
