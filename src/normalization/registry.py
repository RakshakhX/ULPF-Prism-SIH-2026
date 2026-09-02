"""Versioned registry for Source Pack normalization mappings."""

from __future__ import annotations

from src.normalization.models import NormalizationMapping


class NormalizationRegistry:
    def __init__(self) -> None:
        self._mappings: dict[str, NormalizationMapping] = {}

    def register(self, mapping: NormalizationMapping) -> None:
        source_pack_id = mapping.source_pack_id
        if source_pack_id in self._mappings:
            raise ValueError(f"mapping already registered for {source_pack_id}")
        self._mappings[source_pack_id] = mapping

    def get(self, source_pack_id: str | None) -> NormalizationMapping | None:
        if source_pack_id is None:
            return None
        return self._mappings.get(source_pack_id)

    @property
    def source_pack_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._mappings))
