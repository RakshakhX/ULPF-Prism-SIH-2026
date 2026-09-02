"""Versioned registry for Source Pack normalization mappings."""

from __future__ import annotations

import re

from src.normalization.models import NormalizationMapping

_SOURCE_PACK_ID = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")
_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


class NormalizationRegistry:
    def __init__(self) -> None:
        self._mappings: dict[str, NormalizationMapping] = {}

    def register(self, mapping: NormalizationMapping) -> None:
        source_pack_id = getattr(mapping, "source_pack_id", None)
        version = getattr(mapping, "version", None)
        if not isinstance(source_pack_id, str) or not _SOURCE_PACK_ID.fullmatch(source_pack_id):
            raise ValueError("mapping source_pack_id must be lowercase snake_case")
        if not isinstance(version, str) or not _SEMVER.fullmatch(version):
            raise ValueError("mapping version must be semantic version X.Y.Z")
        if not callable(getattr(mapping, "map", None)):
            raise ValueError("mapping must provide callable map()")
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
