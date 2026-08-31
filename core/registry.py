"""
core/registry.py

Discovers Source Packs on disk (source_packs/<pack_dir>/manifest.yaml),
loads them, and matches an incoming RawEventEnvelope to the best pack.

This is the "plug-and-play" mechanism: dropping a new, valid pack directory
into source_packs/ and restarting (or calling `reload()`) is enough for the
engine to start routing matching events to it — no core code changes.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

from core.exceptions import SourcePackLoadError, SourcePackValidationError
from core.models import RawEventEnvelope
from core.source_pack import SourcePackBase

logger = logging.getLogger("ulpf.registry")


class SourcePackRegistry:
    def __init__(self, packs_dir: Path):
        self.packs_dir = Path(packs_dir)
        self._packs: List[SourcePackBase] = []
        self.reload()

    def reload(self) -> None:
        """(Re)scan packs_dir and load every valid Source Pack found."""
        loaded: List[SourcePackBase] = []

        if not self.packs_dir.exists():
            logger.warning("Source pack directory does not exist: %s", self.packs_dir)
            self._packs = []
            return

        for entry in sorted(self.packs_dir.iterdir()):
            manifest_path = entry / "manifest.yaml"
            if not entry.is_dir() or not manifest_path.exists():
                continue
            try:
                pack = SourcePackBase(manifest_path)
                loaded.append(pack)
                logger.info(
                    "Loaded Source Pack '%s' (%s / %s, v%s)",
                    pack.pack_id, pack.vendor, pack.product, pack.pack_version,
                )
            except (SourcePackValidationError, SourcePackLoadError, Exception) as exc:
                # A single broken pack must never take down the engine or
                # prevent other packs from loading.
                logger.error("Failed to load Source Pack at %s: %s", manifest_path, exc)

        # Highest detection priority first so more-specific packs (e.g. a
        # vendor-specific CEF pack) get first shot before generic ones.
        loaded.sort(key=lambda p: p.priority, reverse=True)
        self._packs = loaded

    @property
    def packs(self) -> List[SourcePackBase]:
        return list(self._packs)

    def get_pack(self, pack_id: str) -> Optional[SourcePackBase]:
        for pack in self._packs:
            if pack.pack_id == pack_id:
                return pack
        return None

    def match(self, envelope: RawEventEnvelope) -> Optional[SourcePackBase]:
        """Return the highest-priority pack whose detection rules match, or None."""
        for pack in self._packs:
            try:
                if pack.detect(envelope):
                    return pack
            except Exception as exc:
                logger.warning("Detection error in pack '%s': %s", pack.pack_id, exc)
                continue
        return None
