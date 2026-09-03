"""
src/pipeline/exporter.py

Exports normalized events and quarantined logs to JSON-Lines data-lake storage.
Ensures zero data loss by partitioning valid versus partial/invalid events.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.exports.jsonl import JsonlExporter
from src.exports.models import atomic_write


class DataLakeExporter:
    """Exports UnifiedEvents to structured JSON-Lines data lake directory."""

    def __init__(self, base_dir: Path | str = "data/exports") -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def export_events(
        self, events: list[dict[str, Any]], filename_prefix: str = "ulpf_lake"
    ) -> dict[str, Any]:
        """
        Partitions and exports events into valid and quarantine data lake files.
        """
        result = JsonlExporter(self.base_dir).export(events, prefix=filename_prefix)
        manifest_file = self.base_dir / f"{filename_prefix}_manifest.json"
        valid = next(item for item in result.files if not item.quarantine)
        quarantine = next(item for item in result.files if item.quarantine)
        manifest = {
            "exported_at": result.exported_at,
            "total_events": result.total_events,
            "valid_events": {
                "count": result.valid_events,
                "file_path": str(self.base_dir / valid.path),
                "file_bytes": valid.bytes,
                "sha256": valid.sha256 if valid.rows else None,
            },
            "quarantine_events": {
                "count": result.quarantine_events,
                "file_path": str(self.base_dir / quarantine.path),
                "file_bytes": quarantine.bytes,
                "sha256": quarantine.sha256 if quarantine.rows else None,
            },
        }
        atomic_write(manifest_file, (json.dumps(manifest, indent=2) + "\n").encode())
        return manifest
