"""
src/pipeline/exporter.py

Exports normalized events and quarantined logs to JSON-Lines data-lake storage.
Ensures zero data loss by partitioning valid versus partial/invalid events.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


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
        self.base_dir.mkdir(parents=True, exist_ok=True)
        valid_file = self.base_dir / f"{filename_prefix}_normalized.jsonl"
        quarantine_file = self.base_dir / f"{filename_prefix}_quarantine.jsonl"
        manifest_file = self.base_dir / f"{filename_prefix}_manifest.json"

        valid_count = 0
        quarantine_count = 0

        valid_bytes = bytearray()
        quarantine_bytes = bytearray()

        for event in events:
            line = (json.dumps(event, separators=(",", ":")) + "\n").encode("utf-8")
            status = event.get("quality", {}).get("status", "valid")

            if status == "valid":
                valid_bytes.extend(line)
                valid_count += 1
            else:
                quarantine_bytes.extend(line)
                quarantine_count += 1

        # Write files
        valid_file.write_bytes(valid_bytes)
        quarantine_file.write_bytes(quarantine_bytes)

        # Generate manifest with cryptographic checksums
        manifest = {
            "exported_at": datetime.now(UTC).isoformat(),
            "total_events": len(events),
            "valid_events": {
                "count": valid_count,
                "file_path": str(valid_file),
                "file_bytes": len(valid_bytes),
                "sha256": hashlib.sha256(valid_bytes).hexdigest() if valid_bytes else None,
            },
            "quarantine_events": {
                "count": quarantine_count,
                "file_path": str(quarantine_file),
                "file_bytes": len(quarantine_bytes),
                "sha256": hashlib.sha256(quarantine_bytes).hexdigest()
                if quarantine_bytes
                else None,
            },
        }

        manifest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return manifest
