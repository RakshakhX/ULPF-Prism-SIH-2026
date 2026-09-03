"""Atomic JSON-Lines data-lake exports."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.exports.models import (
    ExportManifest,
    atomic_write,
    describe_file,
    write_manifest,
)


class JsonlExporter:
    """Write deterministic normalized and quarantine JSONL files."""

    def __init__(self, base_dir: Path | str) -> None:
        self.base_dir = Path(base_dir)

    def export(self, events: list[dict[str, Any]], *, prefix: str = "ulpf_lake") -> ExportManifest:
        self.base_dir.mkdir(parents=True, exist_ok=True)
        valid = [event for event in events if _is_valid(event)]
        quarantine = [event for event in events if not _is_valid(event)]
        outputs = (
            (self.base_dir / f"{prefix}_normalized.jsonl", valid, False),
            (self.base_dir / f"{prefix}_quarantine.jsonl", quarantine, True),
        )

        files = []
        for path, records, is_quarantine in outputs:
            payload = b"".join(_line(record) for record in records)
            atomic_write(path, payload)
            files.append(
                describe_file(
                    self.base_dir,
                    path,
                    rows=len(records),
                    schema_version=_schema_version(records),
                    format="jsonl",
                    quarantine=is_quarantine,
                )
            )

        manifest = ExportManifest(
            root=self.base_dir,
            format="jsonl",
            exported_at=datetime.now(UTC).isoformat(),
            total_events=len(events),
            valid_events=len(valid),
            quarantine_events=len(quarantine),
            files=tuple(files),
        )
        write_manifest(manifest, f"{prefix}_manifest.v2.json")
        return manifest


def _line(event: dict[str, Any]) -> bytes:
    return (
        json.dumps(event, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")


def _is_valid(event: dict[str, Any]) -> bool:
    return event.get("quality", {}).get("status", "valid") == "valid"


def _schema_version(events: list[dict[str, Any]]) -> str:
    versions = {str(event.get("schema_version", "unknown")) for event in events}
    if not versions:
        return "unknown"
    return versions.pop() if len(versions) == 1 else "mixed"
