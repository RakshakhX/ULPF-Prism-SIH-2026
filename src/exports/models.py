"""Verifiable data-lake export manifest contracts."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ExportFile:
    """Integrity and row-count metadata for one exported file."""

    path: str
    rows: int
    bytes: int
    sha256: str
    schema_version: str
    format: str
    quarantine: bool = False


@dataclass(frozen=True)
class ExportManifest:
    """Complete result of one export operation."""

    root: Path = field(repr=False, compare=False)
    format: str
    exported_at: str
    total_events: int
    valid_events: int
    quarantine_events: int
    files: tuple[ExportFile, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "exported_at": self.exported_at,
            "total_events": self.total_events,
            "valid_events": self.valid_events,
            "quarantine_events": self.quarantine_events,
            "files": [asdict(item) for item in self.files],
        }


def describe_file(
    root: Path,
    path: Path,
    *,
    rows: int,
    schema_version: str,
    format: str,
    quarantine: bool,
) -> ExportFile:
    content = path.read_bytes()
    return ExportFile(
        path=path.relative_to(root).as_posix(),
        rows=rows,
        bytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        schema_version=schema_version,
        format=format,
        quarantine=quarantine,
    )


def write_manifest(manifest: ExportManifest, filename: str) -> Path:
    """Atomically persist a manifest beside its exported data."""
    destination = manifest.root / filename
    payload = (json.dumps(manifest.to_dict(), indent=2, sort_keys=True) + "\n").encode()
    atomic_write(destination, payload)
    return destination


def atomic_write(destination: Path, payload: bytes) -> None:
    """Commit bytes by rename so readers never observe a partial file."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.",
        suffix=".tmp",
    )
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary_path.replace(destination)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def verify_manifest(manifest: ExportManifest) -> bool:
    """Fail closed when counts, paths, sizes, or checksums do not reconcile."""
    if manifest.total_events != manifest.valid_events + manifest.quarantine_events:
        return False
    if sum(item.rows for item in manifest.files) != manifest.total_events:
        return False
    if sum(item.rows for item in manifest.files if item.quarantine) != manifest.quarantine_events:
        return False
    if sum(item.rows for item in manifest.files if not item.quarantine) != manifest.valid_events:
        return False

    root = manifest.root.resolve()
    for item in manifest.files:
        candidate = (manifest.root / item.path).resolve()
        if not candidate.is_relative_to(root) or not candidate.is_file():
            return False
        content = candidate.read_bytes()
        if len(content) != item.bytes:
            return False
        if hashlib.sha256(content).hexdigest() != item.sha256:
            return False
    return True
