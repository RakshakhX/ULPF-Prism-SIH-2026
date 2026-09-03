"""Partitioned Parquet exporter for analytics-oriented lake ingestion."""

from __future__ import annotations

import json
import re
import tempfile
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pyarrow as pa
import pyarrow.parquet as pq

from src.exports.models import ExportManifest, describe_file, write_manifest

PARQUET_SCHEMA = pa.schema(
    [
        ("schema_version", pa.string()),
        ("event_id", pa.string()),
        ("event_category", pa.string()),
        ("observed_at", pa.timestamp("us", tz="UTC")),
        ("raw_event_id", pa.string()),
        ("raw_sha256", pa.string()),
        ("observer_vendor", pa.string()),
        ("observer_product", pa.string()),
        ("quality_status", pa.string()),
        ("normalized_json", pa.large_string()),
    ]
)


class ParquetExporter:
    """Write UnifiedEvents into valid/quarantine Hive-style partitions."""

    def __init__(self, base_dir: Path | str) -> None:
        self.base_dir = Path(base_dir)

    def export(self, events: list[dict[str, Any]]) -> ExportManifest:
        self.base_dir.mkdir(parents=True, exist_ok=True)
        partitions: dict[tuple[bool, str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
        for event in events:
            quarantine = not _is_valid(event)
            year, month, day = _date_partition(event)
            category = _safe_partition(event.get("event", {}).get("category"))
            partitions[(quarantine, year, month, day, category)].append(event)

        files = []
        for partition, records in sorted(partitions.items()):
            quarantine, year, month, day, category = partition
            directory = self.base_dir
            if quarantine:
                directory /= "quarantine"
            directory /= f"year={year}/month={month}/day={day}/category={category}"
            directory.mkdir(parents=True, exist_ok=True)
            destination = directory / f"part-{uuid4().hex}.parquet"
            _write_atomic_parquet(destination, records)
            files.append(
                describe_file(
                    self.base_dir,
                    destination,
                    rows=len(records),
                    schema_version=_schema_version(records),
                    format="parquet",
                    quarantine=quarantine,
                )
            )

        valid_count = sum(1 for event in events if _is_valid(event))
        manifest = ExportManifest(
            root=self.base_dir,
            format="parquet",
            exported_at=datetime.now(UTC).isoformat(),
            total_events=len(events),
            valid_events=valid_count,
            quarantine_events=len(events) - valid_count,
            files=tuple(files),
        )
        write_manifest(manifest, "parquet_manifest.json")
        return manifest


def _write_atomic_parquet(destination: Path, events: list[dict[str, Any]]) -> None:
    rows = [_project(event) for event in events]
    table = pa.Table.from_pylist(rows, schema=PARQUET_SCHEMA)
    with tempfile.NamedTemporaryFile(
        dir=destination.parent,
        prefix=f".{destination.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        temporary = Path(handle.name)
    try:
        pq.write_table(table, temporary, compression="zstd")
        if pq.read_metadata(temporary).num_rows != len(events):
            raise RuntimeError("Parquet read-back row count did not match input")
        temporary.replace(destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _project(event: dict[str, Any]) -> dict[str, Any]:
    traceability = event.get("traceability", {})
    observer = event.get("observer", {})
    return {
        "schema_version": str(event.get("schema_version", "unknown")),
        "event_id": _optional_string(event.get("event", {}).get("id")),
        "event_category": _optional_string(event.get("event", {}).get("category")),
        "observed_at": _parse_timestamp(event.get("time", {}).get("observed_at")),
        "raw_event_id": _optional_string(traceability.get("raw_event_id")),
        "raw_sha256": _optional_string(traceability.get("raw_sha256")),
        "observer_vendor": _optional_string(observer.get("vendor")),
        "observer_product": _optional_string(observer.get("product")),
        "quality_status": _optional_string(event.get("quality", {}).get("status")),
        "normalized_json": json.dumps(
            event,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ),
    }


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _date_partition(event: dict[str, Any]) -> tuple[str, str, str]:
    observed = _parse_timestamp(event.get("time", {}).get("observed_at"))
    if observed is None:
        return "unknown", "unknown", "unknown"
    return f"{observed.year:04d}", f"{observed.month:02d}", f"{observed.day:02d}"


def _safe_partition(value: Any) -> str:
    text = _optional_string(value) or "unknown"
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("._")
    return safe or "unknown"


def _optional_string(value: Any) -> str | None:
    return str(value) if value is not None else None


def _is_valid(event: dict[str, Any]) -> bool:
    return event.get("quality", {}).get("status", "valid") == "valid"


def _schema_version(events: list[dict[str, Any]]) -> str:
    versions = {str(event.get("schema_version", "unknown")) for event in events}
    return versions.pop() if len(versions) == 1 else "mixed"
