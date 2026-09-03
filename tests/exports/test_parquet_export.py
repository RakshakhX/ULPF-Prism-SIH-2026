from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pyarrow.parquet as pq

from src.exports import ParquetExporter, verify_manifest

FIXTURE = Path("tests/fixtures/valid_minimal_network_event.json")


def _events() -> tuple[dict, dict]:
    valid = json.loads(FIXTURE.read_text(encoding="utf-8"))
    quarantined = deepcopy(valid)
    quarantined["event"]["id"] = "223e4567-e89b-12d3-a456-426614174001"
    quarantined["quality"]["status"] = "partial"
    quarantined["quality"]["warnings"] = ["source field was unavailable"]
    return valid, quarantined


def test_parquet_partition_manifest_and_readback(tmp_path: Path) -> None:
    valid, quarantined = _events()

    manifest = ParquetExporter(tmp_path).export([valid, quarantined])

    assert manifest.total_events == 2
    assert manifest.valid_events == 1
    assert manifest.quarantine_events == 1
    assert len(manifest.files) == 2
    assert verify_manifest(manifest)

    valid_file = next(item for item in manifest.files if not item.quarantine)
    quarantine_file = next(item for item in manifest.files if item.quarantine)
    assert valid_file.path.startswith("year=2026/month=08/day=30/category=network/")
    assert quarantine_file.path.startswith(
        "quarantine/year=2026/month=08/day=30/category=network/"
    )
    assert valid_file.format == "parquet"
    assert valid_file.schema_version == "1.0.0"

    table = pq.read_table(tmp_path / valid_file.path)
    row = table.to_pylist()[0]
    assert table.num_rows == 1
    assert row["event_id"] == valid["event"]["id"]
    assert row["raw_event_id"] == valid["traceability"]["raw_event_id"]
    assert row["raw_sha256"] == valid["traceability"]["raw_sha256"]
    assert json.loads(row["normalized_json"]) == valid


def test_manifest_verification_detects_tampered_parquet(tmp_path: Path) -> None:
    valid, _ = _events()
    manifest = ParquetExporter(tmp_path).export([valid])
    exported = tmp_path / manifest.files[0].path

    exported.write_bytes(exported.read_bytes() + b"tampered")

    assert not verify_manifest(manifest)


def test_parquet_export_is_empty_safe(tmp_path: Path) -> None:
    manifest = ParquetExporter(tmp_path).export([])

    assert manifest.total_events == 0
    assert manifest.files == ()
    assert verify_manifest(manifest)
