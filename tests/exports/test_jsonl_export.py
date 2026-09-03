from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from src.exports import JsonlExporter, verify_manifest
from src.pipeline.exporter import DataLakeExporter

FIXTURE = Path("tests/fixtures/valid_minimal_network_event.json")


def _events() -> tuple[dict, dict]:
    valid = json.loads(FIXTURE.read_text(encoding="utf-8"))
    quarantined = deepcopy(valid)
    quarantined["event"]["id"] = "223e4567-e89b-12d3-a456-426614174001"
    quarantined["quality"]["status"] = "invalid"
    return valid, quarantined


def test_jsonl_export_is_atomic_verifiable_and_separates_quarantine(tmp_path: Path) -> None:
    valid, quarantined = _events()

    manifest = JsonlExporter(tmp_path).export([valid, quarantined], prefix="batch")

    assert manifest.total_events == 2
    assert manifest.valid_events == 1
    assert manifest.quarantine_events == 1
    assert {item.path for item in manifest.files} == {
        "batch_normalized.jsonl",
        "batch_quarantine.jsonl",
    }
    assert verify_manifest(manifest)
    assert not list(tmp_path.glob("*.tmp"))

    valid_line = (tmp_path / "batch_normalized.jsonl").read_text(encoding="utf-8")
    quarantine_line = (tmp_path / "batch_quarantine.jsonl").read_text(encoding="utf-8")
    assert json.loads(valid_line) == valid
    assert json.loads(quarantine_line) == quarantined


def test_legacy_data_lake_exporter_keeps_existing_manifest_contract(tmp_path: Path) -> None:
    valid, quarantined = _events()

    manifest = DataLakeExporter(tmp_path).export_events([valid, quarantined])

    assert manifest["total_events"] == 2
    assert manifest["valid_events"]["count"] == 1
    assert manifest["quarantine_events"]["count"] == 1
    assert (tmp_path / "ulpf_lake_normalized.jsonl").exists()
    assert (tmp_path / "ulpf_lake_quarantine.jsonl").exists()
    assert (tmp_path / "ulpf_lake_manifest.json").exists()
