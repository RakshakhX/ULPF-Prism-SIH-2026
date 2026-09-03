"""Reproducible fictional Suricata dataset acceptance tests."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from core.engine import ParsingEngine
from src.contracts import ParseStatus, RawEventEnvelope
from src.normalization import UniversalNormalizer, default_registry
from src.storage import ClickHouseEventStore
from src.validation.validate_unified_event import validate_event
from tests.storage.fakes import FakeClickHouseClient

DATASET = Path("source_packs/suricata/samples")


def _raw_lines(name: str) -> list[bytes]:
    return [line for line in (DATASET / name).read_bytes().splitlines() if line.strip()]


def test_dataset_has_twenty_valid_and_five_invalid_records() -> None:
    valid = _raw_lines("valid.jsonl")
    invalid = _raw_lines("invalid.jsonl")

    assert len(valid) == 20
    assert len(invalid) == 5
    assert Counter(json.loads(line)["event_type"] for line in valid) == {
        "alert": 5,
        "flow": 5,
        "dns": 5,
        "http": 5,
    }


def test_all_valid_records_normalize_and_validate_with_raw_traceability() -> None:
    engine = ParsingEngine(Path("source_packs"))
    normalizer = UniversalNormalizer(default_registry())

    for raw in _raw_lines("valid.jsonl"):
        envelope = RawEventEnvelope.from_bytes(
            raw, source_id="suricata-dataset", transport="replay"
        )
        parsed = engine.process(envelope)
        unified = normalizer.normalize(parsed)

        assert parsed.source_pack_id == "suricata_eve"
        assert parsed.status is ParseStatus.SUCCESS
        assert unified["quality"]["status"] == "valid"
        assert unified["traceability"]["raw_sha256"] == envelope.raw_sha256
        assert validate_event(unified).valid


def test_invalid_records_are_explained_and_quarantined() -> None:
    engine = ParsingEngine(Path("source_packs"))
    normalizer = UniversalNormalizer(default_registry())
    client = FakeClickHouseClient()
    store = ClickHouseEventStore(client)

    for raw in _raw_lines("invalid.jsonl"):
        envelope = RawEventEnvelope.from_bytes(
            raw, source_id="suricata-invalid", transport="replay"
        )
        parsed = engine.process(envelope)
        unified = normalizer.normalize(parsed)
        result = store.write_batch([unified])

        assert parsed.source_pack_id == "suricata_eve"
        assert parsed.status is ParseStatus.FAILED
        assert parsed.issues
        assert unified["quality"]["status"] == "invalid"
        assert result.quarantine_count == 1
