from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.storage import AnalyticalVisibilityStore
from src.storage import ClickHouseEventStore, map_unified_event
from tests.storage.fakes import FakeClickHouseClient

VALID_FIXTURE = Path("tests/fixtures/valid_minimal_network_event.json")


def valid_event() -> dict:
    return json.loads(VALID_FIXTURE.read_text(encoding="utf-8"))


def test_valid_event_maps_to_searchable_row() -> None:
    event = valid_event()

    row = map_unified_event(event)

    assert row.event_id == event["event"]["id"]
    assert row.raw_sha256 == event["traceability"]["raw_sha256"]
    assert row.vendor == event["observer"]["vendor"]
    assert row.source_ip == event["source"]["ip"]
    assert row.destination_port == event["destination"]["port"]
    assert json.loads(row.normalized_json) == event


def test_valid_batch_is_inserted_into_events_table() -> None:
    client = FakeClickHouseClient()

    result = ClickHouseEventStore(client).write_batch([valid_event()])

    assert result.accepted_count == 1
    assert result.valid_count == 1
    assert result.quarantine_count == 0
    assert result.failed_count == 0
    assert client.inserts[0]["table"] == "ulpf.events_v1"


def test_invalid_event_is_quarantined_with_validation_codes() -> None:
    client = FakeClickHouseClient()
    invalid = {"schema_version": "1.0.0", "event": {"id": "broken"}}

    result = ClickHouseEventStore(client).write_batch([invalid])

    assert result.accepted_count == 1
    assert result.valid_count == 0
    assert result.quarantine_count == 1
    assert result.failed_count == 0
    insert = client.inserts[0]
    assert insert["table"] == "ulpf.quarantine_v1"
    error_codes = insert["data"][0][3]
    assert any("required" in code for code in error_codes)


def test_schema_valid_event_with_invalid_quality_is_quarantined() -> None:
    client = FakeClickHouseClient()
    event = valid_event()
    event["quality"]["status"] = "invalid"
    event["quality"]["warnings"] = ["parser could not establish required fields"]

    result = ClickHouseEventStore(client).write_batch([event])

    assert result.valid_count == 0
    assert result.quarantine_count == 1
    assert client.inserts[0]["table"] == "ulpf.quarantine_v1"
    assert "$.quality.status:invalid" in client.inserts[0]["data"][0][3]


def test_client_failure_is_accounted_without_claiming_acceptance() -> None:
    client = FakeClickHouseClient()
    client.fail_with = RuntimeError("ClickHouse unavailable")

    result = ClickHouseEventStore(client).write_batch([valid_event()])

    assert result.accepted_count == 0
    assert result.valid_count == 0
    assert result.quarantine_count == 0
    assert result.failed_count == 1
    assert result.errors == ("ClickHouse unavailable",)


def test_in_memory_store_implements_the_shared_batch_contract() -> None:
    store = AnalyticalVisibilityStore()
    event = valid_event()

    result = store.write_batch([event])

    assert result.accepted_count == 1
    assert result.valid_count == 1
    assert result.failed_count == 0
    assert store.get_by_event_id(event["event"]["id"]) == event


def test_clickhouse_schema_preserves_json_and_projected_traceability() -> None:
    schema = Path("deploy/clickhouse/init/001_events.sql").read_text(encoding="utf-8")

    assert "CREATE TABLE IF NOT EXISTS ulpf.events_v1" in schema
    assert "ReplacingMergeTree(normalized_at)" in schema
    assert "PARTITION BY toYYYYMM(observed_at)" in schema
    assert "normalized_json String" in schema
    assert "raw_sha256 FixedString(64)" in schema
    assert "CREATE TABLE IF NOT EXISTS ulpf.quarantine_v1" in schema
