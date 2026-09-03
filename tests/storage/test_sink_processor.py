from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.storage import ClickHouseEventStore, ClickHouseSinkProcessor
from tests.storage.fakes import FakeClickHouseClient

VALID_FIXTURE = Path("tests/fixtures/valid_minimal_network_event.json")


def payload() -> bytes:
    return VALID_FIXTURE.read_bytes()


def test_sink_acknowledges_only_after_storage_success() -> None:
    client = FakeClickHouseClient()
    store = ClickHouseEventStore(client)

    success = ClickHouseSinkProcessor(store).process(payload())
    client.fail_with = RuntimeError("ClickHouse unavailable")
    failure = ClickHouseSinkProcessor(store).process(payload())

    assert success.acknowledge is True
    assert success.retryable is False
    assert failure.acknowledge is False
    assert failure.retryable is True
    assert failure.error_code == "STORAGE_WRITE_FAILED"


def test_sink_persists_invalid_json_to_quarantine_before_acknowledging() -> None:
    client = FakeClickHouseClient()

    decision = ClickHouseSinkProcessor(ClickHouseEventStore(client)).process(b"{not-json")

    assert decision.acknowledge is True
    assert decision.retryable is False
    assert decision.error_code == "INVALID_NORMALIZED_JSON"
    assert client.inserts[0]["table"] == "ulpf.quarantine_v1"
    assert client.inserts[0]["data"][0][2] == "{not-json"


def test_sink_rejects_non_object_json_to_quarantine() -> None:
    client = FakeClickHouseClient()

    decision = ClickHouseSinkProcessor(ClickHouseEventStore(client)).process(
        json.dumps(["not", "an", "event"]).encode()
    )

    assert decision.acknowledge is True
    assert decision.error_code == "INVALID_NORMALIZED_CONTRACT"


@pytest.mark.parametrize("section", ["quality", "event", "traceability"])
@pytest.mark.parametrize("value", [None, [], "bad", 42, False])
def test_sink_quarantines_malformed_sections_before_acknowledging(section, value) -> None:
    client = FakeClickHouseClient()
    processor = ClickHouseSinkProcessor(ClickHouseEventStore(client))
    event = json.loads(payload())
    event[section] = value
    malformed = json.dumps(event).encode()

    decision = processor.process(malformed)

    assert decision.acknowledge is True
    assert decision.retryable is False
    assert decision.error_code == "INVALID_NORMALIZED_CONTRACT"
    assert len(client.inserts) == 1
    insert = client.inserts[0]
    assert insert["table"] == "ulpf.quarantine_v1"
    assert len(insert["data"]) == 1
    assert json.loads(insert["data"][0][2]) == event
    assert insert["data"][0][3]

    client.fail_with = RuntimeError("quarantine storage unavailable")
    failure = processor.process(malformed)

    assert failure.acknowledge is False
    assert failure.retryable is True
    assert failure.error_code == "STORAGE_WRITE_FAILED"
    assert len(client.inserts) == 1
