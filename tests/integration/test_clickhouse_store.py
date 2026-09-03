from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from src.storage import ClickHouseEventStore, create_clickhouse_client

VALID_FIXTURE = Path("tests/fixtures/valid_minimal_network_event.json")


@pytest.mark.integration
def test_insert_search_deduplicate_and_trace() -> None:
    url = os.environ.get("ULPF_CLICKHOUSE_URL")
    if not url:
        pytest.skip("ULPF_CLICKHOUSE_URL is not set")
    store = ClickHouseEventStore(create_clickhouse_client(url))
    fixture = json.loads(VALID_FIXTURE.read_text(encoding="utf-8"))

    result = store.write_batch([fixture, fixture])

    assert result.accepted_count == 2
    assert store.get_by_event_id(fixture["event"]["id"])["event"]["id"] == fixture["event"]["id"]
    assert len(store.search(vendor="example_vendor", limit=10)) == 1
