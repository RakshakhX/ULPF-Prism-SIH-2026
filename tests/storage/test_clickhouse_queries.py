from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from src.storage import ClickHouseEventStore
from tests.storage.fakes import FakeClickHouseClient

VALID_FIXTURE = Path("tests/fixtures/valid_minimal_network_event.json")


def event() -> dict:
    return json.loads(VALID_FIXTURE.read_text(encoding="utf-8"))


def test_search_uses_parameters_for_every_caller_supplied_value() -> None:
    client = FakeClickHouseClient()
    client.query_rows = [(json.dumps(event()),)]
    store = ClickHouseEventStore(client)
    attack_text = "x' OR 1=1 --"

    results = store.search(
        query=attack_text,
        vendor="example_vendor",
        category="network",
        action="allow",
        severity="informational",
        quality_status="valid",
        start_time=datetime(2026, 8, 1, tzinfo=UTC),
        end_time=datetime(2026, 9, 1, tzinfo=UTC),
        limit=25,
    )

    issued = client.queries[0]
    assert results == [event()]
    assert attack_text not in issued["query"]
    assert issued["parameters"]["query"] == attack_text
    assert issued["parameters"]["vendor"] == "example_vendor"
    assert issued["parameters"]["limit"] == 25
    assert "{vendor:String}" in issued["query"]
    assert "{start_time:DateTime64(6)}" in issued["query"]


def test_event_and_raw_hash_lookups_are_parameterized() -> None:
    expected = event()
    client = FakeClickHouseClient()
    client.query_rows = [(json.dumps(expected),)]
    store = ClickHouseEventStore(client)

    assert store.get_by_event_id(expected["event"]["id"]) == expected
    assert client.queries[-1]["parameters"] == {"event_id": expected["event"]["id"]}
    assert store.get_by_raw_hash(expected["traceability"]["raw_sha256"]) == expected
    assert client.queries[-1]["parameters"] == {
        "raw_sha256": expected["traceability"]["raw_sha256"]
    }


def test_search_limit_is_bounded_before_query_execution() -> None:
    client = FakeClickHouseClient()
    store = ClickHouseEventStore(client)

    store.search(limit=100_000)

    assert client.queries[0]["parameters"]["limit"] == 500


def test_persistent_aggregations_match_dashboard_contract() -> None:
    client = FakeClickHouseClient()
    client.query_responses = [
        [(5, 2, 1)],
        [("Cisco", "ASA", 3), ("Fortinet", "FortiGate", 2)],
        [("high", 2), ("informational", 3)],
        [("valid", 4), ("partial", 1)],
    ]
    store = ClickHouseEventStore(client)

    aggregations = store.get_aggregations()

    assert aggregations == {
        "total_events": 5,
        "events_by_source": {"Cisco ASA": 3, "Fortinet FortiGate": 2},
        "allow_vs_deny": {
            "allow_count": 2,
            "deny_count": 1,
            "allow_percent": 66.7,
            "deny_percent": 33.3,
        },
        "severity_distribution": {
            "critical": 0,
            "high": 2,
            "medium": 0,
            "low": 0,
            "informational": 3,
            "unknown": 0,
        },
        "quality_metrics": {"valid": 4, "partial": 1, "invalid": 0, "unknown": 0},
    }


def test_event_count_counts_deduplicated_ids() -> None:
    client = FakeClickHouseClient()
    client.query_rows = [(7,)]

    assert ClickHouseEventStore(client).event_count == 7
    assert "uniqExact(event_id)" in client.queries[0]["query"]
