"""Application wiring tests for configured analytical storage."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

import main
from src.pipeline.storage import AnalyticalVisibilityStore
from src.storage import ClickHouseEventStore
from src.storage.models import WriteResult
from tests.storage.fakes import FakeClickHouseClient

FIXTURE = json.loads(
    Path("tests/fixtures/valid_minimal_network_event.json").read_text(encoding="utf-8")
)


class RecordingStore:
    event_count = 1

    def __init__(self) -> None:
        self.filters: dict = {}

    def search(self, **filters):
        self.filters = filters
        return [FIXTURE]

    def get_aggregations(self):
        return {"total_events": 1}

    def list_events(self, limit: int = 50):
        return [FIXTURE][:limit]


def test_store_factory_keeps_zero_setup_mode_without_url() -> None:
    assert main.build_analytical_store("") is main.global_visibility_store
    assert isinstance(main.build_analytical_store(""), AnalyticalVisibilityStore)


def test_store_factory_selects_clickhouse_when_url_is_configured(monkeypatch) -> None:
    client = FakeClickHouseClient()
    seen: list[str] = []
    monkeypatch.setattr(
        main,
        "create_clickhouse_client",
        lambda url: seen.append(url) or client,
    )

    store = main.build_analytical_store("http://ulpf:secret@clickhouse:8123/ulpf")

    assert isinstance(store, ClickHouseEventStore)
    assert store.client is client
    assert seen == ["http://ulpf:secret@clickhouse:8123/ulpf"]


def test_analytics_endpoint_reads_configured_store_and_forwards_filters(monkeypatch) -> None:
    store = RecordingStore()
    monkeypatch.setattr(main, "analytical_store", store)

    response = TestClient(main.app).get(
        "/v1/analytics/events",
        params={
            "vendor": "Cisco",
            "category": "network",
            "start_time": "2026-08-01T00:00:00Z",
            "end_time": "2026-09-01T00:00:00Z",
            "limit": 25,
        },
    )

    assert response.status_code == 200
    assert response.json()["aggregations"] == {"total_events": 1}
    assert store.filters["vendor"] == "Cisco"
    assert store.filters["category"] == "network"
    assert store.filters["start_time"] == datetime(2026, 8, 1, tzinfo=UTC)
    assert store.filters["end_time"] == datetime(2026, 9, 1, tzinfo=UTC)
    assert store.filters["limit"] == 25


def test_ingest_api_returns_service_unavailable_when_indexing_fails(monkeypatch) -> None:
    from src.pipeline.runner import StorageWriteError

    class FailingRunner:
        def process(self, *args, **kwargs):
            raise StorageWriteError(WriteResult(0, 0, 0, 1, ("store offline",)))

    monkeypatch.setattr(main, "pipeline_runner", FailingRunner())

    response = TestClient(main.app).post(
        "/v1/events",
        json={"raw_text": "valid input boundary", "source_id": "api-storage-test"},
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "store offline"}
