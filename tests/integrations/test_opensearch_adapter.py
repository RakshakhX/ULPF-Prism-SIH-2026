from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import yaml

from src.integrations import DeliveryResult
from src.integrations.opensearch import OpenSearchAdapter, TransportResponse

FIXTURE = Path("tests/fixtures/valid_minimal_network_event.json")


def events() -> list[dict]:
    first = json.loads(FIXTURE.read_text(encoding="utf-8"))
    second = deepcopy(first)
    second["event"]["id"] = "223e4567-e89b-12d3-a456-426614174001"
    return [first, second]


class FakeTransport:
    def __init__(self, response: TransportResponse) -> None:
        self.response = response
        self.calls: list[tuple[str, bytes, dict[str, str]]] = []

    def post(self, path: str, body: bytes, headers: dict[str, str]) -> TransportResponse:
        self.calls.append((path, body, headers))
        return self.response


def test_bulk_result_reconciles_mixed_item_statuses() -> None:
    transport = FakeTransport(
        TransportResponse(
            200,
            {
                "items": [
                    {"index": {"status": 201}},
                    {"index": {"status": 429, "error": {"reason": "busy"}}},
                ]
            },
        )
    )

    result = OpenSearchAdapter(transport).deliver(events())

    assert result == DeliveryResult(2, 1, 1, 0, ("busy",))
    path, body, headers = transport.calls[0]
    assert path == "/_bulk"
    assert headers["Content-Type"] == "application/x-ndjson"
    lines = body.decode().splitlines()
    assert len(lines) == 4
    assert json.loads(lines[0])["index"]["_id"] == events()[0]["event"]["id"]
    assert json.loads(lines[1])["traceability"]["raw_sha256"]


def test_bulk_classifies_terminal_and_server_failures() -> None:
    terminal = FakeTransport(
        TransportResponse(
            200,
            {"items": [{"index": {"status": 400}}, {"index": {"status": 403}}]},
        )
    )
    unavailable = FakeTransport(TransportResponse(503, {"error": "unavailable"}))

    assert OpenSearchAdapter(terminal).deliver(events()).terminal_failures == 2
    assert OpenSearchAdapter(unavailable).deliver(events()).retryable_failures == 2


def test_bulk_fails_closed_when_response_item_count_is_wrong() -> None:
    transport = FakeTransport(TransportResponse(200, {"items": [{"index": {"status": 201}}]}))

    result = OpenSearchAdapter(transport).deliver(events())

    assert result.delivered == 0
    assert result.retryable_failures == 2
    assert result.errors == ("bulk response item count did not match request",)


def test_opensearch_compose_profile_is_optional_and_pinned() -> None:
    compose = yaml.safe_load(Path("docker-compose.yml").read_text())
    service = compose["services"]["opensearch"]

    assert service["image"] == "opensearchproject/opensearch:3.8.0"
    assert service["profiles"] == ["siem-search"]
    assert "opensearch-data:/usr/share/opensearch/data" in service["volumes"]
    assert "opensearch-data" in compose["volumes"]
