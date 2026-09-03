from __future__ import annotations

import json
from pathlib import Path

from src.integrations import AdapterDeliveryWorker, DeliveryResult

FIXTURE = Path("tests/fixtures/valid_minimal_network_event.json")


class FakeAdapter:
    def __init__(self, result: DeliveryResult) -> None:
        self.result = result
        self.events: list[dict] = []

    def deliver(self, events: list[dict]) -> DeliveryResult:
        self.events.extend(events)
        return self.result


def payload() -> bytes:
    return FIXTURE.read_bytes()


def test_worker_acknowledges_only_complete_delivery() -> None:
    adapter = FakeAdapter(DeliveryResult(1, 1, 0, 0))

    decision = AdapterDeliveryWorker(adapter).process(payload())

    assert decision.acknowledge is True
    assert decision.retryable is False
    assert decision.dead_letter is False
    assert len(adapter.events) == 1


def test_worker_retries_partial_or_retryable_delivery() -> None:
    adapter = FakeAdapter(DeliveryResult(1, 0, 1, 0, ("timeout",)))

    decision = AdapterDeliveryWorker(adapter).process(payload())

    assert decision.acknowledge is False
    assert decision.retryable is True
    assert decision.dead_letter is False
    assert decision.error_message == "timeout"


def test_worker_routes_terminal_delivery_to_dead_letter() -> None:
    adapter = FakeAdapter(DeliveryResult(1, 0, 0, 1, ("bad request",)))

    decision = AdapterDeliveryWorker(adapter).process(payload())

    assert decision.acknowledge is False
    assert decision.retryable is False
    assert decision.dead_letter is True


def test_worker_rejects_malformed_contract_without_calling_adapter() -> None:
    adapter = FakeAdapter(DeliveryResult(1, 1, 0, 0))

    decision = AdapterDeliveryWorker(adapter).process(json.dumps(["not", "object"]).encode())

    assert decision.dead_letter is True
    assert decision.error_code == "INVALID_NORMALIZED_CONTRACT"
    assert adapter.events == []


def test_worker_fails_closed_when_adapter_counts_do_not_reconcile() -> None:
    adapter = FakeAdapter(DeliveryResult(1, 1, 1, 0))

    decision = AdapterDeliveryWorker(adapter).process(payload())

    assert decision.acknowledge is False
    assert decision.retryable is False
    assert decision.dead_letter is True
    assert decision.error_code == "DELIVERY_ACCOUNTING_INVALID"

