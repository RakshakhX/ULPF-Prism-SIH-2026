"""OpenSearch Bulk API adapter with per-event delivery reconciliation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

from src.integrations.base import DeliveryResult
from src.integrations.json_adapter import serialize_json


@dataclass(frozen=True)
class TransportResponse:
    status: int
    body: dict[str, Any]


class OpenSearchTransport(Protocol):
    def post(self, path: str, body: bytes, headers: dict[str, str]) -> TransportResponse: ...


class OpenSearchAdapter:
    def __init__(
        self,
        transport: OpenSearchTransport,
        *,
        index: str = "ulpf-events-v1",
        batch_size: int = 500,
    ) -> None:
        if batch_size < 1:
            raise ValueError("batch_size must be positive")
        self.transport = transport
        self.index = index
        self.batch_size = batch_size

    def deliver(self, events: list[dict[str, Any]]) -> DeliveryResult:
        results = [
            self._deliver_chunk(events[start : start + self.batch_size])
            for start in range(0, len(events), self.batch_size)
        ]
        return DeliveryResult(
            attempted=sum(result.attempted for result in results),
            delivered=sum(result.delivered for result in results),
            retryable_failures=sum(result.retryable_failures for result in results),
            terminal_failures=sum(result.terminal_failures for result in results),
            errors=tuple(error for result in results for error in result.errors),
        )

    def _deliver_chunk(self, events: list[dict[str, Any]]) -> DeliveryResult:
        if not events:
            return DeliveryResult(0, 0, 0, 0)
        lines: list[bytes] = []
        for event in events:
            metadata = {"index": {"_index": self.index, "_id": event["event"]["id"]}}
            lines.append(json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode())
            lines.append(serialize_json(event))
        payload = b"\n".join(lines) + b"\n"
        try:
            response = self.transport.post(
                "/_bulk",
                payload,
                {"Content-Type": "application/x-ndjson"},
            )
        except Exception as error:
            return DeliveryResult(len(events), 0, len(events), 0, (str(error),))

        if not 200 <= response.status < 300:
            retryable = _retryable(response.status)
            message = _reason(response.body) or f"bulk request returned HTTP {response.status}"
            return DeliveryResult(
                len(events),
                0,
                len(events) if retryable else 0,
                0 if retryable else len(events),
                (message,),
            )

        items = response.body.get("items")
        if not isinstance(items, list) or len(items) != len(events):
            return DeliveryResult(
                len(events),
                0,
                len(events),
                0,
                ("bulk response item count did not match request",),
            )

        delivered = retryable_failures = terminal_failures = 0
        errors: list[str] = []
        for item in items:
            operation = item.get("index", {}) if isinstance(item, dict) else {}
            status = operation.get("status")
            if isinstance(status, int) and 200 <= status < 300:
                delivered += 1
            elif isinstance(status, int) and _retryable(status):
                retryable_failures += 1
                if reason := _reason(operation):
                    errors.append(reason)
            else:
                terminal_failures += 1
                if reason := _reason(operation):
                    errors.append(reason)
        return DeliveryResult(
            len(events),
            delivered,
            retryable_failures,
            terminal_failures,
            tuple(errors),
        )


def _retryable(status: int) -> bool:
    return status in {408, 429} or 500 <= status <= 599


def _reason(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    error = value.get("error")
    if isinstance(error, str):
        return error
    if isinstance(error, dict) and isinstance(error.get("reason"), str):
        return error["reason"]
    return None
