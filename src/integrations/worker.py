"""Pure broker decision logic for normalized-event output adapters."""

from __future__ import annotations

import json
from dataclasses import dataclass

from src.integrations.base import OutputAdapter


@dataclass(frozen=True)
class DeliveryDecision:
    acknowledge: bool
    retryable: bool
    dead_letter: bool
    error_code: str | None = None
    error_message: str | None = None


class AdapterDeliveryWorker:
    def __init__(self, adapter: OutputAdapter) -> None:
        self.adapter = adapter

    def process(self, payload: bytes) -> DeliveryDecision:
        try:
            event = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return DeliveryDecision(False, False, True, "INVALID_NORMALIZED_JSON")
        if not isinstance(event, dict):
            return DeliveryDecision(False, False, True, "INVALID_NORMALIZED_CONTRACT")

        try:
            result = self.adapter.deliver([event])
        except Exception as error:
            return DeliveryDecision(False, True, False, "ADAPTER_UNAVAILABLE", str(error))
        message = "; ".join(result.errors) or None
        if not result.reconciled or result.attempted != 1:
            return DeliveryDecision(
                False,
                False,
                True,
                "DELIVERY_ACCOUNTING_INVALID",
                message,
            )
        if result.retryable_failures:
            return DeliveryDecision(False, True, False, "DELIVERY_RETRYABLE", message)
        if result.terminal_failures:
            return DeliveryDecision(False, False, True, "DELIVERY_TERMINAL", message)
        return DeliveryDecision(True, False, False)
