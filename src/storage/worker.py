"""Pure normalized-event sink decisions for broker worker adapters."""

from __future__ import annotations

import json
from dataclasses import dataclass

from src.storage.clickhouse import ClickHouseEventStore


@dataclass(frozen=True)
class StorageDecision:
    acknowledge: bool
    retryable: bool
    error_code: str | None = None
    error_message: str | None = None


class ClickHouseSinkProcessor:
    """Acknowledge only records durably written to events or quarantine."""

    def __init__(self, store: ClickHouseEventStore) -> None:
        self.store = store

    def process(self, payload: bytes) -> StorageDecision:
        try:
            event = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._quarantine(payload, "INVALID_NORMALIZED_JSON")
        if not isinstance(event, dict):
            return self._quarantine(payload, "INVALID_NORMALIZED_CONTRACT")

        result = self.store.write_batch([event])
        if result.failed_count:
            return StorageDecision(
                acknowledge=False,
                retryable=True,
                error_code="STORAGE_WRITE_FAILED",
                error_message="; ".join(result.errors),
            )
        if result.quarantine_count:
            return StorageDecision(True, False, "INVALID_NORMALIZED_CONTRACT")
        return StorageDecision(True, False)

    def _quarantine(self, payload: bytes, error_code: str) -> StorageDecision:
        result = self.store.quarantine_payload(payload, error_code)
        if result.failed_count:
            return StorageDecision(
                acknowledge=False,
                retryable=True,
                error_code="STORAGE_WRITE_FAILED",
                error_message="; ".join(result.errors),
            )
        return StorageDecision(True, False, error_code)
