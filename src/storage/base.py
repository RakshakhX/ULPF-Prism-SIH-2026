"""Interfaces shared by in-memory and persistent analytical stores."""

from __future__ import annotations

from typing import Any, Protocol

from src.storage.models import WriteResult


class AnalyticalEventSink(Protocol):
    def write_batch(self, events: list[dict[str, Any]]) -> WriteResult: ...


class AnalyticalEventStore(AnalyticalEventSink, Protocol):
    def search(self, **filters: Any) -> list[dict[str, Any]]: ...

    def get_by_event_id(self, event_id: str) -> dict[str, Any] | None: ...

    def get_by_raw_hash(self, raw_sha256: str) -> dict[str, Any] | None: ...
