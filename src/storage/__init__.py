"""Persistent analytical storage contracts and implementations."""

from src.storage.base import AnalyticalEventSink, AnalyticalEventStore
from src.storage.clickhouse import (
    ClickHouseEventStore,
    create_clickhouse_client,
    map_unified_event,
)
from src.storage.models import EventRow, QuarantineRow, WriteResult
from src.storage.worker import ClickHouseSinkProcessor, StorageDecision

__all__ = [
    "AnalyticalEventSink",
    "AnalyticalEventStore",
    "ClickHouseEventStore",
    "ClickHouseSinkProcessor",
    "EventRow",
    "QuarantineRow",
    "WriteResult",
    "StorageDecision",
    "create_clickhouse_client",
    "map_unified_event",
]
