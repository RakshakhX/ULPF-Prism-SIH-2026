"""Deterministic JSON serialization and a small callable delivery adapter."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from src.integrations.base import DeliveryResult


def serialize_json(event: dict[str, Any]) -> bytes:
    return json.dumps(
        event,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


class JsonOutputAdapter:
    """Deliver deterministic JSON through a caller-provided byte sender."""

    def __init__(self, sender: Callable[[bytes], None]) -> None:
        self.sender = sender

    def deliver(self, events: list[dict[str, Any]]) -> DeliveryResult:
        delivered = 0
        errors: list[str] = []
        for event in events:
            try:
                self.sender(serialize_json(event))
                delivered += 1
            except Exception as error:
                errors.append(str(error))
        failed = len(events) - delivered
        return DeliveryResult(len(events), delivered, failed, 0, tuple(errors))
