"""Bounded partition-aware retry scheduling without blocking consumer polling."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from confluent_kafka import TopicPartition

from src.streaming.kafka import CanonicalKafkaWorker
from src.streaming.workers import InvalidRetryProcessor, RetryProcessorRouter


class RetryKafkaWorker(CanonicalKafkaWorker):
    """Hold at most one uncommitted record per paused retry partition.

    The runtime must keep polling while waiting, call process_due() each loop,
    and register on_revoke for both lost and revoked assignments. Rebalances or
    shutdown leave deferred offsets uncommitted for the next owner.
    """

    def __init__(
        self,
        *,
        consumer: Any,
        producer: Any,
        processor: RetryProcessorRouter,
        clock: Callable[[], float] = time.time,
    ) -> None:
        super().__init__(consumer=consumer, producer=producer, processor=processor)
        self.clock = clock
        self._pending: dict[tuple[str, int], tuple[int, Any]] = {}

    def process_one(self, message: Any) -> bool:
        key = (message.topic(), message.partition())
        if key in self._pending:
            # Fail closed if a client ever returns an additional prefetched
            # message after pause, rather than acknowledging beyond held input.
            raise RuntimeError("received another record from a paused partition")
        headers = self._headers(message)
        if isinstance(self.processor.for_headers(headers), InvalidRetryProcessor):
            return super().process_one(message)
        try:
            due_ms = int(headers.get("retry_not_before_epoch_ms", "0"))
            if due_ms < 0 or due_ms > self.clock() * 1000 + 1_805_000:
                raise ValueError("deadline is outside the supported retry horizon")
        except ValueError:
            invalid = InvalidRetryProcessor("invalid retry_not_before_epoch_ms")
            return CanonicalKafkaWorker(
                consumer=self.consumer, producer=self.producer, processor=invalid
            ).process_one(message)

        if due_ms > self.clock() * 1000:
            self.consumer.pause([TopicPartition(*key)])
            self._pending[key] = (due_ms, message)
            return True  # Held, not acknowledged; other partitions can progress.
        return super().process_one(message)

    def process_due(self) -> bool:
        for key, (due_ms, message) in list(self._pending.items()):
            if due_ms > self.clock() * 1000:
                continue
            if not super().process_one(message):
                return False
            del self._pending[key]
            self.consumer.resume([TopicPartition(*key)])
        return True

    def on_revoke(self, _consumer: Any, partitions: list[Any]) -> None:
        for partition in partitions:
            self._pending.pop((partition.topic, partition.partition), None)
