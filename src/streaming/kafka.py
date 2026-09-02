"""Thin Kafka adapter that keeps offset commits behind output delivery."""

from __future__ import annotations

from typing import Any

from src.streaming.processor import StreamProcessor


class CanonicalKafkaWorker:
    """Process one record and commit it only after its output is flushed."""

    def __init__(self, *, consumer: Any, producer: Any, processor: StreamProcessor) -> None:
        self.consumer = consumer
        self.producer = producer
        self.processor = processor

    def process_one(self, message: Any) -> bool:
        payload = message.value()
        if not isinstance(payload, bytes):
            raise TypeError("Kafka message value must be bytes")

        header_values = self._headers(message)
        processor = self.processor
        router = getattr(processor, "for_headers", None)
        if router is not None:
            processor = router(header_values)
        decision = processor.process(payload, attempt=self._attempt_value(header_values))
        headers = [(key, value.encode("utf-8")) for key, value in decision.headers.items()]
        delivery_errors: list[str] = []

        def on_delivery(error: Any, _message: Any) -> None:
            if error is not None:
                delivery_errors.append(str(error))

        self.producer.produce(
            topic=decision.topic,
            key=decision.key.encode("utf-8"),
            value=decision.payload,
            headers=headers,
            on_delivery=on_delivery,
        )

        if self.producer.flush() != 0 or delivery_errors:
            return False

        self.consumer.commit(message=message, asynchronous=False)
        return True

    @staticmethod
    def _headers(message: Any) -> dict[str, str]:
        header_getter = getattr(message, "headers", None)
        if header_getter is None:
            return {}
        headers = header_getter() or []
        decoded: dict[str, str] = {}
        for name, value in headers:
            try:
                decoded[name] = value.decode("utf-8") if isinstance(value, bytes) else str(value)
            except UnicodeDecodeError:
                continue
        return decoded

    @staticmethod
    def _attempt_value(headers: dict[str, str]) -> int:
        try:
            return max(int(headers.get("attempt", "0")), 0)
        except ValueError:
            return 0
