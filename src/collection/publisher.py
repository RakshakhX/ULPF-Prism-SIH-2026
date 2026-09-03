import json
import threading
from pathlib import Path
from typing import Any, Protocol

from src.contracts import RawEventEnvelope
from src.streaming.topics import RAW_EVENT_TOPIC


class RawEventPublisher(Protocol):
    def publish(self, envelope: RawEventEnvelope) -> None: ...


class InMemoryPublisher:
    """Used by tests / other in-process consumers."""

    def __init__(self) -> None:
        self.topic = RAW_EVENT_TOPIC
        self._messages: list[dict] = []
        self._lock = threading.Lock()

    def publish(self, envelope: RawEventEnvelope) -> None:
        with self._lock:
            self._messages.append(envelope.model_dump(mode="json"))

    def messages(self) -> list[dict]:
        with self._lock:
            return list(self._messages)


class FileStreamPublisher:
    """Append-only newline-delimited JSON file standing in for a real topic."""

    def __init__(self, stream_path: Path) -> None:
        self.topic = RAW_EVENT_TOPIC
        self.stream_path = stream_path
        self.stream_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def publish(self, envelope: RawEventEnvelope) -> None:
        line = json.dumps(envelope.model_dump(mode="json"), ensure_ascii=False)
        with self._lock:
            with self.stream_path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")


class KafkaStreamPublisher:
    """Publish archived raw envelopes to the canonical broker topic."""

    def __init__(self, producer: Any, *, flush_timeout_seconds: float = 10.0) -> None:
        self.topic = RAW_EVENT_TOPIC
        self.producer = producer
        self.flush_timeout_seconds = flush_timeout_seconds

    def publish(self, envelope: RawEventEnvelope) -> None:
        errors: list[str] = []

        def delivered(error: Any, _message: Any) -> None:
            if error is not None:
                errors.append(str(error))

        self.producer.produce(
            topic=self.topic,
            key=str(envelope.event_id).encode(),
            value=envelope.model_dump_json().encode(),
            on_delivery=delivered,
        )
        pending = self.producer.flush(self.flush_timeout_seconds)
        if pending or errors:
            detail = "; ".join(errors) if errors else f"{pending} message(s) still pending"
            raise RuntimeError(f"raw-event publish failed: {detail}")
