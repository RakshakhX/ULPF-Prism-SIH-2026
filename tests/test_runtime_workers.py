from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from src.collection.publisher import KafkaStreamPublisher
from src.contracts import RawEventEnvelope
from src.storage.worker import StorageDecision
from src.streaming.run import KafkaSinkWorker


class FakeProducer:
    def __init__(self, *, error: Exception | None = None, pending: int = 0) -> None:
        self.error = error
        self.pending = pending
        self.call: dict[str, Any] | None = None

    def produce(self, **kwargs: Any) -> None:
        self.call = kwargs
        kwargs["on_delivery"](self.error, None)

    def flush(self, timeout: float) -> int:
        assert timeout == 10.0
        return self.pending


def _envelope() -> RawEventEnvelope:
    return RawEventEnvelope.from_bytes(
        b"<34>Oct 11 22:14:15 edge sshd[42]: login failed",
        source_id="runtime-test",
        transport="file",
    )


def test_kafka_publisher_keys_raw_event_by_stable_event_id() -> None:
    producer = FakeProducer()
    envelope = _envelope()

    KafkaStreamPublisher(producer).publish(envelope)

    assert producer.call is not None
    assert producer.call["topic"] == "raw-event"
    assert producer.call["key"] == str(envelope.event_id).encode()
    assert RawEventEnvelope.model_validate_json(producer.call["value"]) == envelope


@pytest.mark.parametrize(
    ("producer", "message"),
    [
        (FakeProducer(error=RuntimeError("rejected")), "rejected"),
        (FakeProducer(pending=1), "still pending"),
    ],
)
def test_kafka_publisher_surfaces_non_durable_delivery(
    producer: FakeProducer, message: str
) -> None:
    with pytest.raises(RuntimeError, match=message):
        KafkaStreamPublisher(producer).publish(_envelope())


class FakeMessage:
    def value(self) -> bytes:
        return b'{"normalized":true}'


class FakeConsumer:
    def __init__(self) -> None:
        self.committed = False

    def commit(self, **_kwargs: Any) -> None:
        self.committed = True


class FakeSinkProcessor:
    def __init__(self, decision: StorageDecision) -> None:
        self.decision = decision

    def process(self, _payload: bytes) -> StorageDecision:
        return self.decision


def test_sink_commits_only_after_storage_acceptance() -> None:
    consumer = FakeConsumer()
    worker = KafkaSinkWorker(
        consumer=consumer,
        processor=FakeSinkProcessor(StorageDecision(True, False)),
    )

    assert worker.process_one(FakeMessage())
    assert consumer.committed


def test_sink_withholds_commit_after_storage_failure() -> None:
    consumer = FakeConsumer()
    worker = KafkaSinkWorker(
        consumer=consumer,
        processor=FakeSinkProcessor(StorageDecision(False, True, "STORE_FAILED", "offline")),
    )

    assert not worker.process_one(FakeMessage())
    assert not consumer.committed


def test_container_commands_reference_importable_runtime_modules() -> None:
    assert Path("src/collection/run.py").is_file()
    assert Path("src/streaming/run.py").is_file()
