from __future__ import annotations

import pytest
from confluent_kafka import TopicPartition

from src.contracts import RawEventEnvelope
from src.streaming.retry import RetryKafkaWorker
from src.streaming.workers import (
    RetryProcessorRouter,
    build_normalizer_processor,
    build_parser_processor,
)


class Message:
    def __init__(self, partition=0, offset=0, due="10000"):
        self.part, self.index, self.due = partition, offset, due

    def value(self):
        return (
            RawEventEnvelope.from_bytes(
                b"future device log", source_id="retry-test", transport="replay"
            )
            .model_dump_json()
            .encode()
        )

    def headers(self):
        return [("retry_stage", b"parser"), ("retry_not_before_epoch_ms", self.due.encode())]

    def topic(self):
        return "retry"

    def partition(self):
        return self.part

    def offset(self):
        return self.index


class Consumer:
    def __init__(self):
        self.commits, self.paused, self.resumed = [], [], []

    def commit(self, *, message, asynchronous):
        assert not asynchronous
        self.commits.append((message.partition(), message.offset()))

    def pause(self, partitions):
        self.paused.extend(partitions)

    def resume(self, partitions):
        self.resumed.extend(partitions)


class Producer:
    def __init__(self):
        self.calls, self.error = [], None

    def produce(self, **kwargs):
        self.calls.append(kwargs)
        kwargs["on_delivery"](self.error, None)

    def flush(self):
        return 0


@pytest.fixture
def runtime():
    consumer, producer, now = Consumer(), Producer(), [0.0]
    worker = RetryKafkaWorker(
        consumer=consumer,
        producer=producer,
        clock=lambda: now[0],
        processor=RetryProcessorRouter(
            parser=build_parser_processor(), normalizer=build_normalizer_processor()
        ),
    )
    return worker, consumer, producer, now


def test_future_retry_pauses_partition_without_processing_or_commit(runtime):
    worker, consumer, producer, now = runtime
    assert worker.process_one(Message())
    assert consumer.paused == [TopicPartition("retry", 0)]
    assert producer.calls == consumer.commits == []
    assert worker.process_due()
    assert producer.calls == []
    now[0] = 10.0
    assert worker.process_due()
    assert consumer.commits == [(0, 0)]
    assert consumer.resumed == [TopicPartition("retry", 0)]
    assert producer.calls[0]["topic"] == "parsed-event"


def test_other_partitions_progress_but_never_commit_past_deferred_record(runtime):
    worker, consumer, _producer, _now = runtime
    worker.process_one(Message())
    worker.process_one(Message(partition=1, due="0"))
    assert consumer.commits == [(1, 0)]
    with pytest.raises(RuntimeError, match="paused partition"):
        worker.process_one(Message(partition=0, offset=1, due="0"))
    assert consumer.commits == [(1, 0)]


def test_revoked_or_shutdown_deferred_records_remain_uncommitted(runtime):
    worker, consumer, producer, now = runtime
    worker.process_one(Message())
    worker.on_revoke(consumer, [TopicPartition("retry", 0)])
    now[0] = 20.0
    assert worker.process_due()
    assert producer.calls == consumer.commits == consumer.resumed == []


def test_failed_due_delivery_does_not_resume_or_commit(runtime):
    worker, consumer, producer, now = runtime
    worker.process_one(Message())
    producer.error = RuntimeError("unavailable")
    now[0] = 11.0
    assert not worker.process_due()
    assert consumer.commits == consumer.resumed == []


@pytest.mark.parametrize("due", ["garbage", "-1", "9999999999999"])
def test_invalid_schedule_goes_to_dlq_instead_of_crashing_or_stalling(runtime, due):
    worker, consumer, producer, _now = runtime
    assert worker.process_one(Message(due=due))
    assert producer.calls[0]["topic"] == "dead-letter"
    assert consumer.commits == [(0, 0)]
