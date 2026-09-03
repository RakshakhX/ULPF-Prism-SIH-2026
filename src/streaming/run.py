"""Runtime entry point for parser, normalizer, retry, and analytical sink roles."""

from __future__ import annotations

import argparse
import logging
import os
import signal
from collections.abc import Sequence
from typing import Any

from src.storage import ClickHouseEventStore, ClickHouseSinkProcessor, create_clickhouse_client
from src.streaming.kafka import CanonicalKafkaWorker
from src.streaming.retry import RetryKafkaWorker
from src.streaming.topics import (
    NORMALIZED_EVENT_TOPIC,
    PARSED_EVENT_TOPIC,
    RAW_EVENT_TOPIC,
    RETRY_TOPIC,
)
from src.streaming.workers import (
    RetryProcessorRouter,
    build_normalizer_processor,
    build_parser_processor,
)

LOGGER = logging.getLogger("ulpf.streaming")


class KafkaSinkWorker:
    """Commit normalized-event offsets only after ClickHouse accepts the record."""

    def __init__(self, *, consumer: Any, processor: ClickHouseSinkProcessor) -> None:
        self.consumer = consumer
        self.processor = processor

    def process_one(self, message: Any) -> bool:
        payload = message.value()
        if not isinstance(payload, bytes):
            raise TypeError("Kafka message value must be bytes")
        decision = self.processor.process(payload)
        if not decision.acknowledge:
            LOGGER.error("sink withheld offset commit: %s", decision.error_message)
            return False
        self.consumer.commit(message=message, asynchronous=False)
        return True


def _consumer(role: str, input_topic: str) -> Any:
    from confluent_kafka import Consumer

    brokers = os.environ.get("ULPF_KAFKA_BROKERS", "redpanda:9092")
    consumer = Consumer(
        {
            "bootstrap.servers": brokers,
            "group.id": os.environ.get("ULPF_GROUP_ID", f"ulpf-{role}-v1"),
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
            "enable.auto.offset.store": False,
        }
    )
    consumer.subscribe([input_topic])
    return consumer


def _producer() -> Any:
    from confluent_kafka import Producer

    return Producer(
        {
            "bootstrap.servers": os.environ.get("ULPF_KAFKA_BROKERS", "redpanda:9092"),
            "acks": "all",
            "enable.idempotence": True,
            "compression.type": "zstd",
        }
    )


def build_worker(role: str) -> tuple[Any, Any]:
    """Build a live worker and return it with its owned consumer."""
    topics = {
        "parser": RAW_EVENT_TOPIC,
        "normalizer": PARSED_EVENT_TOPIC,
        "retry": RETRY_TOPIC,
        "sink": NORMALIZED_EVENT_TOPIC,
    }
    consumer = _consumer(role, topics[role])
    if role == "sink":
        url = os.environ.get("ULPF_CLICKHOUSE_URL")
        if not url:
            raise RuntimeError("ULPF_CLICKHOUSE_URL is required for the sink role")
        store = ClickHouseEventStore(create_clickhouse_client(url))
        return KafkaSinkWorker(
            consumer=consumer, processor=ClickHouseSinkProcessor(store)
        ), consumer

    parser = build_parser_processor(os.environ.get("ULPF_SOURCE_PACKS_DIR", "source_packs"))
    normalizer = build_normalizer_processor()
    processors = {
        "parser": parser,
        "normalizer": normalizer,
        "retry": RetryProcessorRouter(parser=parser, normalizer=normalizer),
    }
    if role == "retry":
        worker = RetryKafkaWorker(
            consumer=consumer, producer=_producer(), processor=processors[role]
        )
        consumer.subscribe([RETRY_TOPIC], on_revoke=worker.on_revoke, on_lost=worker.on_revoke)
        return worker, consumer
    return (
        CanonicalKafkaWorker(
            consumer=consumer,
            producer=_producer(),
            processor=processors[role],
        ),
        consumer,
    )


def run(role: str) -> None:
    worker, consumer = build_worker(role)
    running = True

    def stop(_signum: int, _frame: Any) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    LOGGER.info("starting %s worker", role)
    try:
        while running:
            if isinstance(worker, RetryKafkaWorker) and not worker.process_due():
                raise RuntimeError("retry output was not durable; leaving offset uncommitted")
            message = consumer.poll(1.0)
            if message is None:
                continue
            if message.error():
                LOGGER.warning("consumer error: %s", message.error())
                continue
            if not worker.process_one(message):
                raise RuntimeError(
                    f"{role} output was not durable; exiting with input offset uncommitted"
                )
    finally:
        consumer.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run one ULPF streaming role")
    parser.add_argument("role", choices=("parser", "normalizer", "retry", "sink"))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=os.environ.get("ULPF_LOG_LEVEL", "INFO"))
    arguments = _parser().parse_args(argv)
    run(arguments.role)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
