import json
from pathlib import Path

from core.engine import ParsingEngine
from src.collection.publisher import RAW_EVENT_TOPIC as COLLECTION_RAW_EVENT_TOPIC
from src.contracts import ParsedEvent, RawEventEnvelope
from src.normalization import UniversalNormalizer, default_registry
from src.streaming import (
    DEAD_LETTER_TOPIC,
    NORMALIZED_EVENT_TOPIC,
    PARSED_EVENT_TOPIC,
    RAW_EVENT_TOPIC,
    RETRY_TOPIC,
    CanonicalKafkaWorker,
    NormalizerProcessor,
    ParserProcessor,
    RetryProcessorRouter,
    TransientProcessingError,
)


def raw_json(payload: bytes) -> bytes:
    envelope = RawEventEnvelope.from_bytes(
        payload,
        source_id="stream-test",
        transport="replay",
    )
    return envelope.model_dump_json().encode()


def parser_processor(max_attempts: int = 5) -> ParserProcessor:
    return ParserProcessor(
        ParsingEngine(Path("source_packs")),
        max_attempts=max_attempts,
        backoff_base_seconds=10,
        backoff_cap_seconds=60,
    )


def test_parser_success_routes_canonical_parsed_event() -> None:
    payload = raw_json(b"<34>Oct 11 22:14:15 server-1 sshd[42]: Failed password for alice")

    decision = parser_processor().process(payload)
    parsed = ParsedEvent.model_validate_json(decision.payload)

    assert decision.topic == PARSED_EVENT_TOPIC
    assert decision.terminal is True
    assert decision.key == str(parsed.event_id)
    assert parsed.source_pack_id == "generic_linux_syslog"


def test_transient_failure_retries_without_identity_change() -> None:
    payload = raw_json(b"temporary dependency failure")
    envelope = RawEventEnvelope.model_validate_json(payload)

    decision = parser_processor().process(
        payload,
        attempt=2,
        forced_error=TransientProcessingError("broker unavailable"),
    )

    assert decision.topic == RETRY_TOPIC
    assert decision.headers["attempt"] == "3"
    assert decision.headers["retry_after_seconds"] == "40"
    assert int(decision.headers["retry_not_before_epoch_ms"]) > 0
    assert decision.headers["retry_stage"] == "parser"
    assert decision.event_id == str(envelope.event_id)
    assert decision.payload == payload
    assert decision.terminal is False


def test_parser_catches_transient_dependency_failure() -> None:
    payload = raw_json(b"dependency failure from parser")
    envelope = RawEventEnvelope.model_validate_json(payload)

    class UnavailableEngine:
        def process(self, _envelope):
            raise TransientProcessingError("source pack registry unavailable")

    decision = ParserProcessor(UnavailableEngine()).process(payload)

    assert decision.topic == RETRY_TOPIC
    assert decision.event_id == str(envelope.event_id)
    assert decision.payload == payload


def test_transient_failure_exhaustion_goes_to_dead_letter() -> None:
    payload = raw_json(b"temporary dependency failure")

    decision = parser_processor(max_attempts=3).process(
        payload,
        attempt=3,
        forced_error=TransientProcessingError("still unavailable"),
    )

    assert decision.topic == DEAD_LETTER_TOPIC
    assert decision.error_code == "TRANSIENT_RETRIES_EXHAUSTED"
    assert decision.terminal is True


def test_invalid_raw_contract_goes_directly_to_dead_letter() -> None:
    decision = parser_processor().process(b'{"invalid":true}')

    assert decision.topic == DEAD_LETTER_TOPIC
    assert decision.error_code == "INVALID_RAW_CONTRACT"
    assert decision.headers["attempt"] == "0"
    assert decision.terminal is True


def test_replay_of_same_envelope_preserves_event_identity() -> None:
    payload = raw_json(b"future unrecognized vendor bytes")
    processor = parser_processor()

    first = ParsedEvent.model_validate_json(processor.process(payload).payload)
    replayed = ParsedEvent.model_validate_json(processor.process(payload).payload)

    assert replayed.event_id == first.event_id
    assert replayed.raw_event == first.raw_event


def test_normalizer_routes_schema_valid_unified_event() -> None:
    raw_payload = raw_json(b"<34>Oct 11 22:14:15 server-1 sshd[42]: Failed password for alice")
    parsed_payload = parser_processor().process(raw_payload).payload
    processor = NormalizerProcessor(UniversalNormalizer(default_registry()))

    decision = processor.process(parsed_payload)
    unified = json.loads(decision.payload)

    assert decision.topic == NORMALIZED_EVENT_TOPIC
    assert decision.event_id == unified["event"]["id"]
    assert unified["traceability"]["raw_sha256"]


def test_normalizer_catches_transient_dependency_failure() -> None:
    raw_payload = raw_json(b"dependency failure from normalizer")
    parsed_payload = parser_processor().process(raw_payload).payload
    parsed = ParsedEvent.model_validate_json(parsed_payload)

    class UnavailableNormalizer:
        def normalize(self, _parsed):
            raise TransientProcessingError("mapping dependency unavailable")

    decision = NormalizerProcessor(UnavailableNormalizer()).process(parsed_payload)

    assert decision.topic == RETRY_TOPIC
    assert decision.event_id == str(parsed.event_id)
    assert decision.payload == parsed_payload
    assert decision.headers["retry_stage"] == "normalizer"


def test_retry_router_selects_the_original_processing_stage() -> None:
    parser = parser_processor()
    normalizer = NormalizerProcessor(UniversalNormalizer(default_registry()))
    router = RetryProcessorRouter(parser=parser, normalizer=normalizer)

    assert router.for_headers({"retry_stage": "parser"}) is parser
    assert router.for_headers({"retry_stage": "normalizer"}) is normalizer


def test_invalid_parsed_contract_goes_directly_to_dead_letter() -> None:
    processor = NormalizerProcessor(UniversalNormalizer(default_registry()))

    decision = processor.process(b'{"invalid":true}')

    assert decision.topic == DEAD_LETTER_TOPIC
    assert decision.error_code == "INVALID_PARSED_CONTRACT"


class FakeMessage:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def value(self) -> bytes:
        return self._payload


class FakeProducer:
    def __init__(
        self,
        events: list[str],
        pending_after_flush: int = 0,
        delivery_error: Exception | None = None,
    ) -> None:
        self.events = events
        self.pending_after_flush = pending_after_flush
        self.delivery_error = delivery_error

    def produce(self, **kwargs) -> None:
        self.events.append(f"produce:{kwargs['topic']}")
        if self.delivery_error is not None:
            kwargs["on_delivery"](self.delivery_error, None)

    def flush(self) -> int:
        self.events.append("flush")
        return self.pending_after_flush


class FakeConsumer:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def commit(self, *, message, asynchronous: bool) -> None:
        assert asynchronous is False
        self.events.append("commit")


def test_kafka_worker_commits_only_after_output_acknowledgment() -> None:
    events: list[str] = []
    worker = CanonicalKafkaWorker(
        consumer=FakeConsumer(events),
        producer=FakeProducer(events),
        processor=parser_processor(),
    )

    committed = worker.process_one(FakeMessage(raw_json(b"unknown but valid envelope")))

    assert committed is True
    assert events == [f"produce:{PARSED_EVENT_TOPIC}", "flush", "commit"]


def test_kafka_worker_withholds_commit_when_delivery_is_pending() -> None:
    events: list[str] = []
    worker = CanonicalKafkaWorker(
        consumer=FakeConsumer(events),
        producer=FakeProducer(events, pending_after_flush=1),
        processor=parser_processor(),
    )

    committed = worker.process_one(FakeMessage(raw_json(b"unknown but valid envelope")))

    assert committed is False
    assert events == [f"produce:{PARSED_EVENT_TOPIC}", "flush"]


def test_kafka_worker_withholds_commit_when_delivery_callback_reports_error() -> None:
    events: list[str] = []
    worker = CanonicalKafkaWorker(
        consumer=FakeConsumer(events),
        producer=FakeProducer(events, delivery_error=RuntimeError("broker rejected output")),
        processor=parser_processor(),
    )

    committed = worker.process_one(FakeMessage(raw_json(b"valid canonical input")))

    assert committed is False
    assert events == [f"produce:{PARSED_EVENT_TOPIC}", "flush"]


def test_collection_and_streaming_use_the_same_raw_topic() -> None:
    assert COLLECTION_RAW_EVENT_TOPIC == RAW_EVENT_TOPIC == "raw-event"
