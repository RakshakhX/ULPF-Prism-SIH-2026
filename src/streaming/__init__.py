"""Canonical streaming processors and transport adapters."""

from src.streaming.kafka import CanonicalKafkaWorker
from src.streaming.messages import ProcessingDecision
from src.streaming.processor import (
    NormalizerProcessor,
    ParserProcessor,
    TransientProcessingError,
)
from src.streaming.topics import (
    DEAD_LETTER_TOPIC,
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

__all__ = [
    "CanonicalKafkaWorker",
    "DEAD_LETTER_TOPIC",
    "NORMALIZED_EVENT_TOPIC",
    "NormalizerProcessor",
    "PARSED_EVENT_TOPIC",
    "ParserProcessor",
    "ProcessingDecision",
    "RAW_EVENT_TOPIC",
    "RETRY_TOPIC",
    "RetryProcessorRouter",
    "TransientProcessingError",
    "build_normalizer_processor",
    "build_parser_processor",
]
