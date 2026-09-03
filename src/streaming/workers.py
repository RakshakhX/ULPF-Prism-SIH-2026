"""Composition helpers for live parser, normalizer, and retry workers."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path

from core.engine import ParsingEngine
from src.normalization import UniversalNormalizer, default_registry
from src.streaming.messages import ProcessingDecision
from src.streaming.processor import NormalizerProcessor, ParserProcessor, StreamProcessor
from src.streaming.topics import DEAD_LETTER_TOPIC


class InvalidRetryProcessor:
    """Preserve poison retry input in DLQ instead of crashing forever on it."""

    def __init__(self, reason: str) -> None:
        self.reason = reason

    def process(self, payload: bytes, *, attempt: int = 0) -> ProcessingDecision:
        identity = hashlib.sha256(payload).hexdigest()
        return ProcessingDecision(
            topic=DEAD_LETTER_TOPIC,
            key=identity,
            event_id=identity,
            payload=payload,
            terminal=True,
            error_code="INVALID_RETRY_METADATA",
            headers={"error_code": "INVALID_RETRY_METADATA", "error_message": self.reason},
        )


class RetryProcessorRouter:
    """Route a retry payload back to the processing stage that created it."""

    def __init__(
        self,
        *,
        parser: ParserProcessor,
        normalizer: NormalizerProcessor,
    ) -> None:
        self._processors: dict[str, StreamProcessor] = {
            "parser": parser,
            "normalizer": normalizer,
        }

    def for_headers(self, headers: Mapping[str, str]) -> StreamProcessor:
        stage = headers.get("retry_stage")
        if stage not in self._processors:
            return InvalidRetryProcessor("retry message has no recognized retry_stage header")
        return self._processors[stage]


def build_parser_processor(
    packs_dir: Path | str = "source_packs",
    **retry_options: int,
) -> ParserProcessor:
    return ParserProcessor(ParsingEngine(packs_dir), **retry_options)


def build_normalizer_processor(**retry_options: int) -> NormalizerProcessor:
    return NormalizerProcessor(
        UniversalNormalizer(default_registry()),
        **retry_options,
    )
