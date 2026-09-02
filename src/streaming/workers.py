"""Composition helpers for live parser, normalizer, and retry workers."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from core.engine import ParsingEngine
from src.normalization import UniversalNormalizer, default_registry
from src.streaming.processor import NormalizerProcessor, ParserProcessor, StreamProcessor


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
            raise ValueError("retry message is missing a recognized retry_stage header")
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
