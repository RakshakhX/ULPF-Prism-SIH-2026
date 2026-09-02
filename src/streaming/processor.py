"""Canonical parse and normalize processors with explicit failure routing."""

from __future__ import annotations

import hashlib
import json
import time
from typing import Protocol

from pydantic import ValidationError

from core.engine import ParsingEngine
from src.contracts import ParsedEvent, RawEventEnvelope
from src.normalization import UniversalNormalizer
from src.streaming.messages import ProcessingDecision
from src.streaming.topics import (
    DEAD_LETTER_TOPIC,
    NORMALIZED_EVENT_TOPIC,
    PARSED_EVENT_TOPIC,
    RETRY_TOPIC,
)


class TransientProcessingError(RuntimeError):
    """A processing failure that may succeed if the same payload is retried."""


class StreamProcessor(Protocol):
    def process(self, payload: bytes, *, attempt: int = 0) -> ProcessingDecision: ...


def _opaque_identity(payload: bytes) -> str:
    """Give malformed evidence a stable correlation key without changing it."""

    return hashlib.sha256(payload).hexdigest()


class _RetryPolicy:
    retry_stage = "unknown"

    def __init__(
        self,
        *,
        max_attempts: int = 5,
        backoff_base_seconds: int = 15,
        backoff_cap_seconds: int = 1800,
    ) -> None:
        if max_attempts < 0:
            raise ValueError("max_attempts cannot be negative")
        if backoff_base_seconds <= 0 or backoff_cap_seconds <= 0:
            raise ValueError("retry backoff values must be positive")
        self.max_attempts = max_attempts
        self.backoff_base_seconds = backoff_base_seconds
        self.backoff_cap_seconds = backoff_cap_seconds

    def _retry_or_dead_letter(
        self,
        *,
        payload: bytes,
        event_id: str,
        attempt: int,
        error: TransientProcessingError,
    ) -> ProcessingDecision:
        if attempt >= self.max_attempts:
            return ProcessingDecision(
                topic=DEAD_LETTER_TOPIC,
                key=event_id,
                payload=payload,
                event_id=event_id,
                terminal=True,
                headers={
                    "attempt": str(attempt),
                    "retry_stage": self.retry_stage,
                    "error_code": "TRANSIENT_RETRIES_EXHAUSTED",
                    "error_message": str(error)[:512],
                },
                error_code="TRANSIENT_RETRIES_EXHAUSTED",
            )

        next_attempt = attempt + 1
        delay = min(
            self.backoff_base_seconds * (2**attempt),
            self.backoff_cap_seconds,
        )
        not_before_epoch_ms = int((time.time() + delay) * 1000)
        return ProcessingDecision(
            topic=RETRY_TOPIC,
            key=event_id,
            payload=payload,
            event_id=event_id,
            terminal=False,
            headers={
                "attempt": str(next_attempt),
                "retry_stage": self.retry_stage,
                "retry_after_seconds": str(delay),
                "retry_not_before_epoch_ms": str(not_before_epoch_ms),
                "error_code": "TRANSIENT_PROCESSING_ERROR",
                "error_message": str(error)[:512],
            },
            error_code="TRANSIENT_PROCESSING_ERROR",
        )

    @staticmethod
    def _invalid_contract(
        *,
        payload: bytes,
        attempt: int,
        error_code: str,
        error: Exception,
    ) -> ProcessingDecision:
        identity = _opaque_identity(payload)
        return ProcessingDecision(
            topic=DEAD_LETTER_TOPIC,
            key=identity,
            payload=payload,
            event_id=identity,
            terminal=True,
            headers={
                "attempt": str(attempt),
                "error_code": error_code,
                "error_message": str(error)[:512],
            },
            error_code=error_code,
        )


class ParserProcessor(_RetryPolicy):
    """Validate a raw envelope and route its canonical parsed representation."""

    retry_stage = "parser"

    def __init__(self, engine: ParsingEngine, **retry_options: int) -> None:
        super().__init__(**retry_options)
        self.engine = engine

    def process(
        self,
        payload: bytes,
        *,
        attempt: int = 0,
        forced_error: TransientProcessingError | None = None,
    ) -> ProcessingDecision:
        try:
            envelope = RawEventEnvelope.model_validate_json(payload)
        except (ValidationError, ValueError) as error:
            return self._invalid_contract(
                payload=payload,
                attempt=attempt,
                error_code="INVALID_RAW_CONTRACT",
                error=error,
            )

        event_id = str(envelope.event_id)
        if forced_error is not None:
            return self._retry_or_dead_letter(
                payload=payload,
                event_id=event_id,
                attempt=attempt,
                error=forced_error,
            )

        try:
            parsed = self.engine.process(envelope)
        except TransientProcessingError as error:
            return self._retry_or_dead_letter(
                payload=payload,
                event_id=event_id,
                attempt=attempt,
                error=error,
            )
        return ProcessingDecision(
            topic=PARSED_EVENT_TOPIC,
            key=event_id,
            payload=parsed.model_dump_json().encode("utf-8"),
            event_id=event_id,
            terminal=True,
            headers={"attempt": str(attempt), "contract_version": parsed.contract_version},
        )


class NormalizerProcessor(_RetryPolicy):
    """Validate a parsed event and route its analytics-ready representation."""

    retry_stage = "normalizer"

    def __init__(self, normalizer: UniversalNormalizer, **retry_options: int) -> None:
        super().__init__(**retry_options)
        self.normalizer = normalizer

    def process(
        self,
        payload: bytes,
        *,
        attempt: int = 0,
        forced_error: TransientProcessingError | None = None,
    ) -> ProcessingDecision:
        try:
            parsed = ParsedEvent.model_validate_json(payload)
        except (ValidationError, ValueError) as error:
            return self._invalid_contract(
                payload=payload,
                attempt=attempt,
                error_code="INVALID_PARSED_CONTRACT",
                error=error,
            )

        event_id = str(parsed.event_id)
        if forced_error is not None:
            return self._retry_or_dead_letter(
                payload=payload,
                event_id=event_id,
                attempt=attempt,
                error=forced_error,
            )

        try:
            normalized = self.normalizer.normalize(parsed)
        except TransientProcessingError as error:
            return self._retry_or_dead_letter(
                payload=payload,
                event_id=event_id,
                attempt=attempt,
                error=error,
            )
        normalized_payload = json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return ProcessingDecision(
            topic=NORMALIZED_EVENT_TOPIC,
            key=event_id,
            payload=normalized_payload,
            event_id=event_id,
            terminal=True,
            headers={"attempt": str(attempt), "schema_version": normalized["schema_version"]},
        )
