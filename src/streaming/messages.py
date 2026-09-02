"""Transport-independent decisions emitted by streaming processors."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ProcessingDecision:
    """One durable output decision for one consumed input record."""

    topic: str
    key: str
    payload: bytes
    event_id: str
    terminal: bool
    headers: dict[str, str] = field(default_factory=dict)
    error_code: str | None = None
