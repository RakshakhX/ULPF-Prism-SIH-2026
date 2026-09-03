"""Transport-neutral output adapter contracts and delivery accounting."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class DeliveryResult:
    attempted: int
    delivered: int
    retryable_failures: int
    terminal_failures: int
    errors: tuple[str, ...] = ()

    @property
    def reconciled(self) -> bool:
        return (
            self.attempted >= 0
            and min(self.delivered, self.retryable_failures, self.terminal_failures) >= 0
            and self.delivered + self.retryable_failures + self.terminal_failures
            == self.attempted
        )


class OutputAdapter(Protocol):
    def deliver(self, events: list[dict[str, Any]]) -> DeliveryResult: ...
