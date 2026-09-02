import threading
import time
from collections import deque
from dataclasses import dataclass, field


@dataclass
class CollectorMetrics:
    latency_window_size: int = 128
    received: int = 0
    accepted: int = 0
    rejected: int = 0
    duplicates: int = 0
    bytes_received: int = 0
    _latencies_ms: deque[float] = field(init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        if self.latency_window_size <= 0:
            raise ValueError("latency_window_size must be greater than zero")
        self._latencies_ms = deque(maxlen=self.latency_window_size)

    def record_received(self, size: int) -> None:
        with self._lock:
            self.received += 1
            self.bytes_received += size

    def record_accepted(self) -> None:
        with self._lock:
            self.accepted += 1

    def record_rejected(self) -> None:
        with self._lock:
            self.rejected += 1

    def record_duplicate(self) -> None:
        with self._lock:
            self.duplicates += 1

    def record_latency(self, start_time: float) -> None:
        with self._lock:
            self._latencies_ms.append((time.monotonic() - start_time) * 1000)

    def health(self) -> dict:
        with self._lock:
            latencies = list(self._latencies_ms)
            received = self.received
            accepted = self.accepted
            rejected = self.rejected
            duplicates = self.duplicates
            bytes_received = self.bytes_received
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
        return {
            "status": "up",
            "received": received,
            "accepted": accepted,
            "rejected": rejected,
            "duplicates": duplicates,
            "bytes_received": bytes_received,
            "avg_latency_ms": round(avg_latency, 3),
        }

    @property
    def latency_sample_count(self) -> int:
        with self._lock:
            return len(self._latencies_ms)
