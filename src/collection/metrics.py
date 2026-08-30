import threading
import time
from dataclasses import dataclass, field


@dataclass
class CollectorMetrics:
    received: int = 0
    accepted: int = 0
    rejected: int = 0
    duplicates: int = 0
    bytes_received: int = 0
    _latencies_ms: list[float] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

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
            latencies = list(self._latencies_ms[-1000:])
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
        return {
            "status": "up",
            "received": self.received,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "duplicates": self.duplicates,
            "bytes_received": self.bytes_received,
            "avg_latency_ms": round(avg_latency, 3),
        }
