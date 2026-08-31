import json
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _utc_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass(frozen=True)
class RejectedEventRecord:
    """A durable record of a rejected/oversized event. We do NOT always
    store the full raw payload (an oversized event could be huge and
    storing it defeats the point of rejecting it) — instead we store a
    bounded sample plus enough metadata to explain and trace the rejection."""

    rejection_id: str
    rejected_at: str
    transport: str
    source_ip: str | None
    source_id: str | None
    reason: str
    raw_size: int
    raw_sample: str  # first N bytes, decoded best-effort, for evidence
    sample_truncated: bool
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rejection_id": self.rejection_id,
            "rejected_at": self.rejected_at,
            "transport": self.transport,
            "source_ip": self.source_ip,
            "source_id": self.source_id,
            "reason": self.reason,
            "raw_size": self.raw_size,
            "raw_sample": self.raw_sample,
            "sample_truncated": self.sample_truncated,
            "metadata": self.metadata,
        }


class RejectedEventLog:
    """Persists rejected events so 'rejected events include a rejection
    reason' is answerable after the fact, not just in the return value
    of a single ingest() call."""

    SAMPLE_BYTES = 512

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def record(
        self,
        raw: bytes,
        transport: str,
        reason: str,
        source_ip: str | None = None,
        source_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> RejectedEventRecord:
        sample_bytes = raw[: self.SAMPLE_BYTES]
        rec = RejectedEventRecord(
            rejection_id=str(uuid.uuid4()),
            rejected_at=_utc_now_iso(),
            transport=transport,
            source_ip=source_ip,
            source_id=source_id,
            reason=reason,
            raw_size=len(raw),
            raw_sample=sample_bytes.decode("utf-8", errors="replace"),
            sample_truncated=len(raw) > self.SAMPLE_BYTES,
            metadata=metadata or {},
        )
        path = self.root / f"{rec.rejection_id}.json"
        with self._lock:
            path.write_text(json.dumps(rec.to_dict(), ensure_ascii=False), encoding="utf-8")
        return rec

    def retrieve(self, rejection_id: str) -> dict[str, Any] | None:
        path = self.root / f"{rejection_id}.json"
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def list_by_reason(self, reason: str) -> list[dict[str, Any]]:
        results = []
        for path in self.root.glob("*.json"):
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("reason") == reason:
                results.append(data)
        return results
