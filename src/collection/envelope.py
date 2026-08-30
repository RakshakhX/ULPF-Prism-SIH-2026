from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True)
class RawEventEnvelope:
    event_id: str
    ingested_at: str          # ISO 8601 UTC, ends in Z
    source_id: str | None
    source_ip: str | None
    transport: str            # "udp" | "tcp" | "file"
    raw_event: bytes
    raw_size: int
    content_hash: str         # lowercase sha256 hex
    collector_id: str
    collector_version: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, embed_raw_as_text: bool = True) -> dict[str, Any]:
        """JSON-serializable view. raw_event is embedded as UTF-8 text with
        errors replaced only for display; original bytes are never mutated."""
        d = {
            "event_id": self.event_id,
            "ingested_at": self.ingested_at,
            "source_id": self.source_id,
            "source_ip": self.source_ip,
            "transport": self.transport,
            "raw_size": self.raw_size,
            "content_hash": self.content_hash,
            "collector_id": self.collector_id,
            "collector_version": self.collector_version,
            "metadata": self.metadata,
        }
        if embed_raw_as_text:
            d["raw_event"] = self.raw_event.decode("utf-8", errors="surrogateescape")
        return d


def utc_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
