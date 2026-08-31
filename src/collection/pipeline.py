import time
from dataclasses import dataclass
from typing import Any

from .archive import RawEventArchive
from .envelope import RawEventEnvelope, utc_now_iso
from .hashing import new_event_id, sha256_hex
from .metrics import CollectorMetrics
from .publisher import RawEventPublisher
from .rejected import RejectedEventLog

COLLECTOR_ID = "ulpf-collector-01"
COLLECTOR_VERSION = "0.1.0"


@dataclass
class IngestResult:
    accepted: bool
    envelope: RawEventEnvelope | None
    reason: str | None = None
    duplicate: bool = False


@dataclass
class CollectorConfig:
    max_event_size_bytes: int = 65536


class CollectionPipeline:
    """Transport-agnostic core: every collector (UDP/TCP/file) calls
    ingest() with the raw bytes it received. Nothing here parses or
    normalizes the event."""

    def __init__(
        self,
        publisher: RawEventPublisher,
        archive: RawEventArchive,
        rejected_log: RejectedEventLog | None = None,
        config: CollectorConfig | None = None,
        metrics: CollectorMetrics | None = None,
    ) -> None:
        self.publisher = publisher
        self.archive = archive
        self.rejected_log = rejected_log
        self.config = config or CollectorConfig()
        self.metrics = metrics or CollectorMetrics()
        self._seen_hashes: set[str] = set()

    def ingest(
        self,
        raw: bytes,
        transport: str,
        source_ip: str | None = None,
        source_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> IngestResult:
        start = time.monotonic()
        size = len(raw)
        self.metrics.record_received(size)

        # Empty / malformed input never crashes the collector — it is
        # recorded as a rejection with a reason instead.
        if size == 0:
            reason = "empty_event"
            self.metrics.record_rejected()
            if self.rejected_log:
                self.rejected_log.record(raw, transport, reason, source_ip, source_id, metadata)
            self.metrics.record_latency(start)
            return IngestResult(accepted=False, envelope=None, reason=reason)

        if size > self.config.max_event_size_bytes:
            reason = "oversized_event"
            self.metrics.record_rejected()
            if self.rejected_log:
                self.rejected_log.record(raw, transport, reason, source_ip, source_id, metadata)
            self.metrics.record_latency(start)
            return IngestResult(accepted=False, envelope=None, reason=reason)

        content_hash = sha256_hex(raw)
        is_duplicate = content_hash in self._seen_hashes
        self._seen_hashes.add(content_hash)

        envelope = RawEventEnvelope(
            event_id=new_event_id(),
            ingested_at=utc_now_iso(),
            source_id=source_id,
            source_ip=source_ip,
            transport=transport,
            raw_event=raw,
            raw_size=size,
            content_hash=content_hash,
            collector_id=COLLECTOR_ID,
            collector_version=COLLECTOR_VERSION,
            metadata={**(metadata or {}), "duplicate": is_duplicate},
        )

        # Duplicates are still preserved as full evidence, never silently dropped.
        self.publisher.publish(envelope)
        self.archive.store(envelope)
        self.metrics.record_accepted()
        if is_duplicate:
            self.metrics.record_duplicate()
        self.metrics.record_latency(start)

        return IngestResult(accepted=True, envelope=envelope, duplicate=is_duplicate)
