# Epic 1 — Collection: agreed decisions

- **RawEventEnvelope structure**: see `src/collection/envelope.py` — 10 fields exactly as specified in the epic.
- **Event ID format**: UUID4 string (`uuid.uuid4()`), matches the `traceability.raw_event_id` UUID format in the UnifiedEvent schema.
- **Topic name**: `raw-event-stream` (constant `RAW_EVENT_TOPIC` in `publisher.py`).
- **Maximum accepted event size**: 65536 bytes (65 KB), configurable via `max_event_size_bytes` in `config/collector.example.json`.
- **Raw-event retention**: no automatic expiry/TTL is implemented in Sprint 0 — archived events and rejected-event records persist indefinitely on disk under `archive_store/` until a retention policy is agreed and implemented separately.
- **Rejected-event retention**: rejected events store a 512-byte sample (not the full oversized payload) plus full metadata, so "oversized" rejections don't themselves become an unbounded-storage problem.