# Milestone 1: Canonical Contracts and Collection Reliability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace incompatible raw/parsed models with one lossless contract and make collection acceptance bounded, thread-safe, archive-first, and testable.

**Architecture:** Pydantic v2 models under `src/contracts/` are the only cross-stage contracts. Collectors create a Base64-backed `RawEventEnvelope`, archive it before publication, and use bounded concurrency-safe metrics and duplicate tracking.

**Tech Stack:** Python 3.11, Pydantic v2, pytest 9, Ruff, standard-library Base64/SHA-256/deque/locks.

**Spec:** `docs/superpowers/specs/2026-09-01-full-platform-integration-design.md`

## Global Constraints

- Runtime language is Python 3.11 or newer.
- Serialized raw evidence is Base64 plus exact byte length and lowercase SHA-256.
- Accepted events are archived before downstream publication.
- No event is silently changed, truncated, or discarded.
- Resource tracking is bounded and thread-safe.
- Use tests first and make one focused commit per task.

---

### Task 1: Canonical raw-event contract

**Files:**
- Create: `src/contracts/raw_event.py`
- Create: `src/contracts/__init__.py`
- Test: `tests/contracts/test_raw_event.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Consumes: `bytes`, source/collector metadata.
- Produces: `RawEventEnvelope.from_bytes(raw: bytes, **metadata) -> RawEventEnvelope`, `raw_bytes() -> bytes`, and JSON round-trip through `model_dump_json()` / `model_validate_json()`.

- [ ] **Step 1: Add Pydantic v2 explicitly and write failing contract tests**

```python
def test_non_utf8_round_trip():
    raw = b"\x00\xff\x80ASA\n"
    event = RawEventEnvelope.from_bytes(raw, source_id="fw-1", transport="udp")
    restored = RawEventEnvelope.model_validate_json(event.model_dump_json())
    assert restored.raw_bytes() == raw
    assert restored.raw_size == len(raw)
    assert restored.raw_sha256 == hashlib.sha256(raw).hexdigest()

def test_rejects_hash_mismatch():
    event = RawEventEnvelope.from_bytes(b"original", source_id="fw-1", transport="file")
    with pytest.raises(ValidationError):
        RawEventEnvelope.model_validate({**event.model_dump(), "raw_sha256": "0" * 64})
```

- [ ] **Step 2: Confirm the focused test fails**

Run: `pytest tests/contracts/test_raw_event.py -q`

Expected: collection fails because `src.contracts.raw_event` does not exist.

- [ ] **Step 3: Implement the immutable model and validators**

```python
class RawEventEnvelope(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    contract_version: Literal["1.0.0"] = "1.0.0"
    event_id: UUID
    ingested_at: datetime
    source_id: str
    source_ip: IPvAnyAddress | None = None
    transport: Literal["udp", "tcp", "file", "api", "replay"]
    raw_payload_b64: str
    raw_size: int = Field(ge=0)
    raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    collector_id: str
    collector_version: str
    metadata: dict[str, Any] = Field(default_factory=dict)

    def raw_bytes(self) -> bytes:
        return base64.b64decode(self.raw_payload_b64, validate=True)

    @model_validator(mode="after")
    def verify_evidence(self) -> "RawEventEnvelope":
        raw = self.raw_bytes()
        if len(raw) != self.raw_size or hashlib.sha256(raw).hexdigest() != self.raw_sha256:
            raise ValueError("raw evidence size or SHA-256 mismatch")
        return self
```

`from_bytes()` must set a UUID event ID, UTC timestamp, Base64, length, hash, and configurable collector identity.

- [ ] **Step 4: Run focused and lint checks**

Run: `pytest tests/contracts/test_raw_event.py -q && ruff check src/contracts tests/contracts`

Expected: all tests pass and Ruff reports no findings.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/contracts tests/contracts
git commit -m "feat: add canonical lossless raw event contract"
```

### Task 2: Canonical parsed-event contract

**Files:**
- Create: `src/contracts/parsed_event.py`
- Modify: `src/contracts/__init__.py`
- Test: `tests/contracts/test_parsed_event.py`

**Interfaces:**
- Consumes: canonical `RawEventEnvelope`.
- Produces: `ParsedEvent`, `ParseStatus`, `ParseIssue`, `ParseIssueSeverity`; factory `ParsedEvent.unrecognized(raw_event, reason)`.

- [ ] **Step 1: Write failing success, failure, and preservation tests**

```python
def test_failure_keeps_complete_envelope():
    raw = RawEventEnvelope.from_bytes(b"garbled\xff", source_id="fw-1", transport="udp")
    parsed = ParsedEvent.unrecognized(raw, "no source pack matched")
    assert parsed.raw_event == raw
    assert parsed.status is ParseStatus.UNRECOGNIZED
    assert parsed.issues[0].code == "NO_SOURCE_PACK_MATCH"
```

- [ ] **Step 2: Confirm the test fails**

Run: `pytest tests/contracts/test_parsed_event.py -q`

Expected: import failure for `src.contracts.parsed_event`.

- [ ] **Step 3: Implement strict parsed models**

```python
class ParseStatus(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    UNRECOGNIZED = "unrecognized"

class ParseIssue(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    code: str
    message: str
    severity: Literal["warning", "error", "critical"]
    field: str | None = None

class ParsedEvent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    contract_version: Literal["1.0.0"] = "1.0.0"
    event_id: UUID
    parsed_at: datetime
    vendor: str | None
    product: str | None
    product_version: str | None
    parser_id: str
    parser_version: str
    source_pack_id: str | None
    source_pack_version: str | None
    detected_format: str
    status: ParseStatus
    issues: tuple[ParseIssue, ...] = ()
    extracted_fields: dict[str, Any] = Field(default_factory=dict)
    raw_event: RawEventEnvelope
```

Add a model validator requiring `event_id == raw_event.event_id`; errors are structured data and cannot remove the raw envelope.

- [ ] **Step 4: Verify focused tests and exports**

Run: `pytest tests/contracts -q && ruff check src/contracts tests/contracts`

Expected: all contract tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/contracts tests/contracts
git commit -m "feat: add canonical parsed event contract"
```

### Task 3: Archive-first collection with bounded state

**Files:**
- Modify: `src/collection/pipeline.py`
- Modify: `src/collection/archive.py`
- Modify: `src/collection/metrics.py`
- Modify: `src/collection/config.py`
- Create: `src/collection/dedup.py`
- Test: `tests/test_pipeline.py`
- Test: `tests/test_archive.py`
- Test: `tests/test_hashing_envelope.py`
- Create: `tests/test_collection_bounds.py`

**Interfaces:**
- Consumes: `RawEventEnvelope` from Task 1.
- Produces: `CollectionPipeline.ingest(...) -> IngestResult`; `BoundedHashCache(max_entries: int).check_and_add(hash_value: str) -> bool`; metrics `health()` with bounded latency samples.

- [ ] **Step 1: Replace old-envelope expectations with failing canonical-contract tests**

```python
def test_archive_occurs_before_publish(tmp_path):
    calls = []
    archive = RecordingArchive(tmp_path, calls)
    publisher = RecordingPublisher(calls)
    result = CollectionPipeline(publisher, archive).ingest(b"event", "udp", source_id="fw-1")
    assert result.accepted
    assert calls == ["archive", "publish"]

def test_bounded_state_under_many_unique_events(pipeline):
    for index in range(500):
        pipeline.ingest(str(index).encode(), "file", source_id="fixture")
    assert pipeline.dedup_size <= 64
    assert pipeline.metrics.latency_sample_count <= 128
```

- [ ] **Step 2: Run the reliability tests and observe failures**

Run: `pytest tests/test_pipeline.py tests/test_archive.py tests/test_hashing_envelope.py tests/test_collection_bounds.py -q`

Expected: failures for old field names, publish-before-archive order, and unbounded state.

- [ ] **Step 3: Implement archive-first ingestion and bounded structures**

```python
class BoundedHashCache:
    def __init__(self, max_entries: int):
        self._entries: OrderedDict[str, None] = OrderedDict()
        self._max_entries = max_entries
        self._lock = Lock()

    def check_and_add(self, value: str) -> bool:
        with self._lock:
            duplicate = value in self._entries
            self._entries[value] = None
            self._entries.move_to_end(value)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)
            return duplicate
```

Use `deque(maxlen=config.latency_window_size)` for latency. In `ingest`, validate size, create the canonical envelope, call `archive.store(envelope)`, then `publisher.publish(envelope)`, and return accepted only after both succeed. Archive failure returns `archive_failed`; publication failure returns `publish_failed` while retaining the archived event.

- [ ] **Step 4: Run collection and regression suites**

Run: `pytest tests/test_pipeline.py tests/test_archive.py tests/test_hashing_envelope.py tests/test_collection_bounds.py tests/test_collectors_integration.py -q && ruff check src/collection tests`

Expected: tests pass with no lint findings in changed files.

- [ ] **Step 5: Commit**

```bash
git add src/collection tests
git commit -m "fix: make collection lossless and resource bounded"
```

### Task 4: TCP frame bounds and canonical migration compatibility

**Files:**
- Modify: `src/collection/tcp_collector.py`
- Modify: `src/collection/udp_collector.py`
- Modify: `src/collection/file_collector.py`
- Modify: `src/collection/publisher.py`
- Modify: `src/collection/run.py`
- Test: `tests/test_collectors_integration.py`
- Create: `tests/test_tcp_collector_bounds.py`

**Interfaces:**
- Consumes: canonical envelope and `CollectorConfig.max_event_size_bytes`, `tcp_read_timeout_seconds`.
- Produces: newline-delimited TCP framing that rejects an over-limit frame before unbounded buffering; JSON publishers serialize canonical models.

- [ ] **Step 1: Write a failing oversized-frame test**

```python
def test_tcp_rejects_frame_before_delimiter(tmp_path):
    pipeline = recording_pipeline(max_event_size_bytes=16)
    collector = TCPCollector(pipeline, read_timeout_seconds=0.2)
    collector.handle_chunks([b"A" * 10, b"B" * 10])
    assert pipeline.accepted == []
    assert pipeline.rejections[0].reason == "oversized_event"
```

- [ ] **Step 2: Confirm failure**

Run: `pytest tests/test_tcp_collector_bounds.py tests/test_collectors_integration.py -q`

Expected: the frame grows beyond the limit or the required interface is missing.

- [ ] **Step 3: Enforce limits during accumulation and canonical serialization**

Maintain a `bytearray`; after every chunk, if its length exceeds `max_event_size_bytes`, record exactly one rejection, clear/close the frame, and do not call `ingest`. Configure socket timeout and close idle connections. Replace `.to_dict()` calls with `model_dump(mode="json")`.

- [ ] **Step 4: Verify milestone 1**

Run: `pytest tests/contracts tests/test_pipeline.py tests/test_archive.py tests/test_hashing_envelope.py tests/test_collection_bounds.py tests/test_collectors_integration.py tests/test_tcp_collector_bounds.py -q && ruff check src/contracts src/collection tests/contracts tests/test_collection_bounds.py tests/test_tcp_collector_bounds.py`

Expected: milestone tests and lint pass.

- [ ] **Step 5: Commit**

```bash
git add src/collection tests/test_collectors_integration.py tests/test_tcp_collector_bounds.py
git commit -m "fix: bound collector framing and canonical serialization"
```
