# Milestone 3: Persistent Analytical Storage and Unified Visibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist normalized events in ClickHouse and provide reproducible Grafana dashboards and multi-vendor investigation queries.

**Architecture:** A storage protocol keeps tests independent of infrastructure; the ClickHouse implementation uses batch insertion, idempotent event IDs, explicit quarantine, and query projections. Grafana is provisioned entirely from repository files.

**Tech Stack:** Python 3.11, ClickHouse, clickhouse-connect, Grafana, Docker Compose, pytest.

**Spec:** `docs/superpowers/specs/2026-09-01-full-platform-integration-design.md`

## Global Constraints

- ClickHouse and Grafana are the primary Epic 5 visibility stack.
- The full normalized JSON, extensions, quality, event ID, and raw SHA-256 remain queryable.
- Invalid events go to quarantine rather than the valid table.
- Unit tests do not require Docker; container integration tests use the `integration` marker.
- Fixtures use fictional documentation-safe data.

---

### Task 1: Storage protocol and ClickHouse schema

**Files:**
- Create: `src/storage/models.py`
- Create: `src/storage/base.py`
- Create: `src/storage/clickhouse.py`
- Create: `src/storage/__init__.py`
- Create: `deploy/clickhouse/init/001_events.sql`
- Modify: `src/pipeline/storage.py`
- Modify: `pyproject.toml`
- Test: `tests/storage/test_clickhouse_mapping.py`
- Create: `tests/storage/fakes.py`

**Interfaces:**
- Consumes: validated UnifiedEvent dictionaries.
- Produces: `AnalyticalEventSink.write_batch(events) -> WriteResult`; `ClickHouseEventStore.search(filters, limit) -> list[dict]`; `get_by_event_id()` and `get_by_raw_hash()`.

- [ ] **Step 1: Write failing mapping and quarantine tests**

```python
def test_valid_event_maps_to_searchable_row(valid_event):
    row = map_unified_event(valid_event)
    assert row.event_id == valid_event["event"]["id"]
    assert row.raw_sha256 == valid_event["traceability"]["raw_sha256"]
    assert json.loads(row.normalized_json) == valid_event

def test_invalid_event_is_quarantined(fake_client, invalid_event):
    result = ClickHouseEventStore(fake_client).write_batch([invalid_event])
    assert result.valid_count == 0
    assert result.quarantine_count == 1
```

- [ ] **Step 2: Confirm missing storage package**

Run: `pytest tests/storage/test_clickhouse_mapping.py -q`

Expected: import failure for `src.storage`.

- [ ] **Step 3: Implement schema, mapping, and result accounting**

```python
@dataclass(frozen=True)
class WriteResult:
    accepted_count: int
    valid_count: int
    quarantine_count: int
    failed_count: int
    errors: tuple[str, ...] = ()
```

Create `ulpf.events_v1` using `ReplacingMergeTree(normalized_at)`, partition by `toYYYYMM(observed_at)`, order by `(observed_at, event_id)`, and store normalized JSON plus projected vendor/product/category/action/severity/source/destination/quality/traceability columns. Create `ulpf.quarantine_v1` with event ID, raw hash, payload JSON, error codes, and quarantined time.

- [ ] **Step 4: Run storage unit checks**

Run: `pytest tests/storage/test_clickhouse_mapping.py -q && ruff check src/storage tests/storage`

Expected: mapping and quarantine tests pass.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/storage src/pipeline/storage.py deploy/clickhouse tests/storage
git commit -m "feat: add ClickHouse analytical event store"
```

### Task 2: Persistent queries and container integration

**Files:**
- Create: `tests/integration/test_clickhouse_store.py`
- Create: `src/storage/worker.py`
- Create: `tests/storage/test_sink_processor.py`
- Modify: `src/storage/clickhouse.py`
- Modify: `main.py`
- Modify: `pyproject.toml`
- Modify: `docker-compose.yml`

**Interfaces:**
- Consumes: ClickHouse URL/user/password/database environment configuration.
- Produces: parameterized filters for text, vendor, category, action, severity, quality, time range, event ID, and raw hash; aggregation queries; `ClickHouseSinkProcessor.process(normalized_json) -> WriteResult`; persistent API reads.

- [ ] **Step 1: Write marked integration tests**

```python
@pytest.mark.integration
def test_insert_search_deduplicate_and_trace(clickhouse_store, valid_event):
    clickhouse_store.write_batch([valid_event, valid_event])
    assert clickhouse_store.get_by_event_id(valid_event["event"]["id"])["event"]["id"] == valid_event["event"]["id"]
    assert len(clickhouse_store.search(vendor="cisco", limit=10)) == 1

def test_sink_acknowledges_only_after_storage_success(fake_store, valid_event):
    fake_store.fail_next = True
    decision = ClickHouseSinkProcessor(fake_store).process(json.dumps(valid_event).encode())
    assert not decision.acknowledge
    assert decision.retryable
```

- [ ] **Step 2: Confirm test is selectable but fails without implementation**

Run: `pytest tests/integration/test_clickhouse_store.py -q -m integration`

Expected: connection is skipped when `ULPF_CLICKHOUSE_URL` is absent or query methods fail against a running instance.

- [ ] **Step 3: Add ClickHouse Compose service and parameterized queries**

Add a pinned image, named data volume, healthcheck, init SQL mount, resource defaults, and application dependency on healthy ClickHouse. Never interpolate filter text into SQL; pass query parameters through the client. The sink worker consumes `normalized-event`, acknowledges only after `write_batch()` succeeds, and routes invalid records to the quarantine table. Replace in-memory analytics API reads with the configured `AnalyticalEventStore`, retaining the in-memory implementation only as a unit-test fake.

- [ ] **Step 4: Verify static Compose and live integration when available**

Run: `docker compose config && pytest tests/storage/test_sink_processor.py tests/integration/test_clickhouse_store.py -q`

Expected: Compose validates; integration passes when Docker is running, otherwise the documented environment guard skips it.

- [ ] **Step 5: Commit**

```bash
git add docker-compose.yml pyproject.toml src/storage main.py tests/storage/test_sink_processor.py tests/integration/test_clickhouse_store.py
git commit -m "feat: add persistent analytical queries"
```

### Task 3: Suricata Source Pack and dataset

**Files:**
- Create: `source_packs/suricata/manifest.yaml`
- Create: `source_packs/suricata/pack.py`
- Create: `source_packs/suricata/__init__.py`
- Create: `source_packs/suricata/samples/valid.jsonl`
- Create: `source_packs/suricata/samples/invalid.jsonl`
- Create: `src/normalization/mappings/suricata.py`
- Create: `tests/test_suricata_pack.py`
- Create: `tests/test_suricata_dataset.py`

**Interfaces:**
- Consumes: Suricata EVE JSON bytes.
- Produces: canonical `ParsedEvent` with pack ID `suricata_eve`; normalized network/threat events and quarantine-quality records.

- [ ] **Step 1: Write failing dataset-count and traceability tests**

```python
def test_dataset_has_required_cases():
    assert len(read_jsonl("source_packs/suricata/samples/valid.jsonl")) == 20
    assert len(read_lines("source_packs/suricata/samples/invalid.jsonl")) == 5

def test_valid_suricata_records_normalize_and_validate(engine, normalizer):
    for raw in read_raw_lines("source_packs/suricata/samples/valid.jsonl"):
        parsed = engine.process(make_envelope(raw))
        assert parsed.source_pack_id == "suricata_eve"
        assert validate_event(normalizer.normalize(parsed)).valid
```

- [ ] **Step 2: Confirm pack and fixtures are absent**

Run: `pytest tests/test_suricata_pack.py tests/test_suricata_dataset.py -q`

Expected: missing fixture/pack failures.

- [ ] **Step 3: Implement EVE parsing and fictional fixtures**

Recognize `event_type` values `alert`, `flow`, `dns`, and `http`; preserve the complete decoded JSON in extracted fields. Use RFC 5737 IPv4 and RFC 3849 IPv6 ranges, fictional hostnames, and timestamps fixed in 2026. Invalid fixtures cover malformed JSON, absent event type, invalid IP, invalid port, and missing timestamp.

- [ ] **Step 4: Verify dataset and cross-vendor queries**

Run: `pytest tests/test_suricata_pack.py tests/test_suricata_dataset.py tests/test_universal_normalizer.py -q && ruff check source_packs/suricata src/normalization/mappings/suricata.py tests/test_suricata_pack.py tests/test_suricata_dataset.py`

Expected: 20 valid records pass and 5 invalid records are rejected or quarantined for asserted reasons.

- [ ] **Step 5: Commit**

```bash
git add source_packs/suricata src/normalization/mappings/suricata.py tests
git commit -m "feat: add Suricata visibility dataset"
```

### Task 4: Provisioned Grafana visibility

**Files:**
- Create: `deploy/grafana/provisioning/datasources/clickhouse.yaml`
- Create: `deploy/grafana/provisioning/dashboards/default.yaml`
- Create: `deploy/grafana/dashboards/ulpf-overview.json`
- Create: `deploy/grafana/dashboards/ulpf-investigation.json`
- Modify: `docker-compose.yml`
- Create: `tests/test_grafana_provisioning.py`
- Modify: `docs/epic-5-analytical-storage-and-visibility.md`

**Interfaces:**
- Consumes: ClickHouse datasource UID `ulpf-clickhouse`.
- Produces: version-controlled overview and investigation dashboards with event provenance.

- [ ] **Step 1: Write failing provisioning contract tests**

```python
def test_dashboards_cover_required_panels():
    titles = dashboard_titles("deploy/grafana/dashboards")
    required = {"Total events", "Events over time", "Allow vs deny", "Severity", "Parse failures", "Dead letters", "Raw SHA-256"}
    assert required <= titles
```

- [ ] **Step 2: Confirm provisioning is absent**

Run: `pytest tests/test_grafana_provisioning.py -q`

Expected: missing provisioning files.

- [ ] **Step 3: Add pinned Grafana service, datasource, variables, and panels**

Provide filters for time, vendor, product, category, action, severity, and quality. Investigation table includes event ID, observed time, endpoints, action, quality, pack/parser versions, and raw SHA-256. Mount provisioning read-only and disable anonymous admin access by default.

- [ ] **Step 4: Verify milestone 3**

Run: `pytest tests/storage tests/test_suricata_pack.py tests/test_suricata_dataset.py tests/test_grafana_provisioning.py -q && docker compose config && ruff check src/storage source_packs/suricata tests/storage tests/test_grafana_provisioning.py`

Expected: static and unit gates pass; Compose renders valid ClickHouse/Grafana services.

- [ ] **Step 5: Commit**

```bash
git add deploy/grafana docker-compose.yml tests/test_grafana_provisioning.py docs/epic-5-analytical-storage-and-visibility.md
git commit -m "feat: provision unified Grafana visibility"
```
