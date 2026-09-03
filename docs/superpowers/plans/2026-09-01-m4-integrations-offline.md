# Milestone 4: SIEM, Data-Lake, Container, and Offline Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver tested SIEM serializers/delivery, Parquet/JSONL lake exports, one coherent container stack, and reproducible air-gapped bundle tooling.

**Architecture:** Output adapters share serialization, delivery accounting, health, and retry contracts. The application image and Compose profiles contain all runtime components; offline scripts assemble and verify dependencies and images without storing large archives in Git.

**Tech Stack:** Python 3.11, PyArrow, OpenSearch bulk API, CEF, RFC 5424 Syslog, Docker Compose, CycloneDX SBOM, pytest.

**Spec:** `docs/superpowers/specs/2026-09-01-full-platform-integration-design.md`

## Progress checkpoint — 2026-09-03

- Task 1: adapter contracts checkpointed in `1dc41cc`.
- Task 2: OpenSearch adapter/profile checkpointed in `69078d7`; no live target test yet.
- Task 3: JSONL/Parquet exports checkpointed in `3cd462f`.
- Task 4: container roles, broker publisher, safe retry scheduling and archive-ID
  replay implemented with regression coverage. Compose rendering, shell syntax,
  focused lint and unit tests verified. Image build was attempted but the Docker
  daemon was unavailable. Background role health probes and complete release
  dependency/base-image locking remain open; do not mark this task complete yet.
- Task 5: offline bundle tooling remains to be implemented. Grafana currently
  downloads its plugin at startup; the current stack is not air-gapped-ready.

Operational instructions and explicit limitations: `docs/container-stack.md`.

## Global Constraints

- No public-cloud or runtime internet dependency.
- Every output includes schema version and event traceability.
- Partial delivery reports accepted and failed counts separately.
- OpenSearch is described as a search/SIEM-integration target, not a complete SIEM by itself.
- Dependency versions and container images are pinned for release builds.

---

### Task 1: Common adapter contract and SIEM serializers

**Files:**
- Create: `src/integrations/base.py`
- Create: `src/integrations/json_adapter.py`
- Create: `src/integrations/cef.py`
- Create: `src/integrations/syslog.py`
- Create: `src/integrations/worker.py`
- Create: `src/integrations/__init__.py`
- Create: `tests/integrations/test_serializers.py`
- Create: `tests/integrations/test_delivery_worker.py`

**Interfaces:**
- Consumes: UnifiedEvent dictionary batches.
- Produces: `OutputAdapter.deliver(events) -> DeliveryResult`; `serialize_json(event) -> bytes`; `serialize_cef(event) -> bytes`; `serialize_rfc5424(event) -> bytes`; `AdapterDeliveryWorker.process(normalized_json) -> DeliveryDecision`.

- [ ] **Step 1: Write failing deterministic serialization tests**

```python
def test_cef_escapes_reserved_characters(valid_event):
    payload = serialize_cef(with_message(valid_event, r"deny|reason=a\\b"))
    assert b"deny\\|reason\\=a\\\\b" in payload
    assert valid_event["traceability"]["raw_sha256"].encode() in payload

def test_syslog_contains_schema_and_event_identity(valid_event):
    payload = serialize_rfc5424(valid_event)
    assert payload.startswith(b"<")
    assert b'schemaVersion="1.0.0"' in payload
    assert valid_event["event"]["id"].encode() in payload

def test_delivery_worker_retries_partial_delivery(fake_adapter, valid_event):
    fake_adapter.result = DeliveryResult(1, 0, 1, 0, ("timeout",))
    decision = AdapterDeliveryWorker(fake_adapter).process(json.dumps(valid_event).encode())
    assert not decision.acknowledge
    assert decision.retryable
```

- [ ] **Step 2: Confirm adapter package is absent**

Run: `pytest tests/integrations/test_serializers.py -q`

Expected: import failure for `src.integrations`.

- [ ] **Step 3: Implement serializers and delivery result**

```python
@dataclass(frozen=True)
class DeliveryResult:
    attempted: int
    delivered: int
    retryable_failures: int
    terminal_failures: int
    errors: tuple[str, ...] = ()
```

CEF escapes backslash, pipe, equals, newline, and carriage return. RFC 5424 emits UTC timestamps and structured data for schema version, event ID, raw hash, pack, and quality. JSON uses compact UTF-8 with sorted keys for reproducibility. The delivery worker consumes `normalized-event`, batches events, acknowledges only fully delivered batches, and converts retryable/terminal adapter outcomes into retry/DLQ decisions with event-count reconciliation.

- [ ] **Step 4: Verify serializers**

Run: `pytest tests/integrations/test_serializers.py tests/integrations/test_delivery_worker.py -q && ruff check src/integrations tests/integrations`

Expected: byte-level golden assertions pass.

- [ ] **Step 5: Commit**

```bash
git add src/integrations tests/integrations
git commit -m "feat: add SIEM output adapter contracts"
```

### Task 2: OpenSearch delivery profile

**Files:**
- Create: `src/integrations/opensearch.py`
- Modify: `schemas/opensearch-index-template-v1.json`
- Modify: `docker-compose.yml`
- Create: `tests/integrations/test_opensearch_adapter.py`
- Create: `deploy/opensearch/README.md`

**Interfaces:**
- Consumes: UnifiedEvent batches and OpenSearch endpoint/auth configuration.
- Produces: NDJSON `_bulk` requests keyed by event ID and reconciled `DeliveryResult`.

- [ ] **Step 1: Write failing bulk reconciliation tests**

```python
def test_bulk_result_counts_mixed_items(fake_transport, two_events):
    fake_transport.respond_bulk(statuses=[201, 429])
    result = OpenSearchAdapter(fake_transport).deliver(two_events)
    assert (result.delivered, result.retryable_failures, result.terminal_failures) == (1, 1, 0)
```

- [ ] **Step 2: Confirm adapter is missing**

Run: `pytest tests/integrations/test_opensearch_adapter.py -q`

Expected: import failure.

- [ ] **Step 3: Implement chunked bulk delivery and optional Compose profile**

Use `create`/`index` metadata with `_id = event.id`; classify 408/429/5xx as retryable and other 4xx as terminal. Add pinned OpenSearch service under profile `siem-search`, healthcheck, local volume, and template bootstrap. Document memory requirements and scope accurately.

- [ ] **Step 4: Verify profile and unit behavior**

Run: `pytest tests/integrations/test_opensearch_adapter.py -q && docker compose --profile siem-search config && ruff check src/integrations/opensearch.py tests/integrations/test_opensearch_adapter.py`

Expected: reconciliation tests and profile validation pass.

- [ ] **Step 5: Commit**

```bash
git add src/integrations/opensearch.py schemas/opensearch-index-template-v1.json docker-compose.yml tests/integrations/test_opensearch_adapter.py deploy/opensearch
git commit -m "feat: add OpenSearch integration profile"
```

### Task 3: Parquet lake partitions and manifests

**Files:**
- Create: `src/exports/models.py`
- Create: `src/exports/parquet.py`
- Create: `src/exports/jsonl.py`
- Create: `src/exports/__init__.py`
- Modify: `src/pipeline/exporter.py`
- Modify: `pyproject.toml`
- Create: `tests/exports/test_parquet_export.py`
- Create: `tests/exports/test_jsonl_export.py`

**Interfaces:**
- Consumes: UnifiedEvent batches.
- Produces: `ParquetExporter.export(events) -> ExportManifest`; Hive paths `year=YYYY/month=MM/day=DD/category=<category>/part-*.parquet`; separate quarantine partitions.

- [ ] **Step 1: Write failing partition and read-back tests**

```python
def test_parquet_partition_manifest_and_readback(tmp_path, valid_event, invalid_event):
    manifest = ParquetExporter(tmp_path).export([valid_event, invalid_event])
    assert manifest.total_events == 2
    assert manifest.valid_events == 1
    assert manifest.quarantine_events == 1
    table = pq.read_table(manifest.files[0].path)
    assert table.num_rows == 1
    assert verify_manifest(manifest)
```

- [ ] **Step 2: Confirm Parquet support is absent**

Run: `pytest tests/exports -q`

Expected: missing `src.exports`/PyArrow failure.

- [ ] **Step 3: Implement stable projection, partitions, atomic files, and checksums**

Write temporary files in the target directory and rename after success. Include full normalized JSON, event ID, schema version, category, observed time, raw event ID/hash, vendor, product, and quality. The manifest records relative path, rows, bytes, SHA-256, schema version, and totals; `verify_manifest()` rechecks every file.

- [ ] **Step 4: Verify export formats**

Run: `pytest tests/exports -q && ruff check src/exports src/pipeline/exporter.py tests/exports`

Expected: Parquet and JSONL read-back/count/checksum tests pass.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/exports src/pipeline/exporter.py tests/exports
git commit -m "feat: add verifiable Parquet data lake exports"
```

### Task 4: Complete application image and Compose topology

**Files:**
- Modify: `Dockerfile`
- Modify: `docker-compose.yml`
- Create: `.dockerignore`
- Create: `deploy/redpanda/init-topics.sh`
- Create: `tests/test_container_contract.py`
- Modify: `requirements.txt`
- Modify: `requirements-dev.txt`

**Interfaces:**
- Consumes: pinned application dependencies and environment variables.
- Produces: one image supporting API, collector, parser worker, normalizer worker, sink, and replay commands; Compose services for Redpanda, topic initializer, ClickHouse, Grafana, and application roles.

- [ ] **Step 1: Write failing static container contract tests**

```python
def test_image_contains_every_runtime_package():
    text = Path("Dockerfile").read_text()
    for required in ["COPY core/", "COPY src/", "COPY schemas/", "COPY source_packs/"]:
        assert required in text

def test_compose_declares_pipeline_roles(compose):
    assert {"redpanda", "topic-init", "collector", "parser-worker", "normalizer-worker", "clickhouse", "grafana"} <= set(compose["services"])
```

- [ ] **Step 2: Confirm current image/Compose is incomplete**

Run: `pytest tests/test_container_contract.py -q`

Expected: Dockerfile lacks `src/` and `schemas/`; services are absent.

- [ ] **Step 3: Add role commands, healthchecks, pinned images, and volumes**

Use one non-root application image. Services share explicit topic/broker/storage environment variables; startup dependencies use health conditions; persistent stores use named volumes; demo inputs use read-only mounts. Topic initialization is idempotent and creates all six specified topics.

- [ ] **Step 4: Verify static and rendered topology**

Run: `pytest tests/test_container_contract.py -q && docker compose config && docker build -t ulpf-prism:test .`

Expected: tests/config/build pass when Docker is available; record unavailable Docker as an environment limitation, not a passing result.

- [ ] **Step 5: Commit**

```bash
git add Dockerfile docker-compose.yml .dockerignore deploy/redpanda requirements.txt requirements-dev.txt tests/test_container_contract.py
git commit -m "build: package the complete ULPF platform"
```

### Task 5: Air-gapped bundle creation and verification

**Files:**
- Create: `scripts/offline/build_bundle.sh`
- Create: `scripts/offline/verify_bundle.py`
- Create: `scripts/offline/install_bundle.sh`
- Create: `deploy/offline/manifest.template.json`
- Create: `docs/air-gapped-deployment.md`
- Create: `tests/test_offline_bundle.py`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: release version and output directory.
- Produces: wheelhouse, application wheel, image archive, checksums, CycloneDX SBOM, manifest, install/verify instructions; `verify_bundle.py PATH` exits nonzero on missing or mismatched artifacts.

- [ ] **Step 1: Write failing verifier tests**

```python
def test_verifier_rejects_checksum_mismatch(tmp_path):
    bundle = make_fixture_bundle(tmp_path)
    bundle.joinpath("wheelhouse", "dependency.whl").write_bytes(b"tampered")
    result = run_verify(bundle)
    assert result.returncode != 0
    assert "checksum mismatch" in result.stderr.lower()
```

- [ ] **Step 2: Confirm scripts are absent**

Run: `pytest tests/test_offline_bundle.py -q`

Expected: verifier invocation fails because the script does not exist.

- [ ] **Step 3: Implement fail-closed bundle tooling**

`build_bundle.sh VERSION OUT_DIR` builds wheels with hashes, downloads locked wheels, exports all Compose images, creates an SBOM, and writes sorted SHA-256 checksums. `verify_bundle.py` validates manifest version, required paths, every checksum, and Compose image references. `install_bundle.sh` verifies first, loads images, installs from wheelhouse with `--no-index`, and runs `docker compose pull --policy never`/startup without network access.

- [ ] **Step 4: Verify milestone 4**

Run: `pytest tests/integrations tests/exports tests/test_container_contract.py tests/test_offline_bundle.py -q && ruff check src/integrations src/exports scripts/offline tests/integrations tests/exports tests/test_offline_bundle.py && docker compose config`

Expected: unit/static gates pass; no large generated archives appear in Git status.

- [ ] **Step 5: Commit**

```bash
git add scripts/offline deploy/offline docs/air-gapped-deployment.md tests/test_offline_bundle.py .gitignore
git commit -m "feat: add verifiable air gapped deployment bundle"
```
