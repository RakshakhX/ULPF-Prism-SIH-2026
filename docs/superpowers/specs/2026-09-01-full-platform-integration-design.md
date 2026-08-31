# ULPF Prism Full Platform Integration Design

## Status

Approved direction: incrementally integrate and harden the existing prototype. Preserve working behavior, remove incompatible duplicate contracts, and complete the remaining Epic 5 and Epic 6 acceptance paths without rewriting the repository from scratch.

## Objective

Deliver one reproducible, containerized ULPF Prism path that accepts perimeter-device logs, preserves exact raw evidence, parses vendor-specific attributes, normalizes them into `UnifiedEvent` v1, transports events reliably, supports persistent unified visibility, exports to SIEM and data-lake formats, and can be prepared for air-gapped installation.

The implementation is a competition-grade reference architecture and working prototype. It must demonstrate horizontal scaling mechanisms and measured local capacity, but it must not claim that the prototype itself processed billions of events per day.

## Guiding decisions

1. Python 3.11 remains the application language.
2. Existing working modules are adapted behind shared contracts rather than discarded.
3. Shared contracts live only under `src/contracts/`.
4. Raw evidence is represented losslessly as Base64 plus byte length and SHA-256 when serialized.
5. Redpanda is the Kafka-compatible local streaming backbone.
6. ClickHouse and Grafana are the primary Epic 5 analytical visibility stack because the approved epic explicitly requires them.
7. Existing OpenSearch assets remain an optional SIEM/search integration profile, not the primary analytical store.
8. PyArrow produces Parquet data-lake exports.
9. The complete local platform is started through one root Docker Compose file with optional profiles for heavyweight integration targets.
10. Runtime code must not require public-cloud services or an internet connection.

## Scope decomposition

The work is divided into five independently testable milestones. Each milestone must leave the repository usable and green.

1. Canonical contracts and lossless collection reliability.
2. Real streamed collector-to-normalizer operating path.
3. Persistent analytical storage and unified visibility.
4. SIEM/data-lake adapters and offline deployment tooling.
5. Reliability benchmarks, documentation, and final demonstration evidence.

## Canonical contracts

### `RawEventEnvelope`

The canonical raw contract must contain:

- `contract_version`
- `event_id` as UUID
- `ingested_at` as UTC ISO 8601
- `source_id`
- `source_ip`
- `transport`
- `raw_payload_b64`
- `raw_size`
- `raw_sha256`
- `collector_id`
- `collector_version`
- `metadata`

The model exposes `from_bytes()` and `raw_bytes()` helpers. Hash and byte length are validated whenever the model is constructed or deserialized. Arbitrary non-UTF-8 payloads must round-trip without alteration.

### `ParsedEvent`

The canonical parsed contract must contain:

- `contract_version`
- `event_id`
- `parsed_at`
- vendor, product and optional product version
- parser ID and version
- Source Pack ID and version
- detected format
- parse status
- structured warnings and errors
- extracted fields
- a complete canonical `RawEventEnvelope`

Source-specific fields are retained without renaming inside `extracted_fields`. Parsing failures produce a `ParsedEvent` with structured quality information rather than dropping the event.

### `UnifiedEvent`

`schemas/unified-event-v1.schema.json` remains authoritative. The normalizer consumes canonical `ParsedEvent` and produces dictionaries validated by the existing structural and semantic validators. Vendor fields not mapped to the common taxonomy are preserved under a vendor namespace in `extensions`.

## End-to-end data flow

```text
Device UDP/TCP/File input
        -> CollectionPipeline
        -> raw archive
        -> raw-event topic
        -> parser worker group
        -> parsed-event topic
        -> normalizer worker group
        -> normalized-event topic
        -> ClickHouse sink
        -> Grafana visibility

normalized-event topic
        -> JSON / CEF / Syslog SIEM adapters
        -> Parquet data-lake exporter

processing failures
        -> retry topic
        -> dead-letter topic after retry exhaustion
```

The archive is the authoritative evidence store. Stream messages carry the complete raw envelope so workers can replay independently, but normalized records refer to raw evidence through ID and SHA-256.

## Collection reliability

The collector must archive accepted evidence before acknowledging successful ingestion. Downstream publishing failures are surfaced and retryable without deleting the archive.

The implementation must:

- preserve arbitrary bytes;
- bound TCP frame size before a delimiter arrives;
- bound per-connection buffer and timeouts;
- replace the unbounded duplicate set with a configurable bounded cache;
- replace the unbounded latency list with a bounded rolling window;
- make duplicate detection thread-safe;
- define explicit behavior for empty and oversized events;
- record rejected-event hashes and reasons;
- never report acceptance when neither durable archive nor configured evidence store succeeded.

## Source Packs and parsing

The parser registry loads declarative manifests and optional custom pack implementations through one documented mechanism. A custom pack must actually be instantiated when declared; tests must verify routing through the registry, not only direct class construction.

Initial demonstrated packs are:

- Cisco ASA
- Fortinet FortiGate
- generic Linux Syslog
- Suricata for the Epic 5 dataset

Unknown logs return an unparsed `ParsedEvent`. Invalid Source Packs are rejected during registry loading with understandable validation errors.

## Normalization

The normalizer is registry-driven rather than Cisco-only. A normalizer mapping selects behavior by Source Pack ID and maps common fields for timestamps, network endpoints, protocols, action, outcome, severity, observer identity, category, and quality.

Missing values are not fabricated. Invalid or absent fields generate quality warnings. All original extracted fields remain in `extensions`. Schema, Source Pack, parser, mapping and normalizer versions are recorded.

## Streaming and reliability

The streaming backbone uses these topics:

- `raw-event`
- `parsed-event`
- `normalized-event`
- `retry`
- `dead-letter`
- `framework-metrics`

Workers commit an input offset only after the next durable output or terminal dead-letter action succeeds. Event ID is the idempotency key. Transient errors enter retry with attempt count and next-attempt metadata. Poison events enter dead-letter with the original envelope and error details. Replay can select offsets or timestamps without generating a new identity for the same raw evidence.

The prototype demonstrates consumer-group scaling and reports measured EPS, latency, CPU, memory, retry, dead-letter and lag metrics. Capacity projections state their assumptions.

## Analytical storage and visibility

### ClickHouse

The primary table maps every searchable `UnifiedEvent` field, retains the full normalized JSON, extensions, quality data and traceability references, and uses:

- event date partitioning;
- observed time and event ID ordering;
- event ID deduplication behavior;
- batch insertion;
- explicit insertion-error reporting.

Invalid normalized events are quarantined rather than inserted into the valid table.

### Grafana

Version-controlled provisioning and dashboards provide:

- total events and events over time;
- events by vendor, device and category;
- allow versus deny;
- severity distribution;
- top source/destination IPs and ports;
- unknown sources, parse failures and quality warnings;
- throughput, latency, retry and dead-letter counts;
- investigation filters and provenance display.

The existing HTML dashboard remains a lightweight fallback demonstration, not the primary persistent visibility implementation.

### Suricata dataset

The repository includes 20 valid and 5 incomplete or malformed fictional Suricata records. Valid records pass the public validator. Invalid records fail or enter quarantine for documented reasons. All addresses and identifiers are documentation-safe and fictional.

## SIEM integration

All output adapters implement a common interface for configuration, serialization, batch or continuous delivery, retry classification, metrics and health reporting.

Required adapters:

- normalized JSON;
- CEF;
- RFC 5424 Syslog;
- optional OpenSearch bulk indexing as a demonstrated search and SIEM-integration target.

Every adapter includes schema-version metadata and event-count reconciliation. Delivery failures are visible and retryable.

## Data-lake export

The Parquet exporter writes Hive-style partitions:

```text
year=YYYY/month=MM/day=DD/category=<event-category>/part-*.parquet
```

Exports include schema version and raw-evidence references. A manifest records files, counts, byte sizes and SHA-256 hashes. Read-back validation confirms that files are readable and exported counts match input counts. Invalid records are exported separately as quarantine data.

JSONL remains a supported lightweight export format.

## Container and air-gap design

The root Compose stack contains:

- ULPF API/demo service;
- Redpanda and console;
- topic initializer;
- collector/replay entry point;
- parser worker;
- normalizer worker;
- ClickHouse;
- Grafana;
- optional OpenSearch profile.

Every image and Python dependency is pinned. The application image includes `core/`, `src/`, `schemas/`, Source Packs and required configuration.

Offline tooling produces:

- a Python wheelhouse;
- a container-image archive command and manifest;
- SHA-256 checksums;
- a CycloneDX-compatible software bill of materials;
- offline configuration templates;
- installation, verification, upgrade and rollback instructions.

An offline verification script checks that required files exist, verifies checksums and starts the stack with image pulling disabled. Large image archives are generated artifacts and are not committed to Git.

## API and demonstration

The FastAPI service provides health, parsing, end-to-end ingestion, analytical query and export endpoints. Startup must not silently preload sample events into production state; sample loading is an explicit demo command.

One reproducible demonstration command processes Cisco ASA valid and invalid events through every real stage, verifies the raw hash, searches the persistent normalized event, displays provenance, and validates JSONL and Parquet manifests.

## Error handling

- Contract violations are rejected with stable error codes.
- Parser and normalizer failures preserve the original envelope.
- Storage and export failures report accepted and failed counts separately.
- Retryable and terminal errors are distinguished explicitly.
- No component logs complete raw payloads by default.
- Health endpoints distinguish liveness from readiness.

## Testing strategy

Every behavioral change follows test-driven development.

Required test layers:

1. Contract unit tests, including non-UTF-8 round trips and hash mismatch rejection.
2. Collector reliability and bounded-resource tests.
3. Source Pack registry and malformed-input tests.
4. Normalizer mapping, extension and traceability tests.
5. Worker retry, dead-letter, replay and idempotency tests.
6. ClickHouse mapping/query tests with a repository-local fake for unit tests and an optional container integration marker.
7. Adapter serialization, delivery and reconciliation tests.
8. Parquet write/read-back tests.
9. Dockerfile and Compose static contract tests.
10. One full logical pipeline integration test that uses the real contracts and stage implementations.

CI runs formatting, Ruff and pytest across all maintained Python packages. Container-aware tests are a separate job or documented local gate when the hosted environment cannot run nested containers.

## Acceptance criteria

The integration milestone is complete when:

- one canonical raw and parsed contract is used across components;
- arbitrary bytes round-trip and hashes verify;
- real stage implementations complete the Cisco ASA path;
- invalid events reach quarantine without silent loss;
- retry, dead-letter and replay behavior is tested;
- persistent ClickHouse queries and Grafana provisioning exist;
- Suricata fixtures and cross-vendor queries exist;
- JSON, CEF, Syslog, JSONL and Parquet outputs are tested;
- the OpenSearch integration profile is demonstrated and documented without claiming that OpenSearch alone is a complete SIEM;
- the application and complete Compose configuration validate;
- offline bundle tooling, checksums, SBOM and guides exist;
- full pytest and Ruff gates pass;
- benchmark evidence reports measured results and limitations;
- README and architecture documents match implemented behavior.

## Non-goals

- Proving actual billion-event production throughput on student hardware.
- Building a new message broker, database, SIEM or visualization product.
- Implementing advanced SIEM detection rules or ML models.
- Shipping large container archives in Git.
- Depending on public-cloud services.

## Migration strategy

Migration is incremental:

1. Add canonical contracts and adapters while retaining old models temporarily.
2. Move collection and parser tests to canonical contracts.
3. Move the Cisco demo and streaming workers to the canonical path.
4. Remove legacy duplicate models only after all callers migrate.
5. Add persistent sinks and output adapters behind stable interfaces.

This prevents a repository-wide flag day and keeps each milestone independently reviewable.
