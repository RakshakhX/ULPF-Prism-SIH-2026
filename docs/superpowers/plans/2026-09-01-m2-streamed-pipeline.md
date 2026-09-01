# Milestone 2: Streamed Parsing and Normalization Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run collector, parser, normalizer, retry, dead-letter, and replay through the canonical contracts rather than disconnected demo models.

**Architecture:** Source Pack routing produces canonical `ParsedEvent`; a mapping registry produces schema-validated `UnifiedEvent`; Kafka-compatible workers advance offsets only after durable downstream acknowledgment. Pure processors are separated from broker adapters so correctness is unit-testable without containers.

**Tech Stack:** Python 3.11, Pydantic v2, confluent-kafka 2.5.3, Redpanda, JSON Schema, pytest.

**Spec:** `docs/superpowers/specs/2026-09-01-full-platform-integration-design.md`

## Global Constraints

- Milestone 1 canonical contracts are the only cross-stage models.
- Failed and unknown parsing preserves raw evidence and produces quality data.
- Missing normalized values are not fabricated.
- Input offsets commit only after output acknowledgment or terminal DLQ acknowledgment.
- Replay preserves event identity.

---

### Task 1: Source Pack adapters and real registry loading

**Files:**
- Modify: `core/registry.py`
- Modify: `core/engine.py`
- Modify: `core/source_pack.py`
- Modify: `core/cisco_asa_pack.py`
- Modify: `source_packs/fortinet_fortigate/pack.py`
- Modify: `source_packs/generic_linux_syslog/pack.py`
- Create: `src/source_packs/loader.py`
- Test: `tests/test_engine.py`
- Test: `tests/test_cisco_asa_pack.py`
- Test: `tests/test_source_pack_registry.py`

**Interfaces:**
- Consumes: `RawEventEnvelope`.
- Produces: `SourcePackRegistry.match(envelope) -> SourcePackProtocol | None`; `ParsingEngine.process(envelope) -> ParsedEvent`.

- [ ] **Step 1: Write failing registry-routing tests**

```python
def test_registry_instantiates_manifest_implementation(tmp_path):
    write_manifest(tmp_path, implementation="source_packs.demo.pack:DemoPack")
    registry = SourcePackRegistry(tmp_path)
    assert type(registry.packs[0]).__name__ == "DemoPack"

def test_unknown_event_is_preserved(engine, raw_envelope):
    parsed = engine.process(raw_envelope)
    assert parsed.status is ParseStatus.UNRECOGNIZED
    assert parsed.raw_event.raw_sha256 == raw_envelope.raw_sha256
```

- [ ] **Step 2: Confirm current declarative-only registry fails**

Run: `pytest tests/test_source_pack_registry.py tests/test_engine.py tests/test_cisco_asa_pack.py -q`

Expected: custom implementation is not instantiated and old models mismatch.

- [ ] **Step 3: Implement one Source Pack protocol and import allowlist**

```python
class SourcePackProtocol(Protocol):
    pack_id: str
    priority: int
    def detect(self, envelope: RawEventEnvelope) -> float: ...
    def parse(self, envelope: RawEventEnvelope) -> ParsedEvent: ...
```

Resolve `module:class` only beneath `source_packs`, validate the class, instantiate it with manifest data, and reject invalid packs with `SourcePackValidationError`. Adapt Cisco, Fortinet, and generic Syslog implementations to canonical input/output.

- [ ] **Step 4: Run pack tests and lint**

Run: `pytest tests/test_source_pack_registry.py tests/test_engine.py tests/test_cisco_asa_pack.py source_packs/fortinet_fortigate/tests source_packs/generic_linux_syslog/tests -q && ruff check core src/source_packs source_packs tests/test_source_pack_registry.py`

Expected: all packs route through the registry and unknown input is lossless.

- [ ] **Step 5: Commit**

```bash
git add core src/source_packs source_packs tests
git commit -m "feat: route source packs through canonical contracts"
```

### Task 2: Registry-driven universal normalization

**Files:**
- Create: `src/normalization/models.py`
- Create: `src/normalization/registry.py`
- Create: `src/normalization/normalizer.py`
- Create: `src/normalization/mappings/cisco_asa.py`
- Create: `src/normalization/mappings/fortinet_fortigate.py`
- Create: `src/normalization/mappings/generic_linux_syslog.py`
- Create: `src/normalization/__init__.py`
- Modify: `src/pipeline/normalizer.py`
- Test: `tests/test_universal_normalizer.py`

**Interfaces:**
- Consumes: `ParsedEvent`.
- Produces: `NormalizationRegistry.register(source_pack_id, mapping)`; `UniversalNormalizer.normalize(parsed) -> dict[str, Any]` validated against UnifiedEvent v1.

- [ ] **Step 1: Write failing cross-vendor and no-fabrication tests**

```python
@pytest.mark.parametrize("pack_id", ["cisco_asa", "fortinet_fortigate", "generic_linux_syslog"])
def test_normalizer_preserves_extensions_and_traceability(pack_id, parsed_event_for):
    parsed = parsed_event_for(pack_id)
    unified = normalizer.normalize(parsed)
    assert unified["traceability"]["raw_sha256"] == parsed.raw_event.raw_sha256
    assert unified["extensions"][pack_id]
    assert validate_event(unified).valid

def test_missing_ip_is_not_replaced_with_documentation_ip(partial_parsed):
    unified = normalizer.normalize(partial_parsed)
    assert "ip" not in unified.get("source", {})
    assert "source.ip" in unified["quality"]["missing_fields"]
```

- [ ] **Step 2: Confirm Cisco-only normalizer fails**

Run: `pytest tests/test_universal_normalizer.py -q`

Expected: registry module is missing and current code fabricates fallback IP/device values.

- [ ] **Step 3: Implement mapping protocol and versioned registry**

```python
class NormalizationMapping(Protocol):
    source_pack_id: str
    version: str
    def map(self, event: ParsedEvent) -> dict[str, Any]: ...

class UniversalNormalizer:
    def normalize(self, parsed: ParsedEvent) -> dict[str, Any]:
        mapping = self.registry.get(parsed.source_pack_id)
        event = mapping.map(parsed) if mapping else self._unknown(parsed)
        result = validate_event(event)
        if not result.valid:
            event["quality"]["status"] = "invalid"
            event["quality"]["warnings"].extend(issue.message for issue in result.issues)
        return event
```

Every mapping copies unmapped extracted fields into `extensions[pack_id]` and records source-pack, parser, schema, mapping, and normalizer versions.

- [ ] **Step 4: Verify normalization**

Run: `pytest tests/test_universal_normalizer.py tests/test_schema_validation.py tests/test_semantic_validation.py -q && ruff check src/normalization tests/test_universal_normalizer.py`

Expected: cross-vendor events validate; partial events contain warnings without invented values.

- [ ] **Step 5: Commit**

```bash
git add src/normalization src/pipeline/normalizer.py tests/test_universal_normalizer.py
git commit -m "feat: add registry driven universal normalization"
```

### Task 3: Pure worker processors and broker adapters

**Files:**
- Create: `src/streaming/topics.py`
- Create: `src/streaming/messages.py`
- Create: `src/streaming/processor.py`
- Create: `src/streaming/kafka.py`
- Create: `src/streaming/workers.py`
- Create: `src/streaming/__init__.py`
- Retire after migration: `files/models.py`
- Retire after migration: `files/source_pack.py`
- Modify: `files/worker.py`
- Test: `tests/test_stream_processors.py`
- Modify: `tests/test_epic4_streaming_core.py`

**Interfaces:**
- Consumes: raw topic canonical JSON and parsed topic canonical JSON.
- Produces: `ParserProcessor.process(raw_json) -> ProcessingDecision`; `NormalizerProcessor.process(parsed_json) -> ProcessingDecision`; decision target is `parsed-event`, `normalized-event`, `retry`, or `dead-letter`.

- [ ] **Step 1: Write failing decision tests**

```python
def test_transient_failure_retries_without_identity_change(processor, raw_json):
    decision = processor.process(raw_json, attempt=2, forced_error=TransientProcessingError("broker"))
    assert decision.topic == "retry"
    assert decision.headers["attempt"] == "3"
    assert decision.event_id == RawEventEnvelope.model_validate_json(raw_json).event_id.hex

def test_poison_contract_goes_to_dlq(processor):
    decision = processor.process('{"invalid":true}')
    assert decision.topic == "dead-letter"
    assert decision.error_code == "INVALID_RAW_CONTRACT"
```

- [ ] **Step 2: Confirm missing pure processors**

Run: `pytest tests/test_stream_processors.py tests/test_epic4_streaming_core.py -q`

Expected: missing `src.streaming` imports.

- [ ] **Step 3: Implement deterministic processing decisions**

```python
@dataclass(frozen=True)
class ProcessingDecision:
    topic: str
    key: str
    payload: bytes
    headers: dict[str, str]
    terminal: bool
    error_code: str | None = None
```

Contract validation and deterministic parse failures go directly to DLQ. Dependency failures use capped exponential retry metadata. The Kafka loop must produce with `acks=all`, flush/check delivery, and only then commit the consumed message.

- [ ] **Step 4: Verify retry, DLQ, commit, and replay unit behavior**

Run: `pytest tests/test_stream_processors.py tests/test_epic4_streaming_core.py -q && ruff check src/streaming files/worker.py tests/test_stream_processors.py tests/test_epic4_streaming_core.py`

Expected: all decision and offset-order tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/streaming files tests/test_stream_processors.py tests/test_epic4_streaming_core.py
git commit -m "feat: add canonical streaming workers and reliability decisions"
```

### Task 4: Real end-to-end runner and API path

**Files:**
- Modify: `src/pipeline/runner.py`
- Modify: `main.py`
- Modify: `tests/test_end_to_end_cisco_path.py`
- Create: `tests/test_end_to_end_multi_vendor.py`
- Modify: `tests/test_cli.py`

**Interfaces:**
- Consumes: raw bytes through `CollectionPipeline`, `ParsingEngine`, and `UniversalNormalizer`.
- Produces: `PipelineRunner.process(raw, transport, source_id) -> PipelineResult`; `POST /v1/events` and explicit `python -m src.pipeline.demo` sample command.

- [ ] **Step 1: Write a failing test proving every real stage executes**

```python
def test_cisco_path_archives_parses_normalizes_and_indexes(real_runner, cisco_log):
    result = real_runner.process(cisco_log, transport="file", source_id="demo-fw")
    assert real_runner.archive.verify(str(result.raw_event.event_id))
    assert result.parsed.raw_event == result.raw_event
    assert result.unified["traceability"]["raw_sha256"] == result.raw_event.raw_sha256
    assert result.validation.valid
```

- [ ] **Step 2: Confirm current runner bypasses collector and registry**

Run: `pytest tests/test_end_to_end_cisco_path.py tests/test_end_to_end_multi_vendor.py -q`

Expected: assertions fail because the current runner directly constructs Cisco-specific models.

- [ ] **Step 3: Replace Cisco-only orchestration and remove startup sample mutation**

`PipelineRunner` receives archive, publisher, engine, normalizer, sink, and exporters via constructor. `POST /v1/events` accepts text or Base64 and returns stable stage status plus IDs. Application startup creates no sample events; a demo command loads fixtures explicitly.

- [ ] **Step 4: Verify milestone 2**

Run: `pytest tests/test_end_to_end_cisco_path.py tests/test_end_to_end_multi_vendor.py tests/test_cli.py tests/test_stream_processors.py tests/test_engine.py tests/test_universal_normalizer.py -q && ruff check core src main.py tests/test_end_to_end_multi_vendor.py`

Expected: real canonical paths pass without preloaded production state.

- [ ] **Step 5: Commit**

```bash
git add src/pipeline main.py tests
git commit -m "feat: connect the real end to end processing path"
```
