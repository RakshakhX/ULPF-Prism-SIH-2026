# UnifiedEvent v1 research basis

**Project:** ULPF Prism — SIH 2026  
**Issue:** #9 — Define UnifiedEvent Schema v1  
**Reviewed:** 2026-08-30

This document records the standards and literature reviewed for UnifiedEvent v1.
The sources inform terminology and design boundaries; UnifiedEvent v1 remains a
technology-neutral internal contract and does not claim full conformance to any
external standard.

## Standards and literature decision table

| Source | Version/date used | Adopt | Do not claim or copy |
|---|---|---|---|
| OCSF | stable 1.8.0, released 2026-03-18 | category/type/action separation, reusable objects, requirement levels, extension boundary | Full OCSF compliance or numeric OCSF IDs |
| ECS | 9.5.0 | core versus extended fields, lowercase snake-case field sets, vendor-neutral analytics | Elasticsearch-specific mappings |
| OpenTelemetry Semantic Conventions | 1.44.0 | stable event identity, small frequent core, flexible attributes | Conformance to log attributes still marked Development |
| OWASP Logging Cheat Sheet | accessed 2026-08-30 | when/where/who/what, confidence, integrity and untrusted-source treatment | Logging secrets or sensitive payloads |
| JSON Schema | Draft 2020-12 | `$defs`, `if`/`then`, structural assertions and standard format checking | Treating cross-field semantics as purely structural |
| Drain | IEEE ICWS 2017 | deterministic streaming-parsing context | Adding parser implementation to issue #9 |
| Preprocessing is All You Need | 2024 preprint | preprocessing and parsing require separate evaluation | Assuming schema validation improves parser accuracy |
| Adaptive and Efficient Log Parsing as a Cloud Service | ACM SIGMOD Companion 2025 | throughput/accuracy/compute must be measured independently | Copying its cloud architecture or claiming its benchmark |

### Primary sources

- [OCSF schema releases](https://github.com/ocsf/ocsf-schema/releases)
- [OCSF: Understanding OCSF](https://github.com/ocsf/ocsf-docs/blob/main/overview/understanding-ocsf.md)
- [Elastic Common Schema](https://www.elastic.co/docs/reference/ecs)
- [OpenTelemetry Semantic Conventions](https://opentelemetry.io/docs/specs/semconv/)
- [OpenTelemetry Logs Data Model](https://opentelemetry.io/docs/specs/otel/logs/data-model/)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12)
- [Drain (IEEE ICWS 2017)](https://doi.org/10.1109/ICWS.2017.13)
- [Preprocessing is All You Need (2024 preprint)](https://arxiv.org/abs/2412.05254)
- [Adaptive and Efficient Log Parsing as a Cloud Service (ACM SIGMOD Companion 2025)](https://doi.org/10.1145/3722212.3724427)

## Implementation decisions

1. `event.id` is the stable per-record identifier and deduplication key.
2. `event.category`, `event.type` and `action.normalized` are separate
   classification dimensions.
3. Required top-level sections form the core; optional nested sections are
   extended fields.
4. The authoritative original event remains in `RawEventEnvelope`; therefore,
   `traceability.raw_event_id` and `traceability.raw_sha256` reference that
   authoritative raw evidence.
5. `traceability.raw_event` is opt-in for self-contained export only.
6. A first-level vendor namespace such as `extensions.example_vendor` is the
   unmapped-field escape hatch; first-level vendor extension namespaces must be
   lowercase `snake_case`.
7. `quality.parsing_confidence`, warnings and missing fields expose uncertainty
   rather than hiding it.
8. `event.message` is optional human-readable context; analytics must use
   normalized fields instead of parsing it.
9. Python validation is deterministic, offline-capable and contains no remote
   API or model dependency.
10. OCSF/ECS output adapters and formal conformance belong to Epic 6.

The required schema version for this contract is exactly `1.0.0`.

These decisions preserve a compact mandatory envelope while retaining
losslessness through raw-event references, explicit quality signals and the
vendor extension boundary. They also keep normalization separate from parser
implementation and from downstream export mappings.

## Stability and scope notes

- The OCSF basis is the **stable 1.8.0 release (2026-03-18)**. OCSF's `main`
  branch is a development version and is not treated as the v1 authority.
- OpenTelemetry Semantic Conventions 1.44.0 is used selectively. General log
  attributes that remain labeled **Development** are explicitly not a
  conformance target for UnifiedEvent v1.
- *Preprocessing is All You Need* is a **2024 preprint**, not a deployed
  standard. It supports the evaluation boundary between preprocessing and
  parsing; it does not establish schema-validation accuracy.
- Drain supplies deterministic streaming-parsing context only. Parser work is
  outside issue #9.
- JSON Schema structural validation cannot express every cross-field semantic
  invariant. Those invariants are implemented and tested by the deterministic
  offline Python validator.
- The external standards and papers are references for defensible design
  choices, not permission to copy proprietary mappings, numeric identifiers,
  cloud architectures, benchmarks, secrets or sensitive payloads.
