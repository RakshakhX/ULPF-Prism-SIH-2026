# ULPF Prism architecture

ULPF Prism’s target architecture separates device-specific work from the shared normalized contract. Only the schema and its Python validator are implemented in Sprint 0; the six operational components below are planned boundaries, not working services.

```text
Perimeter device
  -> Collection / RawEventEnvelope
  -> Parsing / ParsedEvent
  -> Normalization / UnifiedEvent
  -> Streaming
  -> Visibility and integration consumers
```

## Boundary purpose

Collection captures a device log as `RawEventEnvelope` without treating normalization as evidence preservation. Parsing produces `ParsedEvent` using source-specific knowledge. Normalization maps that result to the vendor-neutral `UnifiedEvent`; its schema and validator are the Sprint 0 artifacts. Streaming transports shared contracts. Visibility reads normalized records for search and dashboards, while Integration exports normalized records with raw references to storage or a data lake.

## Evidence linkage

Raw evidence stays authoritative in `RawEventEnvelope`. Every `UnifiedEvent` requires `traceability.raw_event_id` and `traceability.raw_sha256`, so a normalized record remains linked to raw evidence by stable ID and lowercase SHA-256 hash. `traceability.raw_event` is optional for self-contained exports and, when included, is hash-verified; it does not replace the authoritative raw record.

See [component boundaries](component-boundaries.md) for ownership and [the event schema](event-schema.md) for the implemented contract.
