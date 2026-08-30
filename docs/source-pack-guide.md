# Source Pack boundary

This document states the shared boundary only; it is not a Source Pack implementation or a detailed parser design.

SourcePack consumes RawEventEnvelope and produces ParsedEvent.

ParsedEvent mappings target canonical UnifiedEvent snake_case paths.

Source-specific values with no mapping must survive under a vendor namespace such as extensions.example_vendor.

Source Pack detailed detection, parsing and packaging design remains owned by Epic 2.

Use the reserved names in [engineering conventions](engineering-conventions.md) and the authoritative field reference in [event schema](event-schema.md). A planned Cisco ASA vertical slice must respect this boundary, but Cisco ASA collection and parsing are not implemented in Sprint 0.
