# Component boundaries and ownership

The following target ownership table is the shared handoff contract. It does not mean every component is implemented in Sprint 0. In particular, Visibility remains intentionally unassigned until a team member takes it on.

| Component | Owner | Input | Output |
|---|---|---|---|
| Collection | Daksh R Jain | device log | `RawEventEnvelope` |
| Parsing | Garvit Mundra | `RawEventEnvelope` | `ParsedEvent` |
| Normalization | Gaurang Bhatia | `ParsedEvent` | `UnifiedEvent` |
| Streaming | Lalit Kumar Sureliya | shared event contracts | transported event |
| Visibility | Unassigned | `UnifiedEvent` | search/dashboard views |
| Integration | Sharanya | `UnifiedEvent` plus raw references | JSON/data-lake output |

## Rules at a handoff

Each component owns its implementation but not a private copy of a shared contract. Shared contract definitions live only under `src/contracts/` when they are added. Until then, use the documented reserved names and the implemented `schemas/unified-event-v1.schema.json` instead of inventing local alternatives.

The handoff chain is `RawEventEnvelope` -> `ParsedEvent` -> `UnifiedEvent`. Streaming may transport shared types but must not silently rename or discard their fields. Visibility and Integration consume `UnifiedEvent`; only Integration is responsible for producing JSON/data-lake output.

Changing a shared field, enum, class name, component input/output, or schema rule requires review by the contract owner and an affected owner. Source-specific parser and Source Pack design belongs to Epic 2; see the [Source Pack guide](source-pack-guide.md).
