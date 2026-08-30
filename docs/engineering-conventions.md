# Engineering conventions

These conventions are the authoritative shared naming and interface rules. Follow them before creating a new class, event field, service boundary, or error code.

## Names and paths

- Python variables, functions, modules, packages, and directories use `snake_case`, for example `validate_event` and `source_packs`.
- Python classes use `PascalCase`, for example `ValidationResult`.
- Python constants use `UPPER_SNAKE_CASE`, for example `SCHEMA_VERSION`.
- JSON fields use `snake_case`. Event categories contain no dots and use lowercase snake case, for example `intrusion_detection`; enum values also use lowercase snake case.
- Shared contract definitions live only under `src/contracts/`. Components must not create incompatible local copies.

The reserved shared class names are `RawEventEnvelope`, `ParsedEvent`, `UnifiedEvent`, `SourcePack`, `ValidationResult`, `QualityFlags`, and `Traceability`. Do not rename these or use near-duplicates such as `RawLogEvent` without an approved shared-contract change.

## Event and logging formats

All event timestamps are UTC ISO 8601 values ending in `Z`. Event IDs are UUIDs. SHA-256 digests are lowercase hexadecimal strings. For the implemented schema, `observed_at <= ingested_at <= normalized_at`.

Structured application logs use these fields when applicable: `timestamp`, `level`, `component`, `message`, `event_id`, and `error_code`. Error codes use `COMPONENT_REASON`, for example `NORMALIZATION_SCHEMA_INVALID`; avoid embedding secrets or raw sensitive payloads in log messages.

## Code and tests

Public functions require type hints and docstrings. Keep one source responsibility per module and mirror that responsibility in tests: a parser test belongs with parser behavior, a validation test with validation behavior. Use fictional vendors, documentation IP ranges, and synthetic inputs only.

Run the documented check before requesting review:

```bash
python -m pytest
ruff check src tests
```

## Changing a shared contract

A shared-contract change includes a schema field or enum, a reserved class name, an item under `src/contracts/`, or a component handoff. It requires review by the contract owner and an affected component owner. Update the schema reference, tests, examples, and boundaries in the same pull request when they are affected.
