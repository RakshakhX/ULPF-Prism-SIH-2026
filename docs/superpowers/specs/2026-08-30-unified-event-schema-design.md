# UnifiedEvent Schema v1 Design

**Project:** ULPF Prism — SIH 2026  
**Issue:** #9 — Define UnifiedEvent Schema v1  
**Owner:** Gaurang Bhatia (`Gaurang-5`)  
**Status:** Approved design, awaiting implementation planning

## 1. Purpose

ULPF Prism must convert heterogeneous perimeter-device events into a lossless, vendor-neutral representation. `UnifiedEvent` is the normalized contract consumed by visibility, storage, SIEM, data-lake and future analytics components.

The contract must provide consistent fields without discarding information that cannot be normalized. It must also maintain a verifiable relationship to the immutable original event stored in `RawEventEnvelope`.

## 2. Scope

This work will deliver:

- UnifiedEvent JSON Schema v1.
- A Python command-line validator.
- Automated schema and semantic validation tests.
- Seven representative perimeter-device example events.
- Invalid test fixtures for important failure conditions.
- Basic repository documentation and engineering conventions.

It will not implement collection, source-specific parsing, streaming infrastructure, analytical storage, dashboards, exporters or production-scale deployment.

## 3. Design choice

UnifiedEvent will use a compact mandatory core with optional nested sections. This avoids a large flat event containing hundreds of empty fields while retaining one universal envelope for all event categories.

Alternative designs were rejected:

- A flat schema is initially simple but becomes difficult to extend and produces naming collisions.
- A separate schema per category offers precision but weakens universal querying and substantially increases maintenance effort.

The JSON Schema is technology-neutral. Python is used only for the reference validator and tests.

## 4. Repository structure

```text
ULPF-Prism-SIH-2026/
├── .editorconfig
├── .gitignore
├── CONTRIBUTING.md
├── README.md
├── pyproject.toml
├── requirements-dev.txt
├── docs/
│   ├── architecture.md
│   ├── component-boundaries.md
│   ├── development-workflow.md
│   ├── engineering-conventions.md
│   ├── event-schema.md
│   ├── source-pack-guide.md
│   └── superpowers/specs/
│       └── 2026-08-30-unified-event-schema-design.md
├── schemas/
│   └── unified-event-v1.schema.json
├── examples/
│   └── unified_events/
│       ├── firewall_allow.json
│       ├── firewall_deny.json
│       ├── ids_threat_detected.json
│       ├── vpn_authentication_failed.json
│       ├── proxy_request_blocked.json
│       ├── router_acl_deny.json
│       └── waf_attack_blocked.json
├── src/
│   ├── contracts/
│   ├── collection/
│   ├── parsing/
│   ├── normalization/
│   ├── streaming/
│   ├── visibility/
│   ├── integration/
│   └── validation/
│       ├── __init__.py
│       └── validate_unified_event.py
└── tests/
    ├── fixtures/
    │   └── invalid_unified_events/
    └── test_unified_event_schema.py
```

Empty component directories will contain a small ownership README or package marker only when needed. No placeholder service implementations will be created.

## 5. Component boundaries

```text
collection     -> produces RawEventEnvelope
parsing        -> consumes RawEventEnvelope and produces ParsedEvent
normalization  -> consumes ParsedEvent and produces UnifiedEvent
streaming      -> transports the shared event types
visibility     -> reads UnifiedEvent
integration    -> exports UnifiedEvent and raw-event references
```

Shared contracts live under `src/contracts/`. Components must not create incompatible local copies of these contracts.

Reserved shared names are:

- `RawEventEnvelope`
- `ParsedEvent`
- `UnifiedEvent`
- `SourcePack`
- `ValidationResult`
- `QualityFlags`
- `Traceability`

## 6. Naming conventions

| Item | Convention | Example |
|---|---|---|
| Python variables and functions | `snake_case` | `validate_event` |
| Python classes | `PascalCase` | `UnifiedEvent` |
| Constants | `UPPER_SNAKE_CASE` | `SCHEMA_VERSION` |
| Python files and packages | `snake_case` | `event_validator.py` |
| JSON fields | `snake_case` | `raw_event_id` |
| Directories | `snake_case` | `source_packs/` |
| Event categories | lowercase words | `intrusion_detection` |
| Enumerated values | lowercase snake case | `authentication_failed` |

Any change to a shared contract requires review from its owner and at least one affected component owner.

## 7. UnifiedEvent top-level model

Required top-level sections:

- `schema_version`
- `event`
- `time`
- `observer`
- `action`
- `severity`
- `traceability`
- `quality`

Optional top-level sections:

- `source`
- `destination`
- `network`
- `threat`
- `authentication`
- `http`
- `extensions`

Unknown top-level properties are rejected. Vendor-specific fields belong in `extensions`.

### 7.1 Schema version

`schema_version` is required and must equal `1.0.0` for this schema file.

### 7.2 Event identity and classification

`event` contains:

- `id`: required UUID.
- `kind`: required and fixed to `event` in v1.
- `category`: required enumeration.
- `type`: required normalized type.
- `name`: required human-readable event name.

Initial categories are:

- `network`
- `intrusion_detection`
- `authentication`
- `web`
- `system`
- `unknown`

### 7.3 Time

`time` contains:

- `observed_at`: when the source device reports that the event occurred.
- `ingested_at`: when ULPF accepted the original event.
- `normalized_at`: when UnifiedEvent was produced.

All are required ISO 8601 UTC timestamps ending in `Z`. Semantic validation enforces:

```text
observed_at <= ingested_at <= normalized_at
```

### 7.4 Source and destination

Each endpoint may contain:

- `ip`: IPv4 or IPv6.
- `port`: integer from 0 through 65535.
- `hostname`.
- `mac`.
- `user`.
- `interface`.

The sections are optional globally. Network events require both `source` and `destination`, each with an IP address. Additional identities can be introduced in later schema versions without changing v1.

### 7.5 Observer

`observer` describes the perimeter device that produced the log:

- `vendor`: required.
- `product`: required.
- `type`: required, such as `firewall`, `ids`, `ips`, `vpn`, `proxy`, `router` or `waf`.
- `hostname`: optional.
- `serial_number`: optional.
- `software_version`: optional.

### 7.6 Network

`network` may contain:

- `transport`: normalized transport protocol.
- `application_protocol`: detected or reported application protocol.
- `direction`: `inbound`, `outbound`, `internal`, `external` or `unknown`.
- `bytes`: non-negative integer.
- `packets`: non-negative integer.

### 7.7 Action and outcome

`action` contains:

- `original`: required source-provided action.
- `normalized`: required normalized action.
- `outcome`: required normalized result.
- `reason`: optional explanation.

Initial normalized actions are:

- `allow`
- `deny`
- `block`
- `detect`
- `authenticate`
- `connect`
- `disconnect`
- `unknown`

Outcomes are `success`, `failure` and `unknown`.

The semantic validator checks obvious contradictions. For example, `deny` or `block` may not use the `success` outcome in v1. A detection event may use `unknown` because detecting a threat does not indicate whether the attack itself succeeded.

### 7.8 Severity

`severity` contains:

- `original`: required vendor value represented as a string.
- `normalized`: required integer from 0 through 10.
- `label`: required enumeration.

Labels are `informational`, `low`, `medium`, `high`, `critical` and `unknown`. V1 will define documented numeric ranges for label consistency.

### 7.9 Threat

`threat` may contain:

- `name`: required when the section exists.
- `signature_id`.
- `category`.
- `confidence`: number from 0 through 1.

An `intrusion_detection` event requires `threat`.

### 7.10 Authentication

`authentication` may contain:

- `user`: required when the section exists.
- `method`.
- `result`: `success`, `failure` or `unknown`.
- `failure_reason`.

An `authentication` event requires this section. Its result must be consistent with `action.outcome`.

### 7.11 HTTP

`http` may contain:

- `method`.
- `host`.
- `path`.
- `status_code`: integer from 100 through 599.
- `user_agent`.

Web proxy and WAF examples use this section.

### 7.12 Traceability and raw evidence

`traceability` contains:

- `raw_event_id`: required UUID referencing `RawEventEnvelope`.
- `raw_sha256`: required lowercase 64-character hexadecimal digest.
- `source_pack.name`: required.
- `source_pack.version`: required semantic version.
- `parser.name`: required.
- `parser.version`: required semantic version.

The complete original event is stored in `RawEventEnvelope`, not duplicated in every normalized record. Self-contained exports may include:

```json
{
  "raw_event": {
    "encoding": "utf-8",
    "content_type": "text/plain",
    "content": "complete original event"
  }
}
```

When embedded raw content exists, the Python validator verifies that its SHA-256 digest equals `raw_sha256`. This does not replace preservation of the authoritative RawEventEnvelope.

### 7.13 Quality

`quality` contains:

- `status`: required and one of `valid`, `partial`, `invalid` or `unknown`.
- `parsing_confidence`: required number from 0 through 1.
- `missing_fields`: required array of JSON paths or normalized field names.
- `warnings`: required array of human-readable messages.

A partial event must identify at least one missing field or warning. Quality metadata describes normalization completeness; it must not be used to silently discard events.

### 7.14 Extensions

`extensions` retains source-specific information with no universal mapping. Each first-level key must be a lowercase snake-case vendor namespace. Example:

```json
{
  "extensions": {
    "example_vendor": {
      "policy_id": "POL-100",
      "vendor_specific_code": "ABC123"
    }
  }
}
```

Vendor fields must not be discarded merely because v1 lacks a normalized field.

## 8. Example coverage

The seven valid examples are:

1. Firewall traffic allowed.
2. Firewall traffic denied.
3. IDS/IPS threat detected.
4. VPN authentication failed.
5. Web proxy request blocked.
6. Router ACL packet denied.
7. Web Application Firewall attack blocked.

Examples use reserved documentation IP ranges and clearly fictional vendor details. They must not contain real credentials, sensitive logs or production identifiers.

## 9. Validation design

### 9.1 JSON Schema validation

The schema validates:

- Required sections and fields.
- Primitive and object types.
- Enumerations.
- IP address formats.
- Numeric ranges for ports, severity, confidence, byte counts and packet counts.
- SHA-256 structure.
- UUID, semantic-version and timestamp formats.
- Conditional sections for known categories.
- Unexpected top-level properties.

Schema format validation uses Python `jsonschema` with its format checker enabled.

### 9.2 Semantic validation

The Python validator checks rules that are clearer outside JSON Schema:

- Timestamp ordering.
- UTC `Z` timestamps.
- Network endpoint requirements.
- Threat requirements.
- Authentication requirements and outcome consistency.
- Action and outcome consistency.
- Vendor namespace rules.
- Partial-quality explanations.
- Embedded raw-content hash verification.

### 9.3 Command-line interface

```bash
python -m src.validation.validate_unified_event EVENT_FILE
```

Success output:

```text
VALID: EVENT_FILE conforms to UnifiedEvent Schema v1
```

Failure output lists one problem per line with a JSON path and understandable message.

Exit codes:

- `0`: event is valid.
- `1`: event is invalid.
- `2`: operational error, including missing or unreadable input/schema files.

The validator will expose small reusable functions so tests and later services can use it without invoking the CLI.

## 10. Testing strategy

Automated tests cover:

- All seven valid examples.
- Missing mandatory sections.
- Invalid IP addresses.
- Ports outside the allowed range.
- Severity outside the allowed range.
- Invalid SHA-256 digests.
- Non-UTC or incorrectly ordered timestamps.
- Missing network endpoints.
- Missing threat information.
- Missing authentication information.
- Unnamespaced extensions.
- Embedded raw-content hash mismatch.
- Unknown top-level properties.
- CLI success, validation-failure and operational-error exit codes.

The standard command is:

```bash
python -m pytest
```

## 11. Basic documentation

- `README.md` explains the problem, architecture summary, setup, validation command and test command.
- `CONTRIBUTING.md` defines branches, commits, pull requests, reviews and contract-change approval.
- `docs/architecture.md` explains component boundaries and event flow.
- `docs/component-boundaries.md` records team ownership and shared interfaces.
- `docs/development-workflow.md` gives a beginner GitHub workflow.
- `docs/engineering-conventions.md` defines names, field formats, timestamps, IDs, errors, imports and testing conventions.
- `docs/event-schema.md` is the human-readable UnifiedEvent reference.
- `docs/source-pack-guide.md` documents only the minimum boundary that source-pack work must respect; Member 2 owns its detailed design.
- `.editorconfig`, `.gitignore`, `pyproject.toml` and `requirements-dev.txt` establish consistent local tooling and prevent generated or sensitive files from being committed.

## 12. Error handling principles

- Validation failures are explicit and never silently ignored.
- Multiple independent field errors are returned together where practical.
- Error messages include the affected JSON path.
- Operational failures are distinguishable from invalid-event results.
- Validation does not modify its input.
- Invalid and partial records remain representable for upstream preservation and diagnostics.

## 13. Completion criteria

Issue #9 is complete when:

- The JSON Schema is versioned as `1.0.0`.
- All seven valid examples pass.
- Invalid fixtures fail for their intended reasons.
- Semantic rules and CLI exit codes are tested.
- Raw evidence traceability is mandatory and embedded raw content can be hash-verified.
- Vendor-specific extensions are preserved under namespaces.
- Basic repository documentation and engineering conventions are present.
- The full test suite passes from a clean checkout using documented commands.
- At least Members 1 and 2 review the shared contract before merge.

