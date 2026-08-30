# UnifiedEvent v1 reference

`schemas/unified-event-v1.schema.json` is the executable contract for `UnifiedEvent` v1. The current Sprint 0 implementation validates JSON structure plus selected cross-field rules with `src.validation.validate_unified_event`; it does not implement collection, parsing, streaming, visibility, or integration services.

## Top-level sections

Unknown top-level properties are rejected. The required core sections are `schema_version` (exactly `1.0.0`), `event`, `time`, `observer`, `action`, `severity`, `traceability`, and `quality`. Optional sections are `source`, `destination`, `network`, `threat`, `authentication`, `http`, and `extensions`.

| Section | Required | Contents and rules |
|---|---|---|
| `schema_version` | Yes | Exact value `1.0.0`. |
| `event` | Yes | UUID `id`; `kind` is `event`; category, normalized `type`, non-empty `name`, optional `message`. Categories: `network`, `intrusion_detection`, `authentication`, `web`, `system`, `unknown`. |
| `time` | Yes | `observed_at`, `ingested_at`, and `normalized_at` are ISO 8601 UTC timestamps ending in `Z`; their order is `observed_at <= ingested_at <= normalized_at`. |
| `source` | No | Endpoint with at least one of IP, port, hostname, MAC, user, or interface. IP is IPv4/IPv6; port is 0–65535. Required with an IP for `network` events. |
| `destination` | No | Same endpoint shape as `source`; required with an IP for `network` events. |
| `observer` | Yes | Device `vendor`, `product`, and type; optional hostname, serial number, and software version. Types: `firewall`, `ids`, `ips`, `vpn`, `proxy`, `router`, `waf`, `unknown`. |
| `network` | No | At least one network field. Transport: `tcp`, `udp`, `icmp`, `icmpv6`, `gre`, `other`, `unknown`; direction: `inbound`, `outbound`, `internal`, `external`, `unknown`; non-negative bytes and packets. Required for `network` events. |
| `action` | Yes | Original string, normalized action, and outcome; optional reason. Actions: `allow`, `deny`, `block`, `detect`, `authenticate`, `connect`, `disconnect`, `unknown`. Outcomes: `success`, `failure`, `unknown`. `deny` and `block` cannot have outcome `success`. |
| `severity` | Yes | Original string, normalized integer 0–10, and label. Labels: `informational`, `low`, `medium`, `high`, `critical`, `unknown`. Known scores map 0 to informational, 1–3 low, 4–6 medium, 7–8 high, and 9–10 critical. |
| `threat` | No | Non-empty `name`, optional signature ID, snake-case category, and confidence 0–1. Required for `intrusion_detection` events. |
| `authentication` | No | Non-empty user, optional method/failure reason, result `success`, `failure`, or `unknown`. Required for `authentication` events and its known result must match `action.outcome`. |
| `http` | No | At least one of uppercase method, host, path beginning `/`, status code 100–599, or user agent. |
| `traceability` | Yes | Raw UUID and lowercase 64-character SHA-256 plus versioned `source_pack` and `parser` (each has name and semantic version). Optional embedded UTF-8 `raw_event` is hash-checked when present. |
| `quality` | Yes | Status `valid`, `partial`, `invalid`, or `unknown`; confidence 0–1; unique missing fields; warnings. A `partial` event needs at least one missing field or warning. An `unknown` severity needs a warning. |
| `extensions` | No | Object of source-specific objects. Every first-level namespace is lowercase snake case, such as `extensions.example_vendor`; keep unmapped values here rather than discarding them. |

## Quality and evidence behavior

`quality` reports normalization completeness; it must not be used to silently discard an event. Preserve authoritative raw evidence in `RawEventEnvelope`; `traceability.raw_event_id` and `traceability.raw_sha256` connect it to the normalized record. `traceability.raw_event` is only an opt-in self-contained export.

## Validate a file

From the repository root, validate one JSON file:

```bash
python -m src.validation.validate_unified_event examples/unified_events/firewall_deny.json
```

The validator prints `VALID` and exits `0` for a valid event, prints diagnostics and exits `1` for an invalid event, or prints an input error and exits `2` for unreadable, malformed, or non-object JSON. Run all checks with:

```bash
python -m pytest
ruff check src tests
```
