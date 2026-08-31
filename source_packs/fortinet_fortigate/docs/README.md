# Source Pack: Fortinet FortiGate

## Overview
Parses native FortiGate syslog output (key=value format) across the three
primary log categories: **traffic** (forward/local), **UTM** (virus,
webfilter, ips, app-ctrl), and **event** (system, vpn, ha, admin).

- **Vendor:** Fortinet
- **Product:** FortiGate
- **Pack version:** 1.0.0
- **Supported FortiOS:** 6.4, 7.0, 7.2, 7.4
- **Format:** `key_value`

## Detection
Matches any payload containing `devname=` or `devid=` (FortiGate always
emits these near the start of a record), or a 10-digit `logid="..."` code.
Priority `60` — above the generic syslog pack (`10`) — so FortiGate logs
route here even if wrapped in an outer syslog header some collectors add.

## Extracted Fields
40 declarative fields covering identity/routing, event classification, the
network 5-tuple, policy/session/byte counters, free-text description, and
UTM-specific attributes (virus, webfilter URL/category, IPS attack
signature, app-control). See `manifest.yaml` for the full raw-key → field
mapping. Fields absent from a given `type`/`subtype` (e.g. `virus_name` on
a traffic log) resolve to `null` rather than causing a parse failure.

## Vendor-Specific Normalization (`pack.py`)
Three things the declarative manifest alone can't express:
1. **Timestamp** — FortiGate splits `date=` and `time=` into two fields;
   `pack.py` combines them into `ParsedEvent.event_timestamp`.
2. **Severity** — FortiGate uses syslog-style level *names* (`notice`,
   `warning`, `alert`, ...) which are translated to the normalized
   `Severity` enum.
3. **Host / message / category promotion** — `ParsedEvent.host`,
   `.message`, and `.event_category` are filled from the most relevant
   available field per log type.

The raw declarative `fields` dict itself is never modified by these
overrides — it always reflects exactly what the manifest's field-mapping
rules extracted.

## Samples & Validation
- `samples/raw_logs.txt` — 25 lines: 20 valid logs (8 traffic, 7 UTM, 5
  event) followed by 5 malformed/corrupted lines.
- `samples/expected_outputs.json` — expected `fields` dict for each of the
  20 valid logs (generated directly from the manifest + KV parser to
  guarantee accuracy), indexed 1:1 with `raw_logs.txt` lines 1–20.
- `tests/test_pack.py` — asserts exact field-match for all 20 valid logs,
  and confirms all 5 malformed logs are rejected by detection and degrade
  to the engine's `FallbackParser` (`UNPARSED_FALLBACK`) without the
  engine ever raising.

Run: `pytest source_packs/fortinet_fortigate/tests/test_pack.py -v`
