# Source Pack: Generic Linux Syslog

## Overview
Parses standard Linux syslog output (RFC3164 and RFC5424) from common
daemons: `sshd`, `sudo`, `CRON`, `systemd`, `kernel`.

- **Vendor:** Generic
- **Product:** Linux Syslog (rsyslog / syslog-ng)
- **Pack version:** 1.0.0
- **Format:** `syslog`

## Detection
This pack matches any payload that:
1. Starts with a valid `<PRI>` syslog header, **or**
2. Contains one of the keywords: `sshd`, `CRON`, `systemd`, `sudo`, `kernel:`

Detection priority is `10` — deliberately low, so vendor-specific packs
that also emit syslog-wrapped payloads (e.g. a firewall pack that detects
on `CEF:` inside the syslog message body) can be given a higher priority
and win the routing decision instead.

## Extracted Fields

| Field                 | Type    | Description                                   |
|------------------------|---------|-----------------------------------------------|
| `timestamp`            | string  | Raw syslog timestamp (host-local, no year)    |
| `hostname`              | string  | Reporting host                                |
| `process`               | string  | Process/tag name (e.g. `sshd`)                |
| `pid`                   | string  | Process ID, if present                        |
| `message`               | string  | Free-text log message                         |
| `syslog_facility`       | integer | Syslog facility code (0-23)                   |
| `severity`              | integer | Syslog severity code (0-7)                    |
| `syslog_variant`        | string  | `rfc3164` or `rfc5424`                        |
| `syslog_facility_name`  | string  | Human-readable facility (added by `pack.py`)  |

## Samples & Validation
- `samples/sample.log` — three representative raw log lines.
- `samples/expected_output.json` — expected `fields` output for line 1,
  used as a fixture by `tests/test_pack.py`.

## Extending
Add new detection keywords or regex rules to `manifest.yaml` under
`detection.rules` to broaden coverage (e.g. additional daemons) without
touching any Python code. Only fall back to `pack.py` custom logic (as
done here for facility-name lookup) when declarative field mapping isn't
expressive enough.
