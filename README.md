# ULPF Prism

## Problem

Perimeter devices emit different log formats for the same kinds of activity. ULPF Prism preserves the original evidence and normalizes the parts that can be shared, so teams can search and export consistent events without losing the device-specific record.

## Current prototype

The repository now implements the real canonical path: lossless collection and archival, registry-driven multi-vendor parsing, `UnifiedEvent` normalization, retry/DLQ streaming decisions, analytical visibility, and data-lake export. Cisco ASA, Fortinet FortiGate, and generic Linux Syslog fixtures run through the same framework.

## Architecture

The system has six boundaries: Collection, Parsing, Normalization, Streaming, Visibility, and Integration. Shared immutable contracts connect them and preserve the event ID, raw bytes, and SHA-256 across processing. See the [architecture](docs/architecture.md) and [component boundaries](docs/component-boundaries.md).

## Quick start

Use Python 3.11 or newer. From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pytest
python -m src.validation.validate_unified_event examples/unified_events/firewall_deny.json
python -m src.pipeline.demo
```

Run the API with `uvicorn main:app --host 0.0.0.0 --port 8080`. Submit text or Base64 bytes to `POST /v1/events`; importing the application does not preload demo data.

On Windows PowerShell, activate the environment with `.venv\Scripts\Activate.ps1` instead.

## Example

`examples/unified_events/firewall_deny.json` is a fictional network deny event. Validate it with:

```bash
python -m src.validation.validate_unified_event examples/unified_events/firewall_deny.json
```

The CLI returns `0` for valid events, `1` for invalid events, and `2` when it cannot read a usable JSON object.

## Documentation

- [Architecture](docs/architecture.md)
- [Component boundaries and ownership](docs/component-boundaries.md)
- [Development workflow](docs/development-workflow.md)
- [Engineering conventions](docs/engineering-conventions.md)
- [UnifiedEvent v1 reference](docs/event-schema.md)
- [Member 6: storage and visibility guide](docs/member-6-visibility-guide.md)
- [Research basis](docs/research-basis.md)
- [Source Pack boundary](docs/source-pack-guide.md)
- [Contributing](CONTRIBUTING.md)

## Team workflow

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing code or contracts. Direct commits to `main` are not allowed: work on a feature branch and open a pull request.
