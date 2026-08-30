# ULPF Prism

## Problem

Perimeter devices emit different log formats for the same kinds of activity. ULPF Prism preserves the original evidence and normalizes the parts that can be shared, so teams can search and export consistent events without losing the device-specific record.

## Sprint 0 deliverable

Sprint 0 implements the `UnifiedEvent` v1 JSON Schema, deterministic Python validator, command-line validator, invalid fixtures, and fictional example events. The target flow is `RawEventEnvelope` -> `ParsedEvent` -> `UnifiedEvent`. A Cisco ASA collection-and-parsing vertical slice is planned; it is not implemented by this repository yet.

## Architecture

The planned system has six boundaries: Collection, Parsing, Normalization, Streaming, Visibility, and Integration. The current repository implements the normalization contract and validator, not those component services. See the [architecture](docs/architecture.md) and [component boundaries](docs/component-boundaries.md).

## Quick start

Use Python 3.11 or newer. From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pytest
python -m src.validation.validate_unified_event examples/unified_events/firewall_deny.json
```

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
