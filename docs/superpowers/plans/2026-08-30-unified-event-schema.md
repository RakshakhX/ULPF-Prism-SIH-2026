# UnifiedEvent Schema v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a versioned UnifiedEvent JSON Schema, reusable Python validator, CLI, automated tests, seven perimeter-event examples, and shared beginner-friendly repository documentation.

**Architecture:** JSON Schema Draft 2020-12 performs structural validation; focused Python modules add semantic rules and expose a reusable `ValidationResult`. A thin CLI reads an event file and prints deterministic diagnostics. Shared conventions and component boundaries prevent different team members from inventing incompatible fields, classes, and services.

**Tech Stack:** Python 3.11+, JSON Schema Draft 2020-12, `jsonschema[format]==4.26.0`, `pytest==9.1.1`, `ruff==0.16.4`.

**Spec:** `docs/superpowers/specs/2026-08-30-unified-event-schema-design.md`

## Global Constraints

- Preserve the authoritative original log in `RawEventEnvelope`; UnifiedEvent carries mandatory ID and SHA-256 traceability.
- Use schema version `1.0.0` and reject unknown top-level properties.
- Use UTC ISO 8601 timestamps ending in `Z` and enforce `observed_at <= ingested_at <= normalized_at`.
- Use `snake_case` for JSON fields, Python modules, variables and functions; use `PascalCase` for classes.
- Put vendor-only fields under a lowercase snake-case namespace in `extensions`.
- Validation must never modify the input event.
- Use exit code `0` for valid, `1` for invalid and `2` for operational errors.
- Keep collection, source-specific parsing, streaming, storage, dashboards and exporters outside this branch.
- Use fictional vendors, documentation IP ranges and no real credentials or production logs.
- Align terminology with OCSF 1.8.0, ECS 9.5.0, OpenTelemetry Semantic Conventions 1.44.0, OWASP logging guidance and JSON Schema 2020-12 without claiming full compliance.
- Record research-derived decisions and source stability; do not introduce AI/LLM parsing into issue #9.

## File map

| File | Responsibility |
|---|---|
| `schemas/unified-event-v1.schema.json` | Structural UnifiedEvent v1 contract |
| `src/validation/result.py` | Immutable diagnostic and result types |
| `src/validation/schema_validation.py` | Schema loading and structural validation |
| `src/validation/semantic_validation.py` | Cross-field and integrity rules |
| `src/validation/validate_unified_event.py` | Composition API and command-line entry point |
| `tests/test_schema_validation.py` | Structural validation behavior |
| `tests/test_semantic_validation.py` | Cross-field validation behavior |
| `tests/test_cli.py` | CLI output and exit codes |
| `tests/test_examples.py` | All official examples remain valid |
| `examples/unified_events/*.json` | Seven valid demonstration records |
| `tests/fixtures/invalid_unified_events/*.json` | Intentionally invalid regression fixtures |
| `README.md` | Project overview and quick start |
| `CONTRIBUTING.md` | Git and review rules |
| `docs/*.md` | Architecture, ownership, conventions and schema reference |
| `.editorconfig`, `.gitignore`, `pyproject.toml`, `requirements-dev.txt` | Consistent local tooling |

---

### Task 0: Record the authoritative research basis

**Files:**
- Create: `docs/research-basis.md`

**Interfaces:**
- Produces: reviewed standards-and-literature decision record used by every later task.
- Consumes: the approved design spec and the primary sources listed below.

- [ ] **Step 1: Create a standards decision table**

Write `docs/research-basis.md` with this source matrix:

| Source | Version/date used | Adopt | Do not claim or copy |
|---|---|---|---|
| OCSF | stable 1.8.0, released 2026-03-18 | category/type/action separation, reusable objects, requirement levels, extension boundary | Full OCSF compliance or numeric OCSF IDs |
| ECS | 9.5.0 | core versus extended fields, lowercase snake-case field sets, vendor-neutral analytics | Elasticsearch-specific mappings |
| OpenTelemetry Semantic Conventions | 1.44.0 | stable event identity, small frequent core, flexible attributes | Conformance to log attributes still marked Development |
| OWASP Logging Cheat Sheet | accessed 2026-08-30 | when/where/who/what, confidence, integrity and untrusted-source treatment | Logging secrets or sensitive payloads |
| JSON Schema | Draft 2020-12 | `$defs`, `if`/`then`, structural assertions and standard format checking | Treating cross-field semantics as purely structural |
| Drain | IEEE ICWS 2017 | deterministic streaming-parsing context | Adding parser implementation to issue #9 |
| Preprocessing is All You Need | 2024 preprint | preprocessing and parsing require separate evaluation | Assuming schema validation improves parser accuracy |
| Adaptive and Efficient Log Parsing as a Cloud Service | ACM SIGMOD Companion 2025 | throughput/accuracy/compute must be measured independently | Copying its cloud architecture or claiming its benchmark |

Use these primary links:

- <https://github.com/ocsf/ocsf-schema/releases>
- <https://github.com/ocsf/ocsf-docs/blob/main/overview/understanding-ocsf.md>
- <https://www.elastic.co/docs/reference/ecs>
- <https://opentelemetry.io/docs/specs/semconv/>
- <https://opentelemetry.io/docs/specs/otel/logs/data-model/>
- <https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html>
- <https://json-schema.org/draft/2020-12>
- <https://doi.org/10.1109/ICWS.2017.13>
- <https://arxiv.org/abs/2412.05254>
- <https://doi.org/10.1145/3722212.3724427>

- [ ] **Step 2: Add the explicit implementation decisions**

The document must state:

1. `event.id` is the stable per-record identifier and deduplication key.
2. `event.category`, `event.type` and `action.normalized` are separate classification dimensions.
3. Required top-level sections form the core; optional nested sections are extended fields.
4. `traceability.raw_event_id` and `traceability.raw_sha256` reference authoritative raw evidence.
5. `traceability.raw_event` is opt-in for self-contained export only.
6. A first-level vendor namespace such as `extensions.example_vendor` is the unmapped-field escape hatch.
7. `quality.parsing_confidence`, warnings and missing fields expose uncertainty rather than hiding it.
8. `event.message` is optional human-readable context; analytics must use normalized fields instead of parsing it.
9. Python validation is deterministic, offline-capable and contains no remote API or model dependency.
10. OCSF/ECS output adapters and formal conformance belong to Epic 6.

- [ ] **Step 3: Review source stability and scope language**

Confirm the document labels OpenTelemetry general log attributes that are still `Development`, distinguishes OCSF stable 1.8.0 from the `main` branch's development version, and calls the 2024 preprocessing work a preprint rather than a deployed standard.

- [ ] **Step 4: Commit the research decision record**

```bash
git add docs/research-basis.md
git commit -m "docs: record UnifiedEvent research basis"
```

---

### Task 1: Establish the Python project and immutable validation result

**Files:**
- Create: `.editorconfig`
- Create: `.gitignore`
- Create: `pyproject.toml`
- Create: `requirements-dev.txt`
- Create: `src/__init__.py`
- Create: `src/validation/__init__.py`
- Create: `src/validation/result.py`
- Create: `tests/test_validation_result.py`

**Interfaces:**
- Produces: `ValidationIssue(path: str, rule: str, message: str)`.
- Produces: `ValidationResult(issues: tuple[ValidationIssue, ...])` with `valid: bool`.
- Consumes: no application code.

- [ ] **Step 1: Add the failing result-model tests**

```python
# tests/test_validation_result.py
from dataclasses import FrozenInstanceError

import pytest

from src.validation.result import ValidationIssue, ValidationResult


def test_result_without_issues_is_valid() -> None:
    assert ValidationResult().valid is True


def test_result_with_issue_is_invalid() -> None:
    issue = ValidationIssue(path="$.event.id", rule="format", message="must be a UUID")
    result = ValidationResult(issues=(issue,))

    assert result.valid is False
    assert result.issues == (issue,)


def test_validation_issue_is_immutable() -> None:
    issue = ValidationIssue(path="$", rule="required", message="missing event")

    with pytest.raises(FrozenInstanceError):
        issue.path = "$.event"  # type: ignore[misc]
```

- [ ] **Step 2: Run the focused test and confirm the expected failure**

Run:

```bash
python -m pytest tests/test_validation_result.py -v
```

Expected: collection fails because `src.validation.result` does not exist.

- [ ] **Step 3: Add shared tooling configuration**

```ini
# .editorconfig
root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
indent_style = space
indent_size = 4
trim_trailing_whitespace = true

[*.{json,yaml,yml}]
indent_size = 2

[*.md]
trim_trailing_whitespace = false
```

```gitignore
# .gitignore
__pycache__/
*.py[cod]
.pytest_cache/
.ruff_cache/
.venv/
venv/
.env
.env.*
!.env.example
.DS_Store
coverage.xml
.coverage
htmlcov/
dist/
build/
*.egg-info/
```

```toml
# pyproject.toml
[build-system]
requires = ["setuptools>=75"]
build-backend = "setuptools.build_meta"

[project]
name = "ulpf-prism"
version = "0.1.0"
description = "Universal Log Pre-processing Framework prototype"
requires-python = ">=3.11"
dependencies = ["jsonschema[format]==4.26.0"]

[project.optional-dependencies]
dev = ["pytest==9.1.1", "ruff==0.16.4"]

[tool.pytest.ini_options]
addopts = "-ra --strict-markers"
testpaths = ["tests"]

[tool.ruff]
line-length = 100
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP"]
```

```text
# requirements-dev.txt
jsonschema[format]==4.26.0
pytest==9.1.1
ruff==0.16.4
```

- [ ] **Step 4: Add the minimal immutable result model**

```python
# src/validation/result.py
from dataclasses import dataclass


@dataclass(frozen=True, order=True)
class ValidationIssue:
    path: str
    rule: str
    message: str


@dataclass(frozen=True)
class ValidationResult:
    issues: tuple[ValidationIssue, ...] = ()

    @property
    def valid(self) -> bool:
        return not self.issues
```

Create empty `src/__init__.py` and expose the types from `src/validation/__init__.py`:

```python
from .result import ValidationIssue, ValidationResult

__all__ = ["ValidationIssue", "ValidationResult"]
```

- [ ] **Step 5: Install dependencies and run the focused checks**

Run:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pytest tests/test_validation_result.py -v
ruff check src tests
```

Expected: three tests pass and Ruff reports no errors.

- [ ] **Step 6: Commit the project foundation**

```bash
git add .editorconfig .gitignore pyproject.toml requirements-dev.txt src tests/test_validation_result.py
git commit -m "build: establish Python validation project"
```

---

### Task 2: Define the structural UnifiedEvent JSON Schema

**Files:**
- Create: `schemas/unified-event-v1.schema.json`
- Create: `tests/test_schema_contract.py`

**Interfaces:**
- Produces: JSON Schema Draft 2020-12 document with `$defs` for endpoints, versions and event-specific sections.
- Consumes: the exact fields and enums approved in the design spec.

- [ ] **Step 1: Write contract tests before creating the schema**

```python
# tests/test_schema_contract.py
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

SCHEMA_PATH = Path("schemas/unified-event-v1.schema.json")


@pytest.fixture(scope="module")
def schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def test_schema_is_valid_draft_2020_12(schema: dict) -> None:
    Draft202012Validator.check_schema(schema)


def test_schema_version_and_required_sections_are_locked(schema: dict) -> None:
    assert schema["properties"]["schema_version"]["const"] == "1.0.0"
    assert set(schema["required"]) == {
        "schema_version",
        "event",
        "time",
        "observer",
        "action",
        "severity",
        "traceability",
        "quality",
    }
    assert schema["additionalProperties"] is False


def test_category_conditionals_are_present(schema: dict) -> None:
    required_by_category = {
        rule["if"]["properties"]["event"]["properties"]["category"]["const"]:
        set(rule["then"]["required"])
        for rule in schema["allOf"]
    }

    assert required_by_category["network"] == {"source", "destination", "network"}
    assert required_by_category["intrusion_detection"] == {"threat"}
    assert required_by_category["authentication"] == {"authentication"}
```

- [ ] **Step 2: Run the tests and confirm the schema is missing**

Run:

```bash
python -m pytest tests/test_schema_contract.py -v
```

Expected: errors with `FileNotFoundError` for `schemas/unified-event-v1.schema.json`.

- [ ] **Step 3: Create the complete Draft 2020-12 schema**

The file must start with:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://rakshakhx.github.io/ulpf/schemas/unified-event-v1.schema.json",
  "title": "ULPF UnifiedEvent v1",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "schema_version",
    "event",
    "time",
    "observer",
    "action",
    "severity",
    "traceability",
    "quality"
  ],
  "properties": {
    "schema_version": {"const": "1.0.0"},
    "event": {"$ref": "#/$defs/event"},
    "time": {"$ref": "#/$defs/time"},
    "source": {"$ref": "#/$defs/endpoint"},
    "destination": {"$ref": "#/$defs/endpoint"},
    "observer": {"$ref": "#/$defs/observer"},
    "network": {"$ref": "#/$defs/network"},
    "action": {"$ref": "#/$defs/action"},
    "severity": {"$ref": "#/$defs/severity"},
    "threat": {"$ref": "#/$defs/threat"},
    "authentication": {"$ref": "#/$defs/authentication"},
    "http": {"$ref": "#/$defs/http"},
    "traceability": {"$ref": "#/$defs/traceability"},
    "quality": {"$ref": "#/$defs/quality"},
    "extensions": {"$ref": "#/$defs/extensions"}
  },
  "allOf": [
    {
      "if": {
        "properties": {
          "event": {
            "properties": {"category": {"const": "network"}},
            "required": ["category"]
          }
        }
      },
      "then": {"required": ["source", "destination", "network"]}
    },
    {
      "if": {
        "properties": {
          "event": {
            "properties": {"category": {"const": "intrusion_detection"}},
            "required": ["category"]
          }
        }
      },
      "then": {"required": ["threat"]}
    },
    {
      "if": {
        "properties": {
          "event": {
            "properties": {"category": {"const": "authentication"}},
            "required": ["category"]
          }
        }
      },
      "then": {"required": ["authentication"]}
    }
  ]
}
```

Before closing the root object, add these exact `$defs`. Every object sets `additionalProperties: false` except the namespaced vendor payload:

```json
"$defs": {
  "semver": {
    "type": "string",
    "pattern": "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$"
  },
  "ip_address": {
    "oneOf": [
      {"type": "string", "format": "ipv4"},
      {"type": "string", "format": "ipv6"}
    ]
  },
  "event": {
    "type": "object",
    "additionalProperties": false,
    "required": ["id", "kind", "category", "type", "name"],
    "properties": {
      "id": {"type": "string", "format": "uuid"},
      "kind": {"const": "event"},
      "category": {
        "enum": ["network", "intrusion_detection", "authentication", "web", "system", "unknown"]
      },
      "type": {"type": "string", "pattern": "^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$"},
      "name": {"type": "string", "minLength": 1},
      "message": {"type": "string", "minLength": 1}
    }
  },
  "time": {
    "type": "object",
    "additionalProperties": false,
    "required": ["observed_at", "ingested_at", "normalized_at"],
    "properties": {
      "observed_at": {"type": "string", "format": "date-time", "pattern": "Z$"},
      "ingested_at": {"type": "string", "format": "date-time", "pattern": "Z$"},
      "normalized_at": {"type": "string", "format": "date-time", "pattern": "Z$"}
    }
  },
  "endpoint": {
    "type": "object",
    "additionalProperties": false,
    "properties": {
      "ip": {"$ref": "#/$defs/ip_address"},
      "port": {"type": "integer", "minimum": 0, "maximum": 65535},
      "hostname": {"type": "string", "minLength": 1},
      "mac": {"type": "string", "pattern": "^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"},
      "user": {"type": "string", "minLength": 1},
      "interface": {"type": "string", "minLength": 1}
    },
    "minProperties": 1
  },
  "observer": {
    "type": "object",
    "additionalProperties": false,
    "required": ["vendor", "product", "type"],
    "properties": {
      "vendor": {"type": "string", "minLength": 1},
      "product": {"type": "string", "minLength": 1},
      "type": {"enum": ["firewall", "ids", "ips", "vpn", "proxy", "router", "waf", "unknown"]},
      "hostname": {"type": "string", "minLength": 1},
      "serial_number": {"type": "string", "minLength": 1},
      "software_version": {"type": "string", "minLength": 1}
    }
  },
  "network": {
    "type": "object",
    "additionalProperties": false,
    "properties": {
      "transport": {"enum": ["tcp", "udp", "icmp", "icmpv6", "gre", "other", "unknown"]},
      "application_protocol": {"type": "string", "minLength": 1},
      "direction": {"enum": ["inbound", "outbound", "internal", "external", "unknown"]},
      "bytes": {"type": "integer", "minimum": 0},
      "packets": {"type": "integer", "minimum": 0}
    },
    "minProperties": 1
  },
  "action": {
    "type": "object",
    "additionalProperties": false,
    "required": ["original", "normalized", "outcome"],
    "properties": {
      "original": {"type": "string", "minLength": 1},
      "normalized": {"enum": ["allow", "deny", "block", "detect", "authenticate", "connect", "disconnect", "unknown"]},
      "outcome": {"enum": ["success", "failure", "unknown"]},
      "reason": {"type": "string", "minLength": 1}
    }
  },
  "severity": {
    "type": "object",
    "additionalProperties": false,
    "required": ["original", "normalized", "label"],
    "properties": {
      "original": {"type": "string"},
      "normalized": {"type": "integer", "minimum": 0, "maximum": 10},
      "label": {"enum": ["informational", "low", "medium", "high", "critical", "unknown"]}
    }
  },
  "threat": {
    "type": "object",
    "additionalProperties": false,
    "required": ["name"],
    "properties": {
      "name": {"type": "string", "minLength": 1},
      "signature_id": {"type": "string", "minLength": 1},
      "category": {"type": "string", "pattern": "^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$"},
      "confidence": {"type": "number", "minimum": 0, "maximum": 1}
    }
  },
  "authentication": {
    "type": "object",
    "additionalProperties": false,
    "required": ["user", "result"],
    "properties": {
      "user": {"type": "string", "minLength": 1},
      "method": {"type": "string", "minLength": 1},
      "result": {"enum": ["success", "failure", "unknown"]},
      "failure_reason": {"type": "string", "minLength": 1}
    }
  },
  "http": {
    "type": "object",
    "additionalProperties": false,
    "properties": {
      "method": {"type": "string", "pattern": "^[A-Z]+$"},
      "host": {"type": "string", "minLength": 1},
      "path": {"type": "string", "pattern": "^/"},
      "status_code": {"type": "integer", "minimum": 100, "maximum": 599},
      "user_agent": {"type": "string"}
    },
    "minProperties": 1
  },
  "versioned_component": {
    "type": "object",
    "additionalProperties": false,
    "required": ["name", "version"],
    "properties": {
      "name": {"type": "string", "minLength": 1},
      "version": {"$ref": "#/$defs/semver"}
    }
  },
  "raw_event": {
    "type": "object",
    "additionalProperties": false,
    "required": ["encoding", "content_type", "content"],
    "properties": {
      "encoding": {"const": "utf-8"},
      "content_type": {"type": "string", "minLength": 1},
      "content": {"type": "string"}
    }
  },
  "traceability": {
    "type": "object",
    "additionalProperties": false,
    "required": ["raw_event_id", "raw_sha256", "source_pack", "parser"],
    "properties": {
      "raw_event_id": {"type": "string", "format": "uuid"},
      "raw_sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
      "source_pack": {"$ref": "#/$defs/versioned_component"},
      "parser": {"$ref": "#/$defs/versioned_component"},
      "raw_event": {"$ref": "#/$defs/raw_event"}
    }
  },
  "quality": {
    "type": "object",
    "additionalProperties": false,
    "required": ["status", "parsing_confidence", "missing_fields", "warnings"],
    "properties": {
      "status": {"enum": ["valid", "partial", "invalid", "unknown"]},
      "parsing_confidence": {"type": "number", "minimum": 0, "maximum": 1},
      "missing_fields": {"type": "array", "items": {"type": "string"}, "uniqueItems": true},
      "warnings": {"type": "array", "items": {"type": "string"}}
    }
  },
  "extensions": {
    "type": "object",
    "propertyNames": {"pattern": "^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$"},
    "additionalProperties": {"type": "object"}
  }
}
```

- [ ] **Step 4: Run schema-contract tests**

Run:

```bash
python -m pytest tests/test_schema_contract.py -v
```

Expected: three tests pass.

- [ ] **Step 5: Commit the structural contract**

```bash
git add schemas/unified-event-v1.schema.json tests/test_schema_contract.py
git commit -m "feat: define UnifiedEvent JSON Schema v1"
```

---

### Task 3: Implement reusable structural validation

**Files:**
- Create: `src/validation/schema_validation.py`
- Create: `tests/test_schema_validation.py`
- Create: `tests/fixtures/valid_minimal_network_event.json`

**Interfaces:**
- Produces: `load_schema(path: Path = DEFAULT_SCHEMA_PATH) -> dict[str, Any]`.
- Produces: `validate_structure(event: Mapping[str, Any], schema: Mapping[str, Any] | None = None) -> tuple[ValidationIssue, ...]`.
- Consumes: `ValidationIssue` and `schemas/unified-event-v1.schema.json`.

- [ ] **Step 1: Create a valid minimal network fixture**

```json
{
  "schema_version": "1.0.0",
  "event": {
    "id": "b981f746-dc29-4f19-91d4-1c6edca806e5",
    "kind": "event",
    "category": "network",
    "type": "connection",
    "name": "Firewall traffic allowed"
  },
  "time": {
    "observed_at": "2026-08-30T10:15:30Z",
    "ingested_at": "2026-08-30T10:15:31Z",
    "normalized_at": "2026-08-30T10:15:32Z"
  },
  "source": {"ip": "192.0.2.10", "port": 51514},
  "destination": {"ip": "198.51.100.20", "port": 443},
  "observer": {"vendor": "example_vendor", "product": "edge_firewall", "type": "firewall"},
  "network": {"transport": "tcp", "application_protocol": "https", "direction": "outbound"},
  "action": {"original": "Accept", "normalized": "allow", "outcome": "success"},
  "severity": {"original": "Info", "normalized": 1, "label": "informational"},
  "traceability": {
    "raw_event_id": "c065ea9a-04fc-4a45-8aa9-b6a919a0fdf6",
    "raw_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "source_pack": {"name": "example_firewall", "version": "1.0.0"},
    "parser": {"name": "syslog_parser", "version": "1.0.0"}
  },
  "quality": {"status": "valid", "parsing_confidence": 1.0, "missing_fields": [], "warnings": []}
}
```

- [ ] **Step 2: Write structural validation tests**

```python
# tests/test_schema_validation.py
import copy
import json
from pathlib import Path

from src.validation.schema_validation import load_schema, validate_structure

FIXTURE = Path("tests/fixtures/valid_minimal_network_event.json")


def load_event() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_valid_event_has_no_structural_issues() -> None:
    assert validate_structure(load_event()) == ()


def test_missing_required_section_reports_json_path() -> None:
    event = load_event()
    del event["traceability"]

    issues = validate_structure(event)

    assert any(issue.path == "$" and issue.rule == "required" for issue in issues)
    assert any("traceability" in issue.message for issue in issues)


def test_invalid_ip_and_port_are_both_reported() -> None:
    event = copy.deepcopy(load_event())
    event["source"]["ip"] = "999.1.1.1"
    event["source"]["port"] = 70000

    issues = validate_structure(event)

    assert any(issue.path == "$.source.ip" for issue in issues)
    assert any(issue.path == "$.source.port" for issue in issues)


def test_unknown_top_level_property_is_rejected() -> None:
    event = load_event()
    event["vendor_policy"] = "POL-1"

    issues = validate_structure(event)

    assert any(issue.path == "$" and issue.rule == "additionalProperties" for issue in issues)


def test_schema_load_returns_independent_dictionary() -> None:
    first = load_schema()
    second = load_schema()
    assert first == second
    assert first is not second
```

- [ ] **Step 3: Run tests to verify missing module failure**

Run:

```bash
python -m pytest tests/test_schema_validation.py -v
```

Expected: collection fails because `schema_validation.py` does not exist.

- [ ] **Step 4: Implement structural validation**

```python
# src/validation/schema_validation.py
import copy
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .result import ValidationIssue

DEFAULT_SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas" / "unified-event-v1.schema.json"


def load_schema(path: Path = DEFAULT_SCHEMA_PATH) -> dict[str, Any]:
    schema = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return copy.deepcopy(schema)


def _json_path(parts: list[Any]) -> str:
    path = "$"
    for part in parts:
        path += f"[{part}]" if isinstance(part, int) else f".{part}"
    return path


def validate_structure(
    event: Mapping[str, Any],
    schema: Mapping[str, Any] | None = None,
) -> tuple[ValidationIssue, ...]:
    active_schema = dict(schema) if schema is not None else load_schema()
    validator = Draft202012Validator(active_schema, format_checker=FormatChecker())
    errors = sorted(
        validator.iter_errors(event),
        key=lambda error: (tuple(str(part) for part in error.path), error.message),
    )
    return tuple(
        ValidationIssue(
            path=_json_path(list(error.absolute_path)),
            rule=str(error.validator),
            message=error.message,
        )
        for error in errors
    )
```

- [ ] **Step 5: Run structural tests and lint**

Run:

```bash
python -m pytest tests/test_schema_validation.py -v
ruff check src tests
```

Expected: five tests pass and Ruff reports no errors.

- [ ] **Step 6: Commit reusable structural validation**

```bash
git add src/validation/schema_validation.py tests/test_schema_validation.py tests/fixtures/valid_minimal_network_event.json
git commit -m "feat: validate UnifiedEvent structure"
```

---

### Task 4: Add semantic and raw-integrity validation

**Files:**
- Create: `src/validation/semantic_validation.py`
- Create: `tests/test_semantic_validation.py`

**Interfaces:**
- Produces: `validate_semantics(event: Mapping[str, Any]) -> tuple[ValidationIssue, ...]`.
- Consumes: structurally valid or partially valid event mappings; never mutates them.

- [ ] **Step 1: Write semantic validation tests**

```python
# tests/test_semantic_validation.py
import copy
import json
from pathlib import Path

from src.validation.semantic_validation import validate_semantics

FIXTURE = Path("tests/fixtures/valid_minimal_network_event.json")


def load_event() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def issue_paths(event: dict) -> set[str]:
    return {issue.path for issue in validate_semantics(event)}


def test_valid_event_has_no_semantic_issues() -> None:
    assert validate_semantics(load_event()) == ()


def test_timestamp_order_is_enforced_without_mutation() -> None:
    event = load_event()
    event["time"]["ingested_at"] = "2026-08-30T10:15:29Z"
    original = copy.deepcopy(event)

    assert "$.time" in issue_paths(event)
    assert event == original


def test_block_action_cannot_report_success() -> None:
    event = load_event()
    event["action"] = {"original": "Block", "normalized": "block", "outcome": "success"}

    assert "$.action.outcome" in issue_paths(event)


def test_known_severity_label_must_match_normalized_range() -> None:
    event = load_event()
    event["severity"] = {"original": "High", "normalized": 8, "label": "low"}

    assert "$.severity.label" in issue_paths(event)


def test_unknown_severity_requires_quality_warning() -> None:
    event = load_event()
    event["severity"]["label"] = "unknown"

    assert "$.severity.label" in issue_paths(event)


def test_authentication_result_must_match_action_outcome() -> None:
    event = load_event()
    event["event"]["category"] = "authentication"
    event["authentication"] = {"user": "alice", "result": "failure"}
    event["action"]["outcome"] = "success"

    assert "$.authentication.result" in issue_paths(event)


def test_partial_quality_requires_an_explanation() -> None:
    event = load_event()
    event["quality"]["status"] = "partial"

    assert "$.quality" in issue_paths(event)


def test_embedded_raw_content_hash_is_verified() -> None:
    event = load_event()
    event["traceability"]["raw_event"] = {
        "encoding": "utf-8",
        "content_type": "text/plain",
        "content": "original log",
    }

    assert "$.traceability.raw_sha256" in issue_paths(event)


def test_namespaced_extensions_are_accepted() -> None:
    event = load_event()
    event["extensions"] = {"example_vendor": {"policy_id": "POL-1"}}

    assert validate_semantics(event) == ()
```

- [ ] **Step 2: Run tests and confirm the missing module failure**

Run:

```bash
python -m pytest tests/test_semantic_validation.py -v
```

Expected: collection fails because `semantic_validation.py` does not exist.

- [ ] **Step 3: Implement the semantic rules**

```python
# src/validation/semantic_validation.py
import hashlib
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from .result import ValidationIssue

VENDOR_NAMESPACE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")


def _issue(path: str, rule: str, message: str) -> ValidationIssue:
    return ValidationIssue(path=path, rule=rule, message=message)


def _parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None


def validate_semantics(event: Mapping[str, Any]) -> tuple[ValidationIssue, ...]:
    issues: list[ValidationIssue] = []
    time = event.get("time", {})
    if isinstance(time, Mapping):
        observed = _parse_utc(time.get("observed_at"))
        ingested = _parse_utc(time.get("ingested_at"))
        normalized = _parse_utc(time.get("normalized_at"))
        if all(value is not None for value in (observed, ingested, normalized)):
            if not observed <= ingested <= normalized:
                issues.append(_issue("$.time", "timestamp_order", "must satisfy observed_at <= ingested_at <= normalized_at"))

    event_meta = event.get("event", {})
    category = event_meta.get("category") if isinstance(event_meta, Mapping) else None
    if category == "network":
        for endpoint_name in ("source", "destination"):
            endpoint = event.get(endpoint_name)
            if not isinstance(endpoint, Mapping) or not endpoint.get("ip"):
                issues.append(_issue(f"$.{endpoint_name}.ip", "network_endpoint", "network events require an IP address"))
    if category == "intrusion_detection" and not isinstance(event.get("threat"), Mapping):
        issues.append(_issue("$.threat", "category_requirement", "intrusion_detection events require threat details"))
    if category == "authentication" and not isinstance(event.get("authentication"), Mapping):
        issues.append(_issue("$.authentication", "category_requirement", "authentication events require authentication details"))

    action = event.get("action", {})
    if isinstance(action, Mapping):
        if action.get("normalized") in {"deny", "block"} and action.get("outcome") == "success":
            issues.append(_issue("$.action.outcome", "action_consistency", "deny and block actions cannot have success outcome"))

    severity = event.get("severity", {})
    if isinstance(severity, Mapping):
        normalized_severity = severity.get("normalized")
        severity_label = severity.get("label")
        if type(normalized_severity) is int and severity_label != "unknown":
            if normalized_severity == 0:
                expected_label = "informational"
            elif normalized_severity <= 3:
                expected_label = "low"
            elif normalized_severity <= 6:
                expected_label = "medium"
            elif normalized_severity <= 8:
                expected_label = "high"
            else:
                expected_label = "critical"
            if severity_label != expected_label:
                issues.append(_issue("$.severity.label", "severity_consistency", f"normalized severity {normalized_severity} requires label {expected_label}"))
        if severity_label == "unknown":
            quality_for_severity = event.get("quality", {})
            warnings = quality_for_severity.get("warnings", []) if isinstance(quality_for_severity, Mapping) else []
            if not warnings:
                issues.append(_issue("$.severity.label", "severity_uncertainty", "unknown severity requires a quality warning"))

    authentication = event.get("authentication")
    if isinstance(authentication, Mapping) and isinstance(action, Mapping):
        auth_result = authentication.get("result")
        outcome = action.get("outcome")
        if auth_result in {"success", "failure"} and outcome in {"success", "failure"} and auth_result != outcome:
            issues.append(_issue("$.authentication.result", "outcome_consistency", "authentication result must match action outcome"))

    quality = event.get("quality", {})
    if isinstance(quality, Mapping) and quality.get("status") == "partial":
        if not quality.get("missing_fields") and not quality.get("warnings"):
            issues.append(_issue("$.quality", "partial_explanation", "partial quality requires missing_fields or warnings"))

    extensions = event.get("extensions", {})
    if isinstance(extensions, Mapping):
        for namespace in extensions:
            if not isinstance(namespace, str) or not VENDOR_NAMESPACE.fullmatch(namespace):
                issues.append(_issue(f"$.extensions.{namespace}", "vendor_namespace", "extension namespace must be lowercase snake_case"))

    traceability = event.get("traceability", {})
    if isinstance(traceability, Mapping) and isinstance(traceability.get("raw_event"), Mapping):
        raw_event = traceability["raw_event"]
        content = raw_event.get("content")
        if isinstance(content, str):
            actual_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
            if actual_hash != traceability.get("raw_sha256"):
                issues.append(_issue("$.traceability.raw_sha256", "raw_integrity", "does not match embedded raw_event content"))

    return tuple(sorted(set(issues)))
```

- [ ] **Step 4: Run semantic tests and lint**

Run:

```bash
python -m pytest tests/test_semantic_validation.py -v
ruff check src tests
```

Expected: nine tests pass and Ruff reports no errors.

- [ ] **Step 5: Commit semantic validation**

```bash
git add src/validation/semantic_validation.py tests/test_semantic_validation.py
git commit -m "feat: validate UnifiedEvent semantics"
```

---

### Task 5: Compose validation and implement the CLI

**Files:**
- Create: `src/validation/validate_unified_event.py`
- Modify: `src/validation/__init__.py`
- Create: `tests/test_cli.py`

**Interfaces:**
- Produces: `validate_event(event: Mapping[str, Any]) -> ValidationResult`.
- Produces: `validate_file(path: Path) -> ValidationResult`.
- Produces: `main(argv: Sequence[str] | None = None) -> int`.
- Consumes: `validate_structure`, `validate_semantics`, `ValidationResult`.

- [ ] **Step 1: Write API and CLI tests**

```python
# tests/test_cli.py
import json
from pathlib import Path

from src.validation.validate_unified_event import main, validate_event, validate_file

VALID_FIXTURE = Path("tests/fixtures/valid_minimal_network_event.json")


def test_validate_event_combines_structural_and_semantic_issues() -> None:
    event = json.loads(VALID_FIXTURE.read_text(encoding="utf-8"))
    event["source"]["port"] = 70000
    event["action"] = {"original": "Deny", "normalized": "deny", "outcome": "success"}

    result = validate_event(event)

    assert result.valid is False
    assert {issue.path for issue in result.issues} >= {"$.source.port", "$.action.outcome"}


def test_validate_file_accepts_valid_event() -> None:
    assert validate_file(VALID_FIXTURE).valid is True


def test_cli_returns_zero_for_valid_event(capsys) -> None:
    exit_code = main([str(VALID_FIXTURE)])
    output = capsys.readouterr()

    assert exit_code == 0
    assert output.out == f"VALID: {VALID_FIXTURE} conforms to UnifiedEvent Schema v1\n"
    assert output.err == ""


def test_cli_returns_one_and_prints_sorted_issues(tmp_path: Path, capsys) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text('{"schema_version": "1.0.0"}', encoding="utf-8")

    exit_code = main([str(invalid)])
    output = capsys.readouterr()

    assert exit_code == 1
    assert output.out.startswith(f"INVALID: {invalid}\n")
    assert "- $ [required]" in output.out


def test_cli_returns_two_for_missing_file(tmp_path: Path, capsys) -> None:
    missing = tmp_path / "missing.json"

    exit_code = main([str(missing)])
    output = capsys.readouterr()

    assert exit_code == 2
    assert output.err.startswith(f"ERROR: unable to read {missing}:")
```

- [ ] **Step 2: Run CLI tests and confirm missing implementation failure**

Run:

```bash
python -m pytest tests/test_cli.py -v
```

Expected: collection fails because `validate_unified_event.py` does not exist.

- [ ] **Step 3: Implement the composition API and CLI**

```python
# src/validation/validate_unified_event.py
import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .result import ValidationResult
from .schema_validation import validate_structure
from .semantic_validation import validate_semantics


def validate_event(event: Mapping[str, Any]) -> ValidationResult:
    issues = set(validate_structure(event))
    issues.update(validate_semantics(event))
    return ValidationResult(issues=tuple(sorted(issues)))


def validate_file(path: Path) -> ValidationResult:
    event = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(event, dict):
        raise ValueError("top-level JSON value must be an object")
    return validate_event(event)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate one ULPF UnifiedEvent v1 JSON file")
    parser.add_argument("event_file", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = validate_file(args.event_file)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        print(f"ERROR: unable to read {args.event_file}: {error}", file=sys.stderr)
        return 2

    if result.valid:
        print(f"VALID: {args.event_file} conforms to UnifiedEvent Schema v1")
        return 0

    print(f"INVALID: {args.event_file}")
    for issue in result.issues:
        print(f"- {issue.path} [{issue.rule}] {issue.message}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
```

Keep package exports limited to dependency-free result types so `python -m` does not import the CLI module twice:

```python
# src/validation/__init__.py
from .result import ValidationIssue, ValidationResult

__all__ = ["ValidationIssue", "ValidationResult"]
```

- [ ] **Step 4: Run focused tests and exercise the real command**

Run:

```bash
python -m pytest tests/test_cli.py -v
python -m src.validation.validate_unified_event tests/fixtures/valid_minimal_network_event.json
```

Expected: five tests pass and the command prints `VALID` with exit code 0.

- [ ] **Step 5: Commit the validation entry point**

```bash
git add src/validation tests/test_cli.py
git commit -m "feat: add UnifiedEvent validation CLI"
```

---

### Task 6: Add seven valid perimeter-event examples

**Files:**
- Create: `examples/unified_events/firewall_allow.json`
- Create: `examples/unified_events/firewall_deny.json`
- Create: `examples/unified_events/ids_threat_detected.json`
- Create: `examples/unified_events/vpn_authentication_failed.json`
- Create: `examples/unified_events/proxy_request_blocked.json`
- Create: `examples/unified_events/router_acl_deny.json`
- Create: `examples/unified_events/waf_attack_blocked.json`
- Create: `tests/test_examples.py`

**Interfaces:**
- Produces: seven valid, fictional UnifiedEvent v1 records used by demos and documentation.
- Consumes: `validate_file` and the approved schema.

- [ ] **Step 1: Write the example-coverage test before the examples**

```python
# tests/test_examples.py
from pathlib import Path

import pytest

from src.validation.validate_unified_event import validate_file

EXAMPLE_DIRECTORY = Path("examples/unified_events")
EXPECTED_EXAMPLES = {
    "firewall_allow.json",
    "firewall_deny.json",
    "ids_threat_detected.json",
    "vpn_authentication_failed.json",
    "proxy_request_blocked.json",
    "router_acl_deny.json",
    "waf_attack_blocked.json",
}


def test_exact_example_set_exists() -> None:
    assert {path.name for path in EXAMPLE_DIRECTORY.glob("*.json")} == EXPECTED_EXAMPLES


@pytest.mark.parametrize("filename", sorted(EXPECTED_EXAMPLES))
def test_official_example_is_valid(filename: str) -> None:
    result = validate_file(EXAMPLE_DIRECTORY / filename)
    assert result.valid, result.issues
```

- [ ] **Step 2: Run the coverage test and confirm the missing examples**

Run:

```bash
python -m pytest tests/test_examples.py -v
```

Expected: `test_exact_example_set_exists` fails and parametrized cases report missing files.

- [ ] **Step 3: Create the canonical firewall allow example**

Copy `tests/fixtures/valid_minimal_network_event.json` to `examples/unified_events/firewall_allow.json`, then add fictional observer metadata, `network.bytes`, `network.packets`, and a namespaced extension:

```json
"observer": {
  "vendor": "example_vendor",
  "product": "edge_firewall",
  "type": "firewall",
  "hostname": "edge-fw-01",
  "serial_number": "EXAMPLE-FW-001",
  "software_version": "1.0"
},
"network": {
  "transport": "tcp",
  "application_protocol": "https",
  "direction": "outbound",
  "bytes": 2048,
  "packets": 12
},
"extensions": {
  "example_vendor": {
    "policy_id": "POL-ALLOW-100"
  }
}
```

- [ ] **Step 4: Create the remaining six records using this exact coverage matrix**

Every record retains the mandatory core, unique UUIDs and valid fictional hashes. Use these exact distinguishing values:

| File | Category/type | Observer | Action/outcome | Required optional content |
|---|---|---|---|---|
| `firewall_deny.json` | `network/connection` | `firewall` | `deny/failure` | source, destination, TCP network, reason `Blocked by perimeter policy` |
| `ids_threat_detected.json` | `intrusion_detection/signature_match` | `ids` | `detect/unknown` | threat name `Suspicious command-and-control traffic`, signature `SIG-1001`, confidence `0.94` |
| `vpn_authentication_failed.json` | `authentication/vpn_login` | `vpn` | `authenticate/failure` | authentication user `alice`, method `password`, result `failure`, reason `invalid_credentials` |
| `proxy_request_blocked.json` | `web/proxy_request` | `proxy` | `block/failure` | HTTP GET, host `blocked.example`, path `/malware`, status `403` |
| `router_acl_deny.json` | `network/acl_match` | `router` | `deny/failure` | source, destination, UDP network, extension ACL `EDGE-IN` |
| `waf_attack_blocked.json` | `web/waf_attack` | `waf` | `block/failure` | threat `SQL injection attempt`, HTTP POST `/login`, embedded raw content |

Use reserved IPs from `192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24`. For `waf_attack_blocked.json`, embed exactly:

```json
"raw_event": {
  "encoding": "utf-8",
  "content_type": "text/plain",
  "content": "<134>WAF blocked SQL injection from 192.0.2.70 to /login"
}
```

Set its `raw_sha256` to:

```text
61ec4a5247db0f628c5c97a924f4579b4355dcfe56093dc0f0bf48f58cb534d5
```

- [ ] **Step 5: Run all example tests and validate one example through the CLI**

Run:

```bash
python -m pytest tests/test_examples.py -v
python -m src.validation.validate_unified_event examples/unified_events/waf_attack_blocked.json
```

Expected: eight tests pass and the WAF example prints `VALID`.

- [ ] **Step 6: Commit valid demonstration records**

```bash
git add examples/unified_events tests/test_examples.py
git commit -m "test: add perimeter UnifiedEvent examples"
```

---

### Task 7: Add invalid regression fixtures

**Files:**
- Create: `tests/fixtures/invalid_unified_events/*.json`
- Create: `tests/test_invalid_fixtures.py`

**Interfaces:**
- Produces: one fixture per named validation rule, with expected path encoded in the test table.
- Consumes: `validate_file`.

- [ ] **Step 1: Write the invalid-fixture matrix test**

```python
# tests/test_invalid_fixtures.py
from pathlib import Path

import pytest

from src.validation.validate_unified_event import validate_file

INVALID_DIRECTORY = Path("tests/fixtures/invalid_unified_events")

CASES = [
    ("missing_traceability.json", "$"),
    ("invalid_ip.json", "$.source.ip"),
    ("invalid_port.json", "$.source.port"),
    ("invalid_severity.json", "$.severity.normalized"),
    ("invalid_sha256.json", "$.traceability.raw_sha256"),
    ("timestamp_order.json", "$.time"),
    ("missing_network_endpoint.json", "$.destination.ip"),
    ("missing_threat.json", "$"),
    ("missing_authentication.json", "$"),
    ("unnamespaced_extension.json", "$.extensions"),
    ("raw_hash_mismatch.json", "$.traceability.raw_sha256"),
    ("unknown_top_level_property.json", "$"),
]


@pytest.mark.parametrize(("filename", "expected_path"), CASES)
def test_invalid_fixture_fails_for_expected_path(filename: str, expected_path: str) -> None:
    result = validate_file(INVALID_DIRECTORY / filename)

    assert result.valid is False
    assert expected_path in {issue.path for issue in result.issues}
```

- [ ] **Step 2: Run the matrix and confirm missing fixture errors**

Run:

```bash
python -m pytest tests/test_invalid_fixtures.py -v
```

Expected: twelve failures because the fixture files do not exist.

- [ ] **Step 3: Generate each fixture as one deliberate mutation**

Start from `tests/fixtures/valid_minimal_network_event.json` and make exactly one relevant change per file:

| Fixture | Exact mutation |
|---|---|
| `missing_traceability.json` | Delete top-level `traceability` |
| `invalid_ip.json` | Set `source.ip` to `999.1.1.1` |
| `invalid_port.json` | Set `source.port` to `70000` |
| `invalid_severity.json` | Set `severity.normalized` to `11` |
| `invalid_sha256.json` | Set `traceability.raw_sha256` to `not-a-sha256` |
| `timestamp_order.json` | Set `time.ingested_at` to `2026-08-30T10:15:29Z` |
| `missing_network_endpoint.json` | Delete `destination.ip` |
| `missing_threat.json` | Set `event.category` to `intrusion_detection` without adding `threat` |
| `missing_authentication.json` | Set `event.category` to `authentication` without adding `authentication` |
| `unnamespaced_extension.json` | Add `extensions` with key `Example-Vendor` |
| `raw_hash_mismatch.json` | Embed raw content `original log` while leaving `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` as the digest |
| `unknown_top_level_property.json` | Add top-level `vendor_policy` |

- [ ] **Step 4: Run invalid and valid fixture tests together**

Run:

```bash
python -m pytest tests/test_invalid_fixtures.py tests/test_examples.py -v
```

Expected: all twenty parametrized checks pass.

- [ ] **Step 5: Commit regression fixtures**

```bash
git add tests/fixtures/invalid_unified_events tests/test_invalid_fixtures.py
git commit -m "test: cover invalid UnifiedEvent records"
```

---

### Task 8: Add shared engineering and beginner documentation

**Files:**
- Rewrite: `README.md`
- Create: `CONTRIBUTING.md`
- Create: `docs/architecture.md`
- Create: `docs/component-boundaries.md`
- Create: `docs/development-workflow.md`
- Create: `docs/engineering-conventions.md`
- Create: `docs/event-schema.md`
- Modify: `docs/research-basis.md`
- Create: `docs/source-pack-guide.md`
- Create: `tests/test_documentation_contract.py`

**Interfaces:**
- Produces: one authoritative naming and boundary contract for all six components.
- Consumes: schema commands, class names and paths delivered in Tasks 1–7.

- [ ] **Step 1: Write a documentation-contract test**

```python
# tests/test_documentation_contract.py
from pathlib import Path

REQUIRED_FILES = {
    "README.md",
    "CONTRIBUTING.md",
    "docs/architecture.md",
    "docs/component-boundaries.md",
    "docs/development-workflow.md",
    "docs/engineering-conventions.md",
    "docs/event-schema.md",
    "docs/research-basis.md",
    "docs/source-pack-guide.md",
}


def test_required_documentation_exists_and_is_not_empty() -> None:
    for filename in REQUIRED_FILES:
        content = Path(filename).read_text(encoding="utf-8")
        assert len(content.splitlines()) >= 8, filename


def test_engineering_conventions_lock_shared_names() -> None:
    content = Path("docs/engineering-conventions.md").read_text(encoding="utf-8")
    for name in (
        "RawEventEnvelope",
        "ParsedEvent",
        "UnifiedEvent",
        "SourcePack",
        "ValidationResult",
        "QualityFlags",
        "Traceability",
    ):
        assert name in content


def test_readme_contains_working_commands() -> None:
    content = Path("README.md").read_text(encoding="utf-8")
    assert "python -m pytest" in content
    assert "python -m src.validation.validate_unified_event" in content
```

- [ ] **Step 2: Run the documentation test and confirm failure**

Run:

```bash
python -m pytest tests/test_documentation_contract.py -v
```

Expected: failures for the missing documentation and existing short README.

- [ ] **Step 3: Rewrite README with these exact sections**

```markdown
# ULPF Prism

## Problem
Explain heterogeneous perimeter logs, lossless preservation and normalization.

## Sprint 0 deliverable
Describe RawEventEnvelope -> ParsedEvent -> UnifiedEvent and the Cisco ASA vertical slice.

## Architecture
Link to docs/architecture.md and show the six component boundaries.

## Quick start
Show venv creation, dependency installation, pytest and validator commands.

## Example
Validate examples/unified_events/firewall_deny.json.

## Documentation
Link every document created by this task.

## Team workflow
Link CONTRIBUTING.md and state that direct commits to main are not allowed.
```

Write full prose under each heading; do not claim that unimplemented components already work.

- [ ] **Step 4: Create the contribution and workflow documents**

`CONTRIBUTING.md` must define:

- Branch format `feature/issue-N-short-name`.
- `git switch main`, `git pull origin main`, branch creation, focused add, commit and push commands.
- Pull-request template containing `Closes #N`, completed work, checks and help needed.
- One-review minimum and two-review requirement for shared contract changes.
- Prohibition on secrets, direct `main` commits, force pushes and destructive Git recovery.

`docs/development-workflow.md` must explain the project statuses Backlog, Ready, In progress, Blocked, In review, Testing and Done, plus the daily update format:

```text
Yesterday: completed work
Today: planned work
Blocked: required help or decision
```

- [ ] **Step 5: Create architecture and ownership documents**

`docs/architecture.md` must include:

```text
Perimeter device
  -> Collection / RawEventEnvelope
  -> Parsing / ParsedEvent
  -> Normalization / UnifiedEvent
  -> Streaming
  -> Visibility and integration consumers
```

It must explain that raw evidence and normalized records remain linked by ID and hash.

`docs/component-boundaries.md` must record:

| Component | Owner | Input | Output |
|---|---|---|---|
| Collection | Daksh R Jain | device log | `RawEventEnvelope` |
| Parsing | Garvit Mundra | `RawEventEnvelope` | `ParsedEvent` |
| Normalization | Gaurang Bhatia | `ParsedEvent` | `UnifiedEvent` |
| Streaming | Lalit Kumar Sureliya | shared event contracts | transported event |
| Visibility | Unassigned | `UnifiedEvent` | search/dashboard views |
| Integration | Sharanya | `UnifiedEvent` plus raw references | JSON/data-lake output |

- [ ] **Step 6: Create the authoritative engineering conventions**

`docs/engineering-conventions.md` must define:

- Python `snake_case`, `PascalCase` and `UPPER_SNAKE_CASE` rules.
- JSON `snake_case`, dotted-free category names and lowercase snake-case enums.
- UTC `Z` timestamps, UUID event IDs and lowercase SHA-256 digests.
- Reserved class names from the global contract.
- Shared contracts live only under `src/contracts/`.
- Structured application log fields: `timestamp`, `level`, `component`, `message`, `event_id`, `error_code`.
- Error codes use `COMPONENT_REASON`, for example `NORMALIZATION_SCHEMA_INVALID`.
- Public functions require type hints and docstrings.
- Tests mirror source responsibilities and use fictional inputs.
- Contract changes require review by the contract owner and an affected owner.

- [ ] **Step 7: Create schema and source-pack boundary references**

`docs/event-schema.md` must document every top-level section, required/optional status, enums, UTC order, quality behavior, namespaced extensions and the CLI commands.

`docs/research-basis.md` must link the primary standards and papers from Task 0, explain each adopted design decision and explicitly state that UnifiedEvent v1 is aligned rather than fully compliant.

`docs/source-pack-guide.md` must remain deliberately limited to the boundary:

```text
SourcePack consumes RawEventEnvelope and produces ParsedEvent.
ParsedEvent mappings target canonical UnifiedEvent snake_case paths.
Source-specific values with no mapping must survive under a vendor namespace such as extensions.example_vendor.
Source Pack detailed detection, parsing and packaging design remains owned by Epic 2.
```

- [ ] **Step 8: Run documentation tests and lint**

Run:

```bash
python -m pytest tests/test_documentation_contract.py -v
ruff check src tests
```

Expected: three documentation tests pass and Ruff reports no errors.

- [ ] **Step 9: Commit shared documentation**

```bash
git add README.md CONTRIBUTING.md docs .editorconfig .gitignore pyproject.toml requirements-dev.txt tests/test_documentation_contract.py
git commit -m "docs: establish ULPF engineering conventions"
```

---

### Task 9: Verify the complete issue deliverable

**Files:**
- Modify only files that fail the verification commands.

**Interfaces:**
- Consumes: all deliverables from Tasks 1–8.
- Produces: clean branch ready for pull-request review by Members 1 and 2.

- [ ] **Step 1: Run the complete automated suite**

Run:

```bash
source .venv/bin/activate
python -m pytest -v
```

Expected: every test passes with no warnings caused by project code.

- [ ] **Step 2: Run formatting and lint checks**

Run:

```bash
ruff format --check src tests
ruff check src tests
```

Expected: both commands exit 0.

- [ ] **Step 3: Validate every official example through the real CLI**

Run:

```bash
for event_file in examples/unified_events/*.json; do
  python -m src.validation.validate_unified_event "$event_file" || exit 1
done
```

Expected: seven `VALID` lines and exit code 0.

- [ ] **Step 4: Verify a known invalid fixture through the real CLI**

Run:

```bash
python -m src.validation.validate_unified_event tests/fixtures/invalid_unified_events/invalid_port.json
test $? -eq 1
```

Expected: `INVALID`, a `$.source.port` diagnostic and final shell status 0.

- [ ] **Step 5: Check documentation links, whitespace and working tree**

Run:

```bash
git diff --check
git status --short
git log --oneline --decorate -10
```

Expected: no whitespace errors; only deliberate fixes, if any, are uncommitted.

- [ ] **Step 6: Commit verification fixes only if needed**

```bash
git status --short
git add -u
git commit -m "fix: resolve UnifiedEvent verification findings"
```

`git add -u` stages only modifications and deletions to tracked files. Skip this commit when verification required no changes, and inspect any untracked file separately rather than using `git add .`.

- [ ] **Step 7: Prepare the pull-request description without opening it yet**

```markdown
Closes #9

## What I completed
- Defined UnifiedEvent JSON Schema v1.
- Added structural, semantic and raw-integrity validation.
- Added a reusable Python API and command-line validator.
- Added seven valid perimeter-event examples and invalid regression fixtures.
- Established shared engineering conventions and beginner documentation.

## Verification
- `python -m pytest -v`
- `ruff format --check src tests`
- `ruff check src tests`
- Validated all seven examples through the CLI.

## Review required
- Member 1: verify RawEventEnvelope traceability boundary.
- Member 2: verify ParsedEvent and Source Pack mapping boundary.
```

Do not push or open the pull request until Gaurang reviews the local diff and verification results.
