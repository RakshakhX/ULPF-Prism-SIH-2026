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
        rule["if"]["properties"]["event"]["properties"]["category"]["const"]: set(
            rule["then"]["required"]
        )
        for rule in schema["allOf"]
    }

    assert required_by_category["network"] == {"source", "destination", "network"}
    assert required_by_category["intrusion_detection"] == {"threat"}
    assert required_by_category["authentication"] == {"authentication"}


@pytest.fixture
def format_aware_validator(schema: dict) -> Draft202012Validator:
    """Use this configuration when validating UnifiedEvent instances."""
    return Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


def valid_unified_event() -> dict:
    return {
        "schema_version": "1.0.0",
        "event": {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "kind": "event",
            "category": "web",
            "type": "web_request",
            "name": "request",
        },
        "time": {
            "observed_at": "2026-08-30T00:00:00Z",
            "ingested_at": "2026-08-30T00:00:01Z",
            "normalized_at": "2026-08-30T00:00:02Z",
        },
        "observer": {"vendor": "ULPF", "product": "Prism", "type": "unknown"},
        "action": {"original": "allow", "normalized": "allow", "outcome": "success"},
        "severity": {"original": "0", "normalized": 0, "label": "informational"},
        "traceability": {
            "raw_event_id": "123e4567-e89b-12d3-a456-426614174001",
            "raw_sha256": "a" * 64,
            "source_pack": {"name": "example", "version": "1.0.0"},
            "parser": {"name": "example", "version": "1.0.0"},
        },
        "quality": {
            "status": "valid",
            "parsing_confidence": 1,
            "missing_fields": [],
            "warnings": [],
        },
    }


def test_schema_metadata_and_definition_set_are_locked(schema: dict) -> None:
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == "https://rakshakhx.github.io/ulpf/schemas/unified-event-v1.schema.json"
    assert set(schema["$defs"]) == {
        "semver",
        "ip_address",
        "event",
        "time",
        "endpoint",
        "observer",
        "network",
        "action",
        "severity",
        "threat",
        "authentication",
        "http",
        "versioned_component",
        "raw_event",
        "traceability",
        "quality",
        "extensions",
    }


def test_object_definitions_are_closed_except_for_extension_payloads(schema: dict) -> None:
    object_definitions = {
        name for name, definition in schema["$defs"].items() if definition.get("type") == "object"
    }

    assert object_definitions == {
        "event",
        "time",
        "endpoint",
        "observer",
        "network",
        "action",
        "severity",
        "threat",
        "authentication",
        "http",
        "versioned_component",
        "raw_event",
        "traceability",
        "quality",
        "extensions",
    }
    assert all(
        schema["$defs"][name]["additionalProperties"] is False
        for name in object_definitions - {"extensions"}
    )
    assert schema["$defs"]["extensions"]["additionalProperties"] == {"type": "object"}


def test_traceability_requirements_are_locked(schema: dict) -> None:
    traceability = schema["$defs"]["traceability"]

    assert set(traceability["required"]) == {
        "raw_event_id",
        "raw_sha256",
        "source_pack",
        "parser",
    }
    assert traceability["properties"]["source_pack"] == {"$ref": "#/$defs/versioned_component"}
    assert traceability["properties"]["parser"] == {"$ref": "#/$defs/versioned_component"}


@pytest.mark.parametrize("address", ["198.51.100.7", "2001:db8::1"])
def test_format_aware_validator_accepts_ipv4_and_ipv6(
    format_aware_validator: Draft202012Validator, address: str
) -> None:
    instance = valid_unified_event()
    instance["source"] = {"ip": address}

    assert list(format_aware_validator.iter_errors(instance)) == []


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("event", "id", "not-a-uuid"),
        ("time", "observed_at", "not-a-dateZ"),
        ("time", "observed_at", "2026-08-30T00:00:00+00:00"),
        ("source", "ip", "not-an-ip-address"),
    ],
)
def test_format_aware_validator_rejects_invalid_identifiers_and_times(
    format_aware_validator: Draft202012Validator, section: str, field: str, value: str
) -> None:
    instance = valid_unified_event()
    if section == "source":
        instance[section] = {field: value}
    else:
        instance[section][field] = value

    assert list(format_aware_validator.iter_errors(instance))


@pytest.mark.parametrize(
    ("category", "missing_sections"),
    [
        ("network", {"source", "destination", "network"}),
        ("intrusion_detection", {"threat"}),
        ("authentication", {"authentication"}),
    ],
)
def test_category_conditionals_reject_missing_guarded_sections(
    format_aware_validator: Draft202012Validator, category: str, missing_sections: set[str]
) -> None:
    instance = valid_unified_event()
    instance["event"]["category"] = category

    missing = {
        error.message.removeprefix("'").removesuffix("' is a required property")
        for error in format_aware_validator.iter_errors(instance)
        if error.validator == "required"
    }

    assert missing_sections <= missing


@pytest.mark.parametrize("event_value", [pytest.param(None, id="missing"), "not-an-object"])
def test_category_conditionals_do_not_activate_without_an_event_object(
    format_aware_validator: Draft202012Validator, event_value: object
) -> None:
    instance = valid_unified_event()
    if event_value is None:
        del instance["event"]
    else:
        instance["event"] = event_value

    errors = list(format_aware_validator.iter_errors(instance))
    category_required = {"source", "destination", "network", "threat", "authentication"}

    assert not any(
        error.validator == "required"
        and any(section in error.message for section in category_required)
        for error in errors
    )
    if event_value is None:
        assert any(error.validator == "required" and "event" in error.message for error in errors)
    else:
        assert any(error.validator == "type" and list(error.path) == ["event"] for error in errors)
