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
