import copy
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .result import ValidationIssue

DEFAULT_SCHEMA_PATH = (
    Path(__file__).resolve().parents[2] / "schemas" / "unified-event-v1.schema.json"
)


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
