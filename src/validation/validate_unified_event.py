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
