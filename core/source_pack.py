"""
core/source_pack.py

Defines the contract every Source Pack must implement. The core engine only
ever talks to packs through this interface — it never imports a specific
vendor pack by name. This is the plug-and-play boundary: new vendors are
added by dropping a new directory under source_packs/ that satisfies
SourcePackBase, with zero changes to core/.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from core.exceptions import FieldExtractionError, SourcePackValidationError
from core.parsers import get_parser
from src.contracts import (
    ParsedEvent,
    ParseIssue,
    ParseIssueSeverity,
    ParseStatus,
    RawEventEnvelope,
)

_REQUIRED_MANIFEST_KEYS = ("pack", "detection", "format", "fields")


def validate_manifest(manifest: Any) -> dict[str, Any]:
    """Validate the common structure required by every Source Pack."""

    if not isinstance(manifest, dict):
        raise SourcePackValidationError("Source Pack manifest must be a YAML mapping")

    missing = [key for key in _REQUIRED_MANIFEST_KEYS if key not in manifest]
    if missing:
        raise SourcePackValidationError(f"Manifest missing required section(s): {missing}")

    pack = manifest["pack"]
    detection = manifest["detection"]
    format_config = manifest["format"]
    fields = manifest["fields"]
    if not isinstance(pack, dict):
        raise SourcePackValidationError("Manifest 'pack' section must be a mapping")
    if not isinstance(detection, dict):
        raise SourcePackValidationError("Manifest 'detection' section must be a mapping")
    if not isinstance(format_config, dict):
        raise SourcePackValidationError("Manifest 'format' section must be a mapping")
    if not isinstance(fields, list) or not all(isinstance(field, dict) for field in fields):
        raise SourcePackValidationError("Manifest 'fields' section must be a list of mappings")

    for key in ("vendor", "product", "pack_version"):
        if not isinstance(pack.get(key), str) or not pack[key].strip():
            raise SourcePackValidationError(
                f"Manifest 'pack' section requires a non-empty '{key}'"
            )

    priority = detection.get("priority", 0)
    rules = detection.get("rules", [])
    if isinstance(priority, bool) or not isinstance(priority, int):
        raise SourcePackValidationError("Manifest detection priority must be an integer")
    if not isinstance(rules, list) or not all(isinstance(rule, dict) for rule in rules):
        raise SourcePackValidationError("Manifest detection rules must be a list of mappings")
    if not isinstance(format_config.get("type"), str) or not format_config["type"].strip():
        raise SourcePackValidationError("Manifest format requires a non-empty 'type'")
    for field in fields:
        if not isinstance(field.get("name"), str) or not isinstance(field.get("source"), str):
            raise SourcePackValidationError(
                "Every manifest field requires string 'name' and 'source' values"
            )
    return manifest


class DetectionRule:
    """A single source-detection rule, loaded from a manifest."""

    def __init__(self, rule: dict[str, Any]):
        self.type = rule.get("type")
        self.target = rule.get("target", "raw_payload")
        self.pattern = rule.get("pattern")
        self.any_of = rule.get("any_of", [])
        self.equals = rule.get("equals")

    def matches(self, envelope: RawEventEnvelope) -> bool:
        value = self._resolve_target(envelope)
        if value is None:
            return False

        if self.type == "regex":
            import re
            return bool(re.search(self.pattern, value))
        if self.type == "keyword":
            return any(kw.lower() in value.lower() for kw in self.any_of)
        if self.type == "equals":
            return value == self.equals
        return False

    def _resolve_target(self, envelope: RawEventEnvelope) -> str | None:
        if self.target == "raw_payload":
            return envelope.raw_bytes().decode("utf-8", errors="replace")
        if self.target == "source_ip":
            return str(envelope.source_ip) if envelope.source_ip is not None else None
        if self.target in {"content_type_hint", "vendor_hint", "product_hint"}:
            value = envelope.metadata.get(self.target)
            return str(value) if value is not None else None
        return None


class FieldRule:
    """One entry from the manifest's `fields:` list — maps a parsed key to an output field."""

    def __init__(self, rule: dict[str, Any]):
        self.name: str = rule["name"]
        self.source: str = rule["source"]
        self.type: str = rule.get("type", "string")
        self.default: Any = rule.get("default")
        self.required: bool = rule.get("required", False)


class SourcePackBase:
    """
    Concrete Source Packs subclass this and typically only need to override
    `manifest_path` (or pass it to __init__) — the base class handles
    manifest loading, detection scoring, format-parser dispatch, and field
    mapping generically. Packs override `extract_fields` only when they need
    custom logic beyond declarative field mapping (e.g. severity translation
    tables, timestamp normalization per vendor quirks).
    """

    def __init__(self, manifest_path: Path):
        self.manifest_path = manifest_path
        self.manifest: dict[str, Any] = self._load_manifest(manifest_path)
        self._validate_manifest(self.manifest)

        pack_meta = self.manifest["pack"]
        self.pack_id: str = manifest_path.parent.name
        self.vendor: str = pack_meta["vendor"]
        self.product: str = pack_meta["product"]
        self.pack_version: str = pack_meta["pack_version"]

        self.priority: int = self.manifest["detection"].get("priority", 0)
        self.detection_rules: list[DetectionRule] = [
            DetectionRule(r) for r in self.manifest["detection"].get("rules", [])
        ]

        self.format_type: str = self.manifest["format"]["type"]
        self.format_options: dict[str, Any] = {
            k: v for k, v in self.manifest["format"].items() if k != "type"
        }

        self.field_rules: list[FieldRule] = [FieldRule(f) for f in self.manifest["fields"]]

    # -- loading / validation ---------------------------------------------
    @staticmethod
    def _load_manifest(manifest_path: Path) -> dict[str, Any]:
        with open(manifest_path, encoding="utf-8") as fh:
            return yaml.safe_load(fh)

    @staticmethod
    def _validate_manifest(manifest: dict[str, Any]) -> None:
        validate_manifest(manifest)

    # -- detection ----------------------------------------------------------

    def detect(self, envelope: RawEventEnvelope) -> bool:
        """Returns True if ANY detection rule matches (rules are OR'd)."""
        if not self.detection_rules:
            return False
        return any(rule.matches(envelope) for rule in self.detection_rules)

    # -- parsing --------------------------------------------------------------

    def parse(self, envelope: RawEventEnvelope) -> ParsedEvent:
        parser = get_parser(self.format_type)
        raw_text = envelope.raw_bytes().decode("utf-8", errors="replace")
        parsed_dict = parser.parse(raw_text, **self.format_options)

        issues: list[ParseIssue] = []
        fields: dict[str, Any] = {}
        for rule in self.field_rules:
            try:
                value = self._extract(parsed_dict, rule.source)
                if value is None:
                    value = rule.default
                if value is None and rule.required:
                    raise FieldExtractionError(
                        f"Required field '{rule.name}' not found "
                        f"(source={rule.source})"
                    )
                fields[rule.name] = value
            except FieldExtractionError as exc:
                issues.append(
                    ParseIssue(
                        code="FIELD_EXTRACTION_FAILED",
                        message=str(exc),
                        severity=ParseIssueSeverity.ERROR,
                        field=rule.name,
                    )
                )

        status = ParseStatus.SUCCESS if not issues else ParseStatus.PARTIAL

        return ParsedEvent(
            event_id=envelope.event_id,
            parsed_at=datetime.now(UTC),
            vendor=self.vendor,
            product=self.product,
            product_version=None,
            parser_id=f"core.parsers.{self.format_type}",
            parser_version="1.0.0",
            source_pack_id=self.pack_id,
            source_pack_version=self.pack_version,
            detected_format=self.format_type,
            status=status,
            issues=tuple(issues),
            extracted_fields=fields,
            raw_event=envelope,
        )

    # -- helpers --------------------------------------------------------------

    @staticmethod
    def _extract(data: dict[str, Any], dotted_path: str) -> Any:
        """Resolve a dotted path like 'extension.src' against a nested dict."""
        current: Any = data
        for part in dotted_path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current

    @staticmethod
    def _coerce_timestamp(value: Any) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            for fmt in (
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S%z",
                "%b %d %H:%M:%S",
            ):
                try:
                    return datetime.strptime(value, fmt)
                except ValueError:
                    continue
        return None
