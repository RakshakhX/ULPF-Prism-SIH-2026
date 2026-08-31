"""
core/source_pack.py

Defines the contract every Source Pack must implement. The core engine only
ever talks to packs through this interface — it never imports a specific
vendor pack by name. This is the plug-and-play boundary: new vendors are
added by dropping a new directory under source_packs/ that satisfies
SourcePackBase, with zero changes to core/.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from core.exceptions import FieldExtractionError, SourcePackValidationError
from core.models import LogFormat, ParsedEvent, ParsingStatus, RawEventEnvelope, Severity
from core.parsers import get_parser

_REQUIRED_MANIFEST_KEYS = ("pack", "detection", "format", "fields")


class DetectionRule:
    """A single source-detection rule, loaded from a manifest."""

    def __init__(self, rule: Dict[str, Any]):
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

    def _resolve_target(self, envelope: RawEventEnvelope) -> Optional[str]:
        if self.target == "raw_payload":
            return envelope.raw_payload
        if self.target == "source_ip":
            return envelope.source_ip
        if self.target == "content_type_hint":
            return envelope.content_type_hint
        if self.target == "vendor_hint":
            return envelope.vendor_hint
        if self.target == "product_hint":
            return envelope.product_hint
        return None


class FieldRule:
    """One entry from the manifest's `fields:` list — maps a parsed key to an output field."""

    def __init__(self, rule: Dict[str, Any]):
        self.name: str = rule["name"]
        self.source: str = rule["source"]           # dotted path into parsed dict, e.g. "extension.src"
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
        self.manifest: Dict[str, Any] = self._load_manifest(manifest_path)
        self._validate_manifest(self.manifest)

        pack_meta = self.manifest["pack"]
        self.pack_id: str = manifest_path.parent.name
        self.vendor: str = pack_meta["vendor"]
        self.product: str = pack_meta["product"]
        self.pack_version: str = pack_meta["pack_version"]

        self.priority: int = self.manifest["detection"].get("priority", 0)
        self.detection_rules: List[DetectionRule] = [
            DetectionRule(r) for r in self.manifest["detection"].get("rules", [])
        ]

        self.format_type: str = self.manifest["format"]["type"]
        self.format_options: Dict[str, Any] = {
            k: v for k, v in self.manifest["format"].items() if k != "type"
        }

        self.field_rules: List[FieldRule] = [FieldRule(f) for f in self.manifest["fields"]]

    # -- loading / validation ---------------------------------------------

    @staticmethod
    def _load_manifest(manifest_path: Path) -> Dict[str, Any]:
        with open(manifest_path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)

    @staticmethod
    def _validate_manifest(manifest: Dict[str, Any]) -> None:
        missing = [k for k in _REQUIRED_MANIFEST_KEYS if k not in manifest]
        if missing:
            raise SourcePackValidationError(f"Manifest missing required section(s): {missing}")
        for key in ("vendor", "product", "pack_version"):
            if key not in manifest["pack"]:
                raise SourcePackValidationError(f"Manifest 'pack' section missing '{key}'")

    # -- detection ----------------------------------------------------------

    def detect(self, envelope: RawEventEnvelope) -> bool:
        """Returns True if ANY detection rule matches (rules are OR'd)."""
        if not self.detection_rules:
            return False
        return any(rule.matches(envelope) for rule in self.detection_rules)

    # -- parsing --------------------------------------------------------------

    def parse(self, envelope: RawEventEnvelope) -> ParsedEvent:
        parser = get_parser(self.format_type)
        parsed_dict = parser.parse(envelope.raw_payload, **self.format_options)

        errors: List[str] = []
        fields: Dict[str, Any] = {}
        for rule in self.field_rules:
            try:
                value = self._extract(parsed_dict, rule.source)
                if value is None:
                    value = rule.default
                if value is None and rule.required:
                    raise FieldExtractionError(f"Required field '{rule.name}' not found (source={rule.source})")
                fields[rule.name] = value
            except FieldExtractionError as exc:
                errors.append(str(exc))

        status = ParsingStatus.SUCCESS if not errors else ParsingStatus.PARTIAL

        return ParsedEvent(
            event_id=envelope.event_id,
            source_pack_id=self.pack_id,
            vendor=self.vendor,
            product=self.product,
            pack_version=self.pack_version,
            format_detected=self._to_log_format(self.format_type),
            event_timestamp=self._coerce_timestamp(fields.get("timestamp")),
            host=fields.get("hostname") or fields.get("host"),
            severity=self._coerce_severity(fields.get("severity")),
            event_category=fields.get("event_category"),
            message=fields.get("message"),
            fields=fields,
            status=status,
            errors=errors,
            raw_event=envelope,
        )

    # -- helpers --------------------------------------------------------------

    @staticmethod
    def _extract(data: Dict[str, Any], dotted_path: str) -> Any:
        """Resolve a dotted path like 'extension.src' against a nested dict."""
        current: Any = data
        for part in dotted_path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current

    @staticmethod
    def _to_log_format(format_type: str) -> LogFormat:
        try:
            return LogFormat(format_type)
        except ValueError:
            return LogFormat.UNKNOWN

    @staticmethod
    def _coerce_timestamp(value: Any) -> Optional[datetime]:
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%b %d %H:%M:%S"):
                try:
                    return datetime.strptime(value, fmt)
                except ValueError:
                    continue
        return None

    @staticmethod
    def _coerce_severity(value: Any) -> Severity:
        if value is None:
            return Severity.UNKNOWN
        text = str(value).strip().lower()
        try:
            return Severity(text)
        except ValueError:
            pass
        # numeric severities (CEF 0-10, syslog 0-7) — coarse bucket mapping
        try:
            num = float(text)
            if num >= 8:
                return Severity.CRITICAL
            if num >= 6:
                return Severity.HIGH
            if num >= 4:
                return Severity.MEDIUM
            if num >= 1:
                return Severity.LOW
            return Severity.INFO
        except ValueError:
            return Severity.UNKNOWN
