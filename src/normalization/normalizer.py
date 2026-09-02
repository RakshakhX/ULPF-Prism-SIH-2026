"""Common, lossless assembly of schema-valid UnifiedEvent records."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from src.contracts import ParsedEvent, ParseStatus
from src.normalization.models import MappingResult
from src.normalization.registry import NormalizationRegistry
from src.validation.validate_unified_event import validate_event

NORMALIZER_VERSION = "1.0.0"
_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_NAMESPACE = re.compile(r"[^a-z0-9]+")


def _utc_z(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _safe_version(value: str | None) -> str:
    return value if isinstance(value, str) and _SEMVER.fullmatch(value) else "0.0.0"


def _namespace(value: str | None) -> str:
    normalized = _NAMESPACE.sub("_", (value or "unknown_source").lower()).strip("_")
    if not normalized or not normalized[0].isalpha():
        return "unknown_source"
    return normalized


def _json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return _utc_z(value)
    if isinstance(value, bytes):
        return {"encoding": "base64", "value": __import__("base64").b64encode(value).decode()}
    if isinstance(value, dict):
        return {str(key): _json_value(child) for key, child in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_value(child) for child in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


class UniversalNormalizer:
    """Normalize canonical parsed events without inventing missing source data."""

    def __init__(self, registry: NormalizationRegistry) -> None:
        self.registry = registry

    def normalize(self, parsed: ParsedEvent) -> dict[str, Any]:
        mapping = self.registry.get(parsed.source_pack_id)
        mapped = mapping.map(parsed) if mapping is not None else self._unknown_mapping(parsed)

        missing = list(mapped.missing_fields)
        warnings = list(mapped.warnings)
        warnings.extend(issue.message for issue in parsed.issues)

        vendor = parsed.vendor or "unknown"
        product = parsed.product or "unknown"
        if parsed.vendor is None:
            missing.append("observer.vendor")
            warnings.append("Source vendor was not identified")
        if parsed.product is None:
            missing.append("observer.product")
            warnings.append("Source product was not identified")

        source_pack_version = _safe_version(parsed.source_pack_version)
        parser_version = _safe_version(parsed.parser_version)
        if source_pack_version == "0.0.0" and parsed.source_pack_version != "0.0.0":
            warnings.append("Source Pack version was missing or invalid")
        if parser_version == "0.0.0" and parsed.parser_version != "0.0.0":
            warnings.append("Parser version was missing or invalid")

        normalized_at = max(datetime.now(UTC), parsed.parsed_at, parsed.raw_event.ingested_at)
        observed_at = mapped.observed_at or parsed.raw_event.ingested_at
        if observed_at > parsed.raw_event.ingested_at:
            observed_at = parsed.raw_event.ingested_at
            warnings.append("Source timestamp was later than ingestion time and was not trusted")

        event_meta = {
            "id": str(parsed.event_id),
            "kind": "event",
            **mapped.event,
        }
        observer = {"vendor": vendor, "product": product, **mapped.observer}
        pack_namespace = _namespace(parsed.source_pack_id)
        unmapped = {
            key: _json_value(value)
            for key, value in parsed.extracted_fields.items()
            if key not in mapped.consumed_fields
        }
        mapping_name = mapping.source_pack_id if mapping is not None else "unknown"
        mapping_version = mapping.version if mapping is not None else "0.0.0"

        quality_status = self._quality_status(parsed.status, missing, warnings)
        unified: dict[str, Any] = {
            "schema_version": "1.0.0",
            "event": event_meta,
            "time": {
                "observed_at": _utc_z(observed_at),
                "ingested_at": _utc_z(parsed.raw_event.ingested_at),
                "normalized_at": _utc_z(normalized_at),
            },
            "observer": observer,
            "action": mapped.action,
            "severity": mapped.severity,
            "traceability": {
                "raw_event_id": str(parsed.raw_event.event_id),
                "raw_sha256": parsed.raw_event.raw_sha256,
                "source_pack": {
                    "name": parsed.source_pack_id or "unknown_source_pack",
                    "version": source_pack_version,
                },
                "parser": {"name": parsed.parser_id, "version": parser_version},
            },
            "quality": {
                "status": quality_status,
                "parsing_confidence": self._confidence(parsed.status, missing, warnings),
                "missing_fields": sorted(set(missing)),
                "warnings": list(dict.fromkeys(warnings)),
            },
            "extensions": {
                pack_namespace: unmapped,
                "ulpf": {
                    "mapping": {"name": mapping_name, "version": mapping_version},
                    "normalizer": {"name": "universal_normalizer", "version": NORMALIZER_VERSION},
                },
            },
        }
        for section in (
            "source",
            "destination",
            "network",
            "threat",
            "authentication",
            "http",
        ):
            value = getattr(mapped, section)
            if value:
                unified[section] = value

        validation = validate_event(unified)
        if not validation.valid:
            unified["quality"]["status"] = "invalid"
            unified["quality"]["warnings"].extend(
                f"{issue.path}: {issue.message}" for issue in validation.issues
            )
        return unified

    @staticmethod
    def _quality_status(
        status: ParseStatus,
        missing: list[str],
        warnings: list[str],
    ) -> str:
        if status is ParseStatus.FAILED:
            return "invalid"
        if status is ParseStatus.UNRECOGNIZED:
            return "unknown"
        if status is ParseStatus.PARTIAL or missing or warnings:
            return "partial"
        return "valid"

    @staticmethod
    def _confidence(
        status: ParseStatus,
        missing: list[str],
        warnings: list[str],
    ) -> float:
        if status in {ParseStatus.FAILED, ParseStatus.UNRECOGNIZED}:
            return 0.0
        if status is ParseStatus.PARTIAL or missing or warnings:
            return 0.5
        return 1.0

    @staticmethod
    def _unknown_mapping(parsed: ParsedEvent) -> MappingResult:
        return MappingResult(
            event={
                "category": "unknown",
                "type": "unmapped_event",
                "name": "Unmapped source event",
            },
            observer={"type": "unknown"},
            action={"original": "unknown", "normalized": "unknown", "outcome": "unknown"},
            severity={"original": "unknown", "normalized": 0, "label": "unknown"},
            missing_fields=("normalization.mapping",),
            warnings=("No normalization mapping is registered for this Source Pack",),
        )
