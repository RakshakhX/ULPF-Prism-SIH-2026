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
    """Return deterministic cross-field validation issues without mutating *event*."""
    issues: list[ValidationIssue] = []

    time = event.get("time", {})
    if isinstance(time, Mapping):
        observed = _parse_utc(time.get("observed_at"))
        ingested = _parse_utc(time.get("ingested_at"))
        normalized = _parse_utc(time.get("normalized_at"))
        if all(value is not None for value in (observed, ingested, normalized)):
            if not observed <= ingested <= normalized:
                issues.append(
                    _issue(
                        "$.time",
                        "timestamp_order",
                        "must satisfy observed_at <= ingested_at <= normalized_at",
                    )
                )

    event_meta = event.get("event", {})
    category = event_meta.get("category") if isinstance(event_meta, Mapping) else None
    if category == "network":
        for endpoint_name in ("source", "destination"):
            endpoint = event.get(endpoint_name)
            if not isinstance(endpoint, Mapping) or not endpoint.get("ip"):
                issues.append(
                    _issue(
                        f"$.{endpoint_name}.ip",
                        "network_endpoint",
                        "network events require an IP address",
                    )
                )
    if category == "intrusion_detection" and not isinstance(event.get("threat"), Mapping):
        issues.append(
            _issue(
                "$.threat",
                "category_requirement",
                "intrusion_detection events require threat details",
            )
        )
    if category == "authentication" and not isinstance(
        event.get("authentication"), Mapping
    ):
        issues.append(
            _issue(
                "$.authentication",
                "category_requirement",
                "authentication events require authentication details",
            )
        )

    action = event.get("action", {})
    if isinstance(action, Mapping):
        normalized_action = action.get("normalized")
        action_outcome = action.get("outcome")
        if (
            isinstance(normalized_action, str)
            and normalized_action in {"deny", "block"}
            and action_outcome == "success"
        ):
            issues.append(
                _issue(
                    "$.action.outcome",
                    "action_consistency",
                    "deny and block actions cannot have success outcome",
                )
            )

    severity = event.get("severity", {})
    if isinstance(severity, Mapping):
        normalized_severity = severity.get("normalized")
        severity_label = severity.get("label")
        if (
            type(normalized_severity) is int
            and 0 <= normalized_severity <= 10
            and severity_label != "unknown"
        ):
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
                issues.append(
                    _issue(
                        "$.severity.label",
                        "severity_consistency",
                        (
                            f"normalized severity {normalized_severity} requires label "
                            f"{expected_label}"
                        ),
                    )
                )
        if severity_label == "unknown":
            quality_for_severity = event.get("quality", {})
            warnings = (
                quality_for_severity.get("warnings", [])
                if isinstance(quality_for_severity, Mapping)
                else []
            )
            if not warnings:
                issues.append(
                    _issue(
                        "$.severity.label",
                        "severity_uncertainty",
                        "unknown severity requires a quality warning",
                    )
                )

    authentication = event.get("authentication")
    if isinstance(authentication, Mapping) and isinstance(action, Mapping):
        auth_result = authentication.get("result")
        outcome = action.get("outcome")
        if (
            isinstance(auth_result, str)
            and auth_result in {"success", "failure"}
            and isinstance(outcome, str)
            and outcome in {"success", "failure"}
            and auth_result != outcome
        ):
            issues.append(
                _issue(
                    "$.authentication.result",
                    "outcome_consistency",
                    "authentication result must match action outcome",
                )
            )

    quality = event.get("quality", {})
    if isinstance(quality, Mapping) and quality.get("status") == "partial":
        if not quality.get("missing_fields") and not quality.get("warnings"):
            issues.append(
                _issue(
                    "$.quality",
                    "partial_explanation",
                    "partial quality requires missing_fields or warnings",
                )
            )

    extensions = event.get("extensions", {})
    if isinstance(extensions, Mapping):
        for namespace in extensions:
            if not isinstance(namespace, str) or not VENDOR_NAMESPACE.fullmatch(namespace):
                issues.append(
                    _issue(
                        f"$.extensions.{namespace}",
                        "vendor_namespace",
                        "extension namespace must be lowercase snake_case",
                    )
                )

    traceability = event.get("traceability", {})
    if isinstance(traceability, Mapping) and isinstance(
        traceability.get("raw_event"), Mapping
    ):
        raw_event = traceability["raw_event"]
        content = raw_event.get("content")
        if isinstance(content, str):
            actual_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
            if actual_hash != traceability.get("raw_sha256"):
                issues.append(
                    _issue(
                        "$.traceability.raw_sha256",
                        "raw_integrity",
                        "does not match embedded raw_event content",
                    )
                )

    return tuple(sorted(set(issues)))
