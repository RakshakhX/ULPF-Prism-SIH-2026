"""
src/pipeline/storage.py

In-memory analytical storage engine supporting fast aggregations,
multi-attribute faceted search, CIDR/free-text filtering, and raw evidence drill-down.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from src.storage.models import WriteResult
from src.validation.validate_unified_event import validate_event


class AnalyticalVisibilityStore:
    """Analytical event store designed for visibility dashboards and fast forensic search."""

    def __init__(self) -> None:
        self._events: list[dict[str, Any]] = []
        self._by_id: dict[str, dict[str, Any]] = {}
        self._by_raw_hash: dict[str, dict[str, Any]] = {}

    def add_event(self, event: dict[str, Any]) -> None:
        """Indexes a normalized UnifiedEvent."""
        event_id = event.get("event", {}).get("id")
        raw_hash = event.get("traceability", {}).get("raw_sha256")

        self._events.append(event)
        if event_id:
            self._by_id[event_id] = event
        if raw_hash:
            self._by_raw_hash[raw_hash] = event

    @property
    def event_count(self) -> int:
        return len(self._events)

    def get_by_id(self, event_id: str) -> dict[str, Any] | None:
        """Lookup by event ID."""
        return self._by_id.get(event_id)

    def get_by_event_id(self, event_id: str) -> dict[str, Any] | None:
        """Shared analytical-store lookup name."""

        return self.get_by_id(event_id)

    def write_batch(self, events: list[dict[str, Any]]) -> WriteResult:
        """Implement the persistent sink contract for tests and local demos."""

        valid_count = 0
        quarantine_count = 0
        for event in events:
            if (
                not validate_event(event).valid
                or event.get("quality", {}).get("status") == "invalid"
            ):
                self.add_event(event)
                quarantine_count += 1
                continue
            self.add_event(event)
            valid_count += 1
        return WriteResult(
            accepted_count=valid_count + quarantine_count,
            valid_count=valid_count,
            quarantine_count=quarantine_count,
            failed_count=0,
        )

    def get_by_raw_hash(self, raw_sha256: str) -> dict[str, Any] | None:
        """Cryptographic lookup by raw SHA-256 hash."""
        return self._by_raw_hash.get(raw_sha256)

    def list_events(self, limit: int = 50) -> list[dict[str, Any]]:
        """Returns recent events in reverse chronological order."""
        return list(reversed(self._events))[:limit]

    def search(
        self,
        query: str | None = None,
        vendor: str | None = None,
        category: str | None = None,
        action: str | None = None,
        severity: str | None = None,
        quality_status: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Search and filter events by attributes and free-text."""
        results = []
        q_lower = query.lower() if query else None

        for event in reversed(self._events):
            # Vendor filter
            ev_vendor = event.get("observer", {}).get("vendor", "").lower()
            if vendor and vendor.lower() != "all" and vendor.lower() != ev_vendor:
                continue

            ev_category = event.get("event", {}).get("category", "").lower()
            if (
                category
                and category.lower() != "all"
                and category.lower() != ev_category
            ):
                continue

            # Action filter
            ev_action = event.get("action", {}).get("normalized", "").lower()
            if action and action.lower() != "all" and action.lower() != ev_action:
                continue

            observed_value = event.get("time", {}).get("observed_at")
            if (start_time is not None or end_time is not None) and isinstance(
                observed_value, str
            ):
                observed_at = datetime.fromisoformat(observed_value.replace("Z", "+00:00"))
                if start_time is not None and observed_at < start_time:
                    continue
                if end_time is not None and observed_at >= end_time:
                    continue

            # Severity filter
            ev_sev = event.get("severity", {}).get("label", "").lower()
            if severity and severity.lower() != "all" and severity.lower() != ev_sev:
                continue

            # Quality status filter
            ev_qual = event.get("quality", {}).get("status", "").lower()
            if (
                quality_status
                and quality_status.lower() != "all"
                and quality_status.lower() != ev_qual
            ):
                continue

            # Free-text search
            if q_lower:
                msg = event.get("event", {}).get("message", "").lower()
                name = event.get("event", {}).get("name", "").lower()
                src_ip = event.get("source", {}).get("ip", "")
                dst_ip = event.get("destination", {}).get("ip", "")
                raw_hash = event.get("traceability", {}).get("raw_sha256", "")

                matched = (
                    q_lower in msg
                    or q_lower in name
                    or q_lower in src_ip
                    or q_lower in dst_ip
                    or q_lower in raw_hash
                    or q_lower in ev_vendor
                )
                if not matched:
                    continue

            results.append(event)
            if len(results) >= limit:
                break

        return results

    def get_aggregations(self) -> dict[str, Any]:
        """Calculates security analytics aggregations across the stored dataset."""
        total = len(self._events)
        sources: dict[str, int] = {}
        actions = {"allow": 0, "deny": 0, "detect": 0, "other": 0}
        severities = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
            "unknown": 0,
        }
        quality_counts = {"valid": 0, "partial": 0, "invalid": 0, "unknown": 0}

        for ev in self._events:
            # Source aggregation
            vendor = ev.get("observer", {}).get("vendor", "unknown")
            product = ev.get("observer", {}).get("product", "unknown")
            key = f"{vendor.capitalize()} {product.upper()}"
            sources[key] = sources.get(key, 0) + 1

            # Action aggregation
            act = ev.get("action", {}).get("normalized", "other")
            if act in {"allow", "connect", "authenticate"}:
                actions["allow"] += 1
            elif act in {"deny", "block"}:
                actions["deny"] += 1
            elif act == "detect":
                actions["detect"] += 1
            else:
                actions["other"] += 1

            # Severity aggregation
            sev_label = ev.get("severity", {}).get("label", "unknown")
            severities[sev_label] = severities.get(sev_label, 0) + 1

            # Quality aggregation
            q_stat = ev.get("quality", {}).get("status", "unknown")
            quality_counts[q_stat] = quality_counts.get(q_stat, 0) + 1

        allow_count = actions["allow"]
        deny_count = actions["deny"]
        total_decisions = allow_count + deny_count
        allow_pct = (allow_count / total_decisions * 100) if total_decisions > 0 else 0.0
        deny_pct = (deny_count / total_decisions * 100) if total_decisions > 0 else 0.0

        return {
            "total_events": total,
            "events_by_source": sources,
            "allow_vs_deny": {
                "allow_count": allow_count,
                "deny_count": deny_count,
                "allow_percent": round(allow_pct, 1),
                "deny_percent": round(deny_pct, 1),
            },
            "severity_distribution": severities,
            "quality_metrics": quality_counts,
        }

    def clear(self) -> None:
        """Clears all stored events."""
        self._events.clear()
        self._by_id.clear()
        self._by_raw_hash.clear()


# Global store instance
global_visibility_store = AnalyticalVisibilityStore()
