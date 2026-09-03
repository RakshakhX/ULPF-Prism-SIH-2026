"""Suricata EVE JSON to UnifiedEvent mapping."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from src.contracts import ParsedEvent
from src.normalization.mappings.common import endpoint, event_type
from src.normalization.models import MappingResult

SURICATA_SEVERITY = {
    1: (8, "high", 0.9),
    2: (5, "medium", 0.7),
    3: (2, "low", 0.5),
}


def _integer(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


class SuricataEveMapping:
    source_pack_id = "suricata_eve"
    version = "1.0.0"

    def map(self, event: ParsedEvent) -> MappingResult:
        fields = event.extracted_fields
        family = str(fields.get("event_type") or "unknown").lower()
        source = endpoint(
            fields,
            ip_key="src_ip",
            port_key="src_port",
            interface_key="in_iface",
        )
        destination = endpoint(
            fields,
            ip_key="dest_ip",
            port_key="dest_port",
            interface_key="out_iface",
        )
        transport = str(fields.get("proto") or "unknown").lower()
        if transport not in {"tcp", "udp", "icmp", "icmpv6", "gre"}:
            transport = "unknown"
        network = self._network(fields, transport)
        category = {
            "alert": "intrusion_detection",
            "flow": "network",
            "dns": "network",
            "http": "web",
        }.get(family, "unknown")
        if category == "network" and (not source or not destination):
            category = "unknown"

        action = self._action(fields, family)
        severity = self._severity(fields, family)
        threat = self._threat(fields) if family == "alert" else None
        http = self._http(fields) if family == "http" else None
        event_section = {
            "category": category,
            "type": event_type(f"suricata_{family}", "suricata_event"),
            "name": f"Suricata {family} event" if family != "unknown" else "Suricata event",
        }
        message = self._message(fields, family)
        if message:
            event_section["message"] = message

        observer: dict[str, Any] = {"type": "ips"}
        version = fields.get("suricata_version")
        if isinstance(version, str) and version:
            observer["software_version"] = version

        missing: list[str] = []
        if family in {"flow", "dns"}:
            if not source or "ip" not in source:
                missing.append("source.ip")
            if not destination or "ip" not in destination:
                missing.append("destination.ip")
        if not message:
            missing.append("event.message")

        observed_at = None
        timestamp = fields.get("timestamp")
        if isinstance(timestamp, str):
            try:
                observed_at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                pass

        return MappingResult(
            event=event_section,
            observer=observer,
            action=action,
            severity=severity,
            source=source,
            destination=destination,
            network=network,
            threat=threat,
            http=http,
            observed_at=observed_at,
            consumed_fields=frozenset(fields),
            missing_fields=tuple(missing),
        )

    @staticmethod
    def _action(fields: dict[str, Any], family: str) -> dict[str, str]:
        if family == "alert":
            original = str(fields.get("alert", {}).get("action") or "alert")
            if original.lower() == "blocked":
                return {"original": original, "normalized": "block", "outcome": "failure"}
            return {"original": original, "normalized": "detect", "outcome": "success"}
        return {"original": family, "normalized": "connect", "outcome": "success"}

    @staticmethod
    def _severity(fields: dict[str, Any], family: str) -> dict[str, Any]:
        if family != "alert":
            return {"original": "informational", "normalized": 0, "label": "informational"}
        original = fields.get("alert", {}).get("severity")
        mapped = SURICATA_SEVERITY.get(original)
        if mapped is None:
            return {"original": str(original or "unknown"), "normalized": 0, "label": "unknown"}
        score, label, _ = mapped
        return {"original": str(original), "normalized": score, "label": label}

    @staticmethod
    def _threat(fields: dict[str, Any]) -> dict[str, Any]:
        alert = fields.get("alert", {})
        severity = SURICATA_SEVERITY.get(alert.get("severity"), (0, "unknown", 0.3))
        threat: dict[str, Any] = {
            "name": str(alert.get("signature") or "Unknown Suricata alert"),
            "confidence": severity[2],
        }
        signature_id = alert.get("signature_id")
        if signature_id is not None:
            threat["signature_id"] = str(signature_id)
        category = alert.get("category")
        if category:
            threat["category"] = event_type(category, "unknown")
        return threat

    @staticmethod
    def _network(fields: dict[str, Any], transport: str) -> dict[str, Any]:
        network: dict[str, Any] = {
            "transport": transport,
            "application_protocol": str(fields.get("app_proto") or "unknown"),
            "direction": {
                "to_server": "outbound",
                "to_client": "inbound",
            }.get(str(fields.get("direction")), "unknown"),
        }
        flow = fields.get("flow")
        if isinstance(flow, dict):
            packets = [_integer(flow.get("pkts_toserver")), _integer(flow.get("pkts_toclient"))]
            byte_counts = [
                _integer(flow.get("bytes_toserver")),
                _integer(flow.get("bytes_toclient")),
            ]
            if all(value is not None for value in packets):
                network["packets"] = sum(packets)  # type: ignore[arg-type]
            if all(value is not None for value in byte_counts):
                network["bytes"] = sum(byte_counts)  # type: ignore[arg-type]
        return network

    @staticmethod
    def _http(fields: dict[str, Any]) -> dict[str, Any] | None:
        source = fields.get("http")
        if not isinstance(source, dict):
            return None
        result: dict[str, Any] = {}
        method = source.get("http_method")
        if isinstance(method, str) and method.isalpha():
            result["method"] = method.upper()
        host = source.get("hostname")
        if isinstance(host, str) and host:
            result["host"] = host
        path = source.get("url")
        if isinstance(path, str) and path.startswith("/"):
            result["path"] = path
        status = source.get("status")
        if isinstance(status, int) and not isinstance(status, bool) and 100 <= status <= 599:
            result["status_code"] = status
        agent = source.get("http_user_agent")
        if isinstance(agent, str):
            result["user_agent"] = agent
        return result or None

    @staticmethod
    def _message(fields: dict[str, Any], family: str) -> str | None:
        body = fields.get(family)
        if not isinstance(body, dict):
            return None
        if family == "alert":
            return body.get("signature")
        if family == "dns":
            rrname = body.get("rrname")
            return f"DNS {body.get('type', 'transaction')}: {rrname}" if rrname else "DNS event"
        if family == "http":
            return f"HTTP {body.get('http_method', 'request')} {body.get('url', '/')}"
        if family == "flow":
            return f"Flow {body.get('state', 'unknown')}: {body.get('reason', 'unspecified')}"
        return None
