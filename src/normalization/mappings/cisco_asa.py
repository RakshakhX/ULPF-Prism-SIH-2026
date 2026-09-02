"""Cisco ASA to UnifiedEvent mapping."""

from __future__ import annotations

from src.contracts import ParsedEvent
from src.normalization.mappings.common import endpoint, event_type, syslog_severity
from src.normalization.models import MappingResult


class CiscoASAMapping:
    source_pack_id = "cisco_asa"
    version = "1.0.0"

    def map(self, event: ParsedEvent) -> MappingResult:
        fields = event.extracted_fields
        source = endpoint(
            fields,
            ip_key="src_ip",
            port_key="src_port",
            interface_key="src_interface",
        )
        destination = endpoint(
            fields,
            ip_key="dst_ip",
            port_key="dst_port",
            interface_key="dst_interface",
        )
        protocol = str(fields.get("protocol") or "").lower()
        allowed_protocols = {"tcp", "udp", "icmp", "icmpv6", "gre"}
        transport = protocol if protocol in allowed_protocols else None

        missing: list[str] = []
        if not source or "ip" not in source:
            missing.append("source.ip")
        if not destination or "ip" not in destination:
            missing.append("destination.ip")
        if transport is None:
            missing.append("network.transport")

        is_network = not missing
        action_original = str(fields.get("action") or "unknown")
        action_text = action_original.lower()
        if "deny" in action_text:
            normalized_action, outcome = "deny", "failure"
        elif "built" in action_text or "permit" in action_text or "allow" in action_text:
            normalized_action, outcome = "allow", "success"
        elif "teardown" in action_text:
            normalized_action, outcome = "disconnect", "success"
        else:
            normalized_action, outcome = "unknown", "unknown"

        severity, severity_warnings = syslog_severity(fields.get("severity"))
        hostname = fields.get("hostname")
        observer = {"type": "firewall"}
        if isinstance(hostname, str) and hostname:
            observer["hostname"] = hostname

        event_section = {
            "category": "network" if is_network else "unknown",
            "type": event_type(fields.get("event_type"), "firewall_event"),
            "name": "Cisco ASA firewall event",
        }
        message = fields.get("message_text")
        if isinstance(message, str) and message:
            event_section["message"] = message
        else:
            missing.append("event.message")

        return MappingResult(
            event=event_section,
            observer=observer,
            action={
                "original": action_original,
                "normalized": normalized_action,
                "outcome": outcome,
            },
            severity=severity,
            source=source,
            destination=destination,
            network={"transport": transport, "direction": "unknown"} if is_network else None,
            consumed_fields=frozenset(
                {
                    "event_type",
                    "message_text",
                    "hostname",
                    "action",
                    "severity",
                    "src_ip",
                    "src_port",
                    "src_interface",
                    "dst_ip",
                    "dst_port",
                    "dst_interface",
                    "protocol",
                }
            ),
            missing_fields=tuple(missing),
            warnings=severity_warnings,
        )
