"""Fortinet FortiGate to UnifiedEvent mapping."""

from __future__ import annotations

from src.contracts import ParsedEvent
from src.normalization.mappings.common import (
    FORTINET_SEVERITY,
    endpoint,
    event_type,
)
from src.normalization.models import MappingResult

PROTOCOLS = {1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 58: "icmpv6"}


class FortinetFortigateMapping:
    source_pack_id = "fortinet_fortigate"
    version = "1.0.0"

    def map(self, event: ParsedEvent) -> MappingResult:
        fields = event.extracted_fields
        source = endpoint(
            fields,
            ip_key="src_ip",
            port_key="src_port",
            interface_key="src_intf",
        )
        destination = endpoint(
            fields,
            ip_key="dst_ip",
            port_key="dst_port",
            interface_key="dst_intf",
        )
        try:
            transport = PROTOCOLS.get(int(fields.get("protocol")))
        except (TypeError, ValueError):
            transport = None

        missing: list[str] = []
        event_family = str(fields.get("event_type") or "").lower()
        is_network_family = event_family in {"traffic", "utm"}
        if is_network_family:
            if not source or "ip" not in source:
                missing.append("source.ip")
            if not destination or "ip" not in destination:
                missing.append("destination.ip")
            if transport is None:
                missing.append("network.transport")
        is_network = is_network_family and not missing

        original_action = str(fields.get("action") or fields.get("status") or "unknown")
        action_text = original_action.lower()
        is_authentication = (
            action_text == "login" and isinstance(fields.get("user"), str) and bool(fields["user"])
        )
        if is_authentication:
            normalized_action = "authenticate"
            status = str(fields.get("status") or "unknown").lower()
            if status == "failed":
                status = "failure"
            outcome = status if status in {"success", "failure"} else "unknown"
        elif action_text in {"deny", "denied", "block", "blocked"}:
            normalized_action, outcome = "block", "failure"
        elif action_text in {"accept", "allow", "allowed", "pass"}:
            normalized_action, outcome = "allow", "success"
        else:
            normalized_action, outcome = "unknown", "unknown"

        level = str(fields.get("level") or "unknown").lower()
        mapped_severity = FORTINET_SEVERITY.get(level)
        warnings: list[str] = []
        if mapped_severity is None:
            severity = {"original": level, "normalized": 0, "label": "unknown"}
            warnings.append("Source severity is missing or unrecognized")
        else:
            score, label = mapped_severity
            severity = {"original": level, "normalized": score, "label": label}

        hostname = fields.get("hostname")
        observer = {"type": "firewall"}
        if isinstance(hostname, str) and hostname:
            observer["hostname"] = hostname

        subtype = fields.get("event_subtype")
        if is_authentication:
            category = "authentication"
        elif is_network:
            category = "network"
        elif is_network_family:
            category = "unknown"
        else:
            category = "system"

        event_section = {
            "category": category,
            "type": event_type(subtype or fields.get("event_type"), "fortigate_event"),
            "name": "FortiGate security event",
        }
        message = fields.get("message") or fields.get("log_description")
        if isinstance(message, str) and message:
            event_section["message"] = message
        else:
            missing.append("event.message")

        authentication = None
        if is_authentication:
            authentication = {
                "user": fields["user"],
                "result": outcome,
            }

        return MappingResult(
            event=event_section,
            observer=observer,
            action={
                "original": original_action,
                "normalized": normalized_action,
                "outcome": outcome,
            },
            severity=severity,
            source=source,
            destination=destination,
            network={"transport": transport, "direction": "unknown"} if is_network else None,
            authentication=authentication,
            consumed_fields=frozenset(
                {
                    "event_type",
                    "event_subtype",
                    "hostname",
                    "action",
                    "status",
                    "level",
                    "message",
                    "log_description",
                    "src_ip",
                    "src_port",
                    "src_intf",
                    "dst_ip",
                    "dst_port",
                    "dst_intf",
                    "protocol",
                }
            ),
            missing_fields=tuple(missing),
            warnings=tuple(warnings),
        )
