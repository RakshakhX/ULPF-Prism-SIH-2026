"""Small, deterministic helpers shared by perimeter-device mappings."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

SYSLOG_SEVERITY: dict[int, tuple[int, str]] = {
    0: (10, "critical"),
    1: (9, "critical"),
    2: (8, "high"),
    3: (7, "high"),
    4: (5, "medium"),
    5: (4, "medium"),
    6: (2, "low"),
    7: (0, "informational"),
}

FORTINET_SEVERITY: dict[str, tuple[int, str]] = {
    "emergency": (10, "critical"),
    "alert": (9, "critical"),
    "critical": (8, "high"),
    "error": (7, "high"),
    "warning": (5, "medium"),
    "notice": (4, "medium"),
    "information": (2, "low"),
    "debug": (0, "informational"),
}


def valid_ip(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def valid_port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def event_type(value: Any, fallback: str) -> str:
    text = str(value or fallback).strip().lower()
    normalized = re.sub(r"[^a-z0-9]+", "_", text).strip("_")
    if not normalized or not normalized[0].isalpha():
        return fallback
    return normalized


def syslog_severity(value: Any) -> tuple[dict[str, Any], tuple[str, ...]]:
    try:
        code = int(value)
    except (TypeError, ValueError):
        code = -1
    mapped = SYSLOG_SEVERITY.get(code)
    if mapped is None:
        return (
            {"original": str(value or "unknown"), "normalized": 0, "label": "unknown"},
            ("Source severity is missing or unrecognized",),
        )
    score, label = mapped
    return {"original": str(value), "normalized": score, "label": label}, ()


def endpoint(
    fields: dict[str, Any],
    *,
    ip_key: str,
    port_key: str,
    interface_key: str,
) -> dict[str, Any] | None:
    result: dict[str, Any] = {}
    ip = valid_ip(fields.get(ip_key))
    port = valid_port(fields.get(port_key))
    interface = fields.get(interface_key)
    if ip is not None:
        result["ip"] = ip
    if port is not None:
        result["port"] = port
    if isinstance(interface, str) and interface:
        result["interface"] = interface
    return result or None
