"""Source-pack and mapping contracts for Suricata EVE JSON."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.engine import ParsingEngine
from src.contracts import ParseStatus, RawEventEnvelope
from src.normalization import UniversalNormalizer, default_registry
from src.validation.validate_unified_event import validate_event


def _process(payload: dict) -> tuple:
    raw = json.dumps(payload, separators=(",", ":")).encode()
    envelope = RawEventEnvelope.from_bytes(raw, source_id="suricata-sensor", transport="file")
    parsed = ParsingEngine(Path("source_packs")).process(envelope)
    unified = UniversalNormalizer(default_registry()).normalize(parsed)
    return envelope, parsed, unified


@pytest.mark.parametrize(
    ("payload", "category", "normalized_action"),
    [
        (
            {
                "timestamp": "2026-08-30T10:00:00.000001+0000",
                "flow_id": 1001,
                "event_type": "alert",
                "src_ip": "192.0.2.10",
                "src_port": 51000,
                "dest_ip": "198.51.100.20",
                "dest_port": 443,
                "proto": "TCP",
                "app_proto": "tls",
                "alert": {
                    "action": "allowed",
                    "signature_id": 900001,
                    "signature": "ULPF DEMO Suspicious TLS Pattern",
                    "category": "Potentially Bad Traffic",
                    "severity": 2,
                },
            },
            "intrusion_detection",
            "detect",
        ),
        (
            {
                "timestamp": "2026-08-30T10:00:01.000001+0000",
                "flow_id": 1002,
                "event_type": "flow",
                "src_ip": "192.0.2.11",
                "src_port": 51001,
                "dest_ip": "198.51.100.21",
                "dest_port": 80,
                "proto": "TCP",
                "app_proto": "http",
                "flow": {
                    "pkts_toserver": 4,
                    "pkts_toclient": 3,
                    "bytes_toserver": 800,
                    "bytes_toclient": 1200,
                    "state": "closed",
                    "reason": "timeout",
                },
            },
            "network",
            "connect",
        ),
        (
            {
                "timestamp": "2026-08-30T10:00:02.000001+0000",
                "flow_id": 1003,
                "event_type": "dns",
                "src_ip": "192.0.2.12",
                "src_port": 53001,
                "dest_ip": "198.51.100.53",
                "dest_port": 53,
                "proto": "UDP",
                "app_proto": "dns",
                "dns": {"type": "query", "rrname": "service.example", "rrtype": "A"},
            },
            "network",
            "connect",
        ),
        (
            {
                "timestamp": "2026-08-30T10:00:03.000001+0000",
                "flow_id": 1004,
                "event_type": "http",
                "src_ip": "192.0.2.13",
                "src_port": 51003,
                "dest_ip": "198.51.100.23",
                "dest_port": 80,
                "proto": "TCP",
                "app_proto": "http",
                "http": {
                    "hostname": "portal.example",
                    "url": "/status",
                    "http_method": "GET",
                    "status": 200,
                    "http_user_agent": "ULPF-Demo/1.0",
                },
            },
            "web",
            "connect",
        ),
    ],
)
def test_supported_eve_families_normalize_losslessly(
    payload: dict,
    category: str,
    normalized_action: str,
) -> None:
    envelope, parsed, unified = _process(payload)

    assert parsed.source_pack_id == "suricata_eve"
    assert parsed.status is ParseStatus.SUCCESS
    assert parsed.extracted_fields["eve"] == payload
    assert unified["event"]["category"] == category
    assert unified["action"]["normalized"] == normalized_action
    assert unified["traceability"]["raw_sha256"] == envelope.raw_sha256
    assert unified["extensions"]["suricata_eve"]["eve"] == payload
    assert validate_event(unified).valid


def test_alert_maps_signature_and_suricata_severity() -> None:
    payload = {
        "timestamp": "2026-08-30T10:00:04.000001+0000",
        "flow_id": 1005,
        "event_type": "alert",
        "src_ip": "2001:db8::10",
        "dest_ip": "2001:db8::20",
        "proto": "ICMPV6",
        "alert": {
            "action": "blocked",
            "signature_id": 900002,
            "signature": "ULPF DEMO IPv6 Policy Alert",
            "category": "Attempted Information Leak",
            "severity": 1,
        },
    }

    _, _, unified = _process(payload)

    assert unified["threat"] == {
        "name": "ULPF DEMO IPv6 Policy Alert",
        "signature_id": "900002",
        "category": "attempted_information_leak",
        "confidence": 0.9,
    }
    assert unified["severity"] == {"original": "1", "normalized": 8, "label": "high"}
    assert unified["action"]["normalized"] == "block"


def test_unrelated_json_is_not_claimed_by_suricata_pack() -> None:
    envelope = RawEventEnvelope.from_bytes(
        b'{"application":"shop","message":"ordinary JSON"}',
        source_id="other-json",
        transport="file",
    )

    parsed = ParsingEngine(Path("source_packs")).process(envelope)

    assert parsed.source_pack_id != "suricata_eve"
