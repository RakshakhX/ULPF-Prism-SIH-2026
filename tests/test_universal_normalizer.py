from datetime import UTC, datetime

import pytest

from src.contracts import ParsedEvent, ParseStatus, RawEventEnvelope
from src.normalization import UniversalNormalizer, default_registry
from src.validation.validate_unified_event import validate_event


def parsed_event_for(pack_id: str, fields: dict, *, status=ParseStatus.SUCCESS) -> ParsedEvent:
    raw = RawEventEnvelope.from_bytes(
        f"sample event from {pack_id}".encode(),
        source_id=f"{pack_id}-fixture",
        transport="file",
    )
    vendor_product = {
        "cisco_asa": ("Cisco", "ASA", "syslog"),
        "fortinet_fortigate": ("Fortinet", "FortiGate", "key_value"),
        "generic_linux_syslog": ("Generic", "Linux Syslog", "syslog"),
    }
    vendor, product, detected_format = vendor_product[pack_id]
    return ParsedEvent(
        event_id=raw.event_id,
        parsed_at=datetime.now(UTC),
        vendor=vendor,
        product=product,
        product_version=None,
        parser_id=f"{pack_id}.parser",
        parser_version="1.2.0",
        source_pack_id=pack_id,
        source_pack_version="2.0.0",
        detected_format=detected_format,
        status=status,
        extracted_fields=fields,
        raw_event=raw,
    )


@pytest.mark.parametrize(
    ("pack_id", "fields"),
    [
        (
            "cisco_asa",
            {
                "event_type": "acl_deny",
                "message_text": "Denied by OUTSIDE_IN",
                "hostname": "asa-edge",
                "action": "Deny",
                "severity": 4,
                "src_ip": "203.0.113.5",
                "src_port": "54321",
                "dst_ip": "10.0.0.5",
                "dst_port": "443",
                "protocol": "tcp",
                "custom_vendor_field": "preserve-me",
            },
        ),
        (
            "fortinet_fortigate",
            {
                "event_type": "traffic",
                "event_subtype": "forward",
                "hostname": "FGT-EDGE-01",
                "action": "accept",
                "level": "notice",
                "src_ip": "10.0.0.10",
                "src_port": "5000",
                "dst_ip": "198.51.100.10",
                "dst_port": "443",
                "protocol": "6",
                "custom_vendor_field": "preserve-me",
            },
        ),
        (
            "generic_linux_syslog",
            {
                "hostname": "server-1",
                "process": "sshd",
                "message": "Failed password for alice",
                "severity": "4",
                "custom_vendor_field": "preserve-me",
            },
        ),
    ],
)
def test_normalizer_preserves_extensions_traceability_and_schema(
    pack_id: str,
    fields: dict,
) -> None:
    parsed = parsed_event_for(pack_id, fields)

    unified = UniversalNormalizer(default_registry()).normalize(parsed)

    assert unified["traceability"]["raw_event_id"] == str(parsed.raw_event.event_id)
    assert unified["traceability"]["raw_sha256"] == parsed.raw_event.raw_sha256
    assert unified["traceability"]["source_pack"] == {
        "name": pack_id,
        "version": "2.0.0",
    }
    assert unified["traceability"]["parser"] == {
        "name": f"{pack_id}.parser",
        "version": "1.2.0",
    }
    assert unified["extensions"][pack_id]["custom_vendor_field"] == "preserve-me"
    assert unified["extensions"]["ulpf"]["mapping"]["version"] == "1.0.0"
    assert unified["extensions"]["ulpf"]["normalizer"]["version"] == "1.0.0"
    assert validate_event(unified).valid


def test_missing_ip_is_reported_and_never_replaced_with_documentation_ip() -> None:
    parsed = parsed_event_for(
        "cisco_asa",
        {
            "event_type": "acl_deny",
            "action": "Deny",
            "severity": 4,
            "dst_ip": "10.0.0.5",
            "protocol": "tcp",
        },
        status=ParseStatus.PARTIAL,
    )

    unified = UniversalNormalizer(default_registry()).normalize(parsed)

    assert "ip" not in unified.get("source", {})
    assert "source.ip" in unified["quality"]["missing_fields"]
    assert unified["event"]["category"] == "unknown"
    assert validate_event(unified).valid


def test_registry_rejects_duplicate_mapping() -> None:
    registry = default_registry()
    mapping = registry.get("cisco_asa")
    assert mapping is not None

    with pytest.raises(ValueError, match="already registered"):
        registry.register(mapping)
