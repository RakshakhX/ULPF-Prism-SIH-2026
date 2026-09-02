from datetime import UTC, datetime
from pathlib import Path

import pytest

from core.cisco_asa_pack import CiscoASASourcePack
from core.engine import ParsingEngine
from src.contracts import ParsedEvent, ParseStatus, RawEventEnvelope
from src.normalization import UniversalNormalizer, default_registry
from src.pipeline.normalizer import normalize_cisco_asa_event
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


def test_invalid_mapped_values_remain_in_lossless_extension() -> None:
    parsed = parsed_event_for(
        "cisco_asa",
        {
            "event_type": "acl_deny",
            "src_ip": "not-an-ip",
            "src_port": "99999",
            "dst_ip": "10.0.0.5",
            "protocol": "made-up-protocol",
        },
    )

    unified = UniversalNormalizer(default_registry()).normalize(parsed)

    extension = unified["extensions"]["cisco_asa"]
    assert extension["src_ip"] == "not-an-ip"
    assert extension["src_port"] == "99999"
    assert extension["protocol"] == "made-up-protocol"
    assert validate_event(unified).valid


@pytest.mark.parametrize(
    ("fields", "category"),
    [
        (
            {
                "event_type": "event",
                "event_subtype": "system",
                "action": "reboot",
                "level": "notice",
                "log_description": "System reboot",
            },
            "system",
        ),
        (
            {
                "event_type": "event",
                "event_subtype": "system",
                "action": "login",
                "status": "success",
                "user": "admin",
                "level": "notice",
                "message": "Administrator logged in",
            },
            "authentication",
        ),
    ],
)
def test_fortinet_non_network_families_have_relevant_requirements_only(
    fields: dict,
    category: str,
) -> None:
    parsed = parsed_event_for("fortinet_fortigate", fields)

    unified = UniversalNormalizer(default_registry()).normalize(parsed)

    assert unified["event"]["category"] == category
    assert "source.ip" not in unified["quality"]["missing_fields"]
    assert "destination.ip" not in unified["quality"]["missing_fields"]
    assert "network.transport" not in unified["quality"]["missing_fields"]
    assert validate_event(unified).valid


def test_fortinet_failed_login_normalizes_failed_to_failure() -> None:
    parsed = parsed_event_for(
        "fortinet_fortigate",
        {
            "event_type": "event",
            "event_subtype": "system",
            "action": "login",
            "status": "failed",
            "user": "admin",
            "level": "warning",
            "message": "Administrator login failed",
        },
    )

    unified = UniversalNormalizer(default_registry()).normalize(parsed)

    assert unified["action"]["outcome"] == "failure"
    assert unified["authentication"]["result"] == "failure"
    assert validate_event(unified).valid


@pytest.mark.parametrize("pack_id", ["cisco_asa", "fortinet_fortigate", "generic_linux_syslog"])
def test_absent_optional_message_is_omitted_not_fabricated(pack_id: str) -> None:
    base_fields = {
        "cisco_asa": {"severity": 4},
        "fortinet_fortigate": {"event_type": "event", "level": "notice"},
        "generic_linux_syslog": {"severity": 4},
    }
    parsed = parsed_event_for(pack_id, base_fields[pack_id])

    unified = UniversalNormalizer(default_registry()).normalize(parsed)

    assert "message" not in unified["event"]
    assert "event.message" in unified["quality"]["missing_fields"]
    assert validate_event(unified).valid


def test_unknown_pack_is_preserved_and_schema_valid() -> None:
    raw = RawEventEnvelope.from_bytes(b"future vendor", source_id="future", transport="file")
    parsed = ParsedEvent(
        event_id=raw.event_id,
        parsed_at=datetime.now(UTC),
        vendor="Future Vendor",
        product="Future Box",
        product_version=None,
        parser_id="future.parser",
        parser_version="1.0.0",
        source_pack_id="future_vendor",
        source_pack_version="1.0.0",
        detected_format="future",
        status=ParseStatus.SUCCESS,
        extracted_fields={"future_field": "still-here"},
        raw_event=raw,
    )

    unified = UniversalNormalizer(default_registry()).normalize(parsed)

    assert unified["extensions"]["future_vendor"]["future_field"] == "still-here"
    assert unified["quality"]["status"] == "partial"
    assert validate_event(unified).valid


@pytest.mark.parametrize(
    ("payload", "pack_id", "category"),
    [
        (
            b"<166>Oct 12 2023 14:23:01 asa-fw1 : %ASA-4-106023: "
            b"Deny tcp src outside:203.0.113.5/54321 dst inside:10.0.0.5/443 "
            b'by access-group "OUTSIDE_IN"',
            "cisco_asa",
            "network",
        ),
        (
            b'date=2026-08-30 time=08:15:22 devname="FGT-EDGE-01" '
            b'devid="FG100" logid="0100032001" type="event" subtype="system" '
            b'level="notice" action="login" status="success" user="admin" '
            b'srcip=192.168.1.5 msg="Administrator logged in"',
            "fortinet_fortigate",
            "authentication",
        ),
        (
            b"<34>Oct 11 22:14:15 server-1 sshd[42]: Failed password for alice",
            "generic_linux_syslog",
            "system",
        ),
    ],
)
def test_real_parser_output_normalizes_across_required_packs(
    payload: bytes,
    pack_id: str,
    category: str,
) -> None:
    raw = RawEventEnvelope.from_bytes(payload, source_id="integration", transport="file")
    parsed = ParsingEngine(Path("source_packs")).process(raw)

    unified = UniversalNormalizer(default_registry()).normalize(parsed)

    assert parsed.source_pack_id == pack_id
    assert unified["event"]["category"] == category
    assert unified["traceability"]["raw_sha256"] == raw.raw_sha256
    assert validate_event(unified).valid


def test_legacy_cisco_adapter_preserves_valid_uuid_and_known_parser_identity() -> None:
    raw = (
        b"<166>Oct 12 2023 14:23:01 asa-fw1 : %ASA-4-106023: "
        b"Deny tcp src outside:203.0.113.5/54321 dst inside:10.0.0.5/443 "
        b'by access-group "OUTSIDE_IN"'
    )
    parsed = CiscoASASourcePack().parse(raw)

    unified = normalize_cisco_asa_event(parsed)

    assert unified["event"]["id"] == parsed.event_id
    assert unified["traceability"]["raw_event_id"] == parsed.event_id
    assert unified["traceability"]["parser"]["name"] == "cisco.asa.syslog"
    assert validate_event(unified).valid
