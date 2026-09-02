"""
tests/test_engine.py

Core engine tests: routing to the sample Source Pack, and fallback behavior
for unrecognized/malformed payloads. Run with: pytest tests/
"""

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from core.engine import ParsingEngine  # noqa: E402
from core.parsers.cef_parser import CEFFormatParser  # noqa: E402
from core.parsers.csv_parser import CSVFormatParser  # noqa: E402
from core.parsers.json_parser import JSONFormatParser  # noqa: E402
from core.parsers.kv_parser import KeyValueParser  # noqa: E402
from core.parsers.regex_parser import RegexFormatParser  # noqa: E402
from src.contracts import ParsedEvent, ParseStatus, RawEventEnvelope  # noqa: E402

PACKS_DIR = PROJECT_ROOT / "source_packs"


def _engine() -> ParsingEngine:
    return ParsingEngine(packs_dir=PACKS_DIR)


def test_engine_loads_packs():
    engine = _engine()
    pack_ids = [p.pack_id for p in engine.registry.packs]
    assert "cisco_asa" in pack_ids
    assert "generic_linux_syslog" in pack_ids


def test_engine_routes_syslog_to_generic_pack():
    engine = _engine()
    envelope = RawEventEnvelope.from_bytes(
        b"<34>Oct 11 22:14:15 mymachine sshd[1234]: Failed password for invalid user admin",
        source_id="linux-1",
        transport="udp",
    )
    result = engine.process(envelope)
    assert result.status is ParseStatus.SUCCESS
    assert result.source_pack_id == "generic_linux_syslog"
    assert result.extracted_fields["hostname"] == "mymachine"


@pytest.mark.parametrize(
    ("payload", "expected_pack"),
    [
        (
            b"<166>Oct 12 2023 14:23:01 asa-fw1 : %ASA-4-106023: "
            b"Deny tcp src outside:203.0.113.5/54321 dst inside:10.0.0.5/443 "
            b'by access-group "OUTSIDE_IN"',
            "cisco_asa",
        ),
        (
            b'date=2026-08-30 time=14:20:00 devname="FGT-EDGE-01" '
            b'devid="FG100" logid="0000000013" type="traffic" '
            b'subtype="forward" level="notice" srcip=10.0.0.1 dstip=10.0.0.2',
            "fortinet_fortigate",
        ),
        (
            b"<34>Oct 11 22:14:15 mymachine sshd[1234]: Failed password",
            "generic_linux_syslog",
        ),
    ],
)
def test_engine_routes_every_required_pack_with_canonical_identity(
    payload: bytes,
    expected_pack: str,
) -> None:
    envelope = RawEventEnvelope.from_bytes(
        payload,
        source_id="routing-test",
        transport="file",
    )

    result = _engine().process(envelope)

    assert result.source_pack_id == expected_pack
    assert result.event_id == envelope.event_id
    assert result.raw_event == envelope
    assert result.raw_event.raw_bytes() == payload


def test_engine_falls_back_on_unrecognized_payload():
    engine = _engine()
    envelope = RawEventEnvelope.from_bytes(
        b"this is just a plain unstructured line of text\xff",
        source_id="unknown-1",
        transport="file",
    )
    result = engine.process(envelope)
    assert result.status is ParseStatus.UNRECOGNIZED
    assert result.raw_event.raw_bytes() == envelope.raw_bytes()
    assert result.raw_event.raw_sha256 == envelope.raw_sha256


def test_engine_never_raises_on_garbage_input():
    engine = _engine()
    garbage_payloads = [b"", b"{{{{not json", b"<not-a-valid-pri>garbled", b"\x00\xffbinary\x02"]
    for payload in garbage_payloads:
        envelope = RawEventEnvelope.from_bytes(
            payload,
            source_id="garbage",
            transport="file",
        )
        result = engine.process(envelope)  # must not raise
        assert result is not None
        assert result.event_id == envelope.event_id


def test_engine_rejects_parse_output_for_a_different_envelope(tmp_path: Path) -> None:
    original = RawEventEnvelope.from_bytes(
        b"original",
        source_id="identity-test",
        transport="file",
    )
    different = RawEventEnvelope.from_bytes(
        b"different",
        source_id="identity-test",
        transport="file",
    )

    class WrongIdentityPack:
        pack_id = "wrong_identity"
        priority = 10
        vendor = "Example"
        product = "Broken Parser"
        pack_version = "2.1.0"
        format_type = "syslog"
        parser_id = "example.broken"
        parser_version = "2.1.0"

        def detect(self, envelope):
            return True

        def parse(self, envelope):
            return ParsedEvent.unrecognized(different, "wrong raw event")

    engine = ParsingEngine(packs_dir=tmp_path)
    engine.registry._packs = [WrongIdentityPack()]

    result = engine.process(original)

    assert result.status is ParseStatus.FAILED
    assert result.raw_event == original
    assert result.vendor == "Example"
    assert result.product == "Broken Parser"
    assert result.source_pack_id == "wrong_identity"
    assert result.source_pack_version == "2.1.0"
    assert result.parser_id == "example.broken"
    assert result.parser_version == "2.1.0"
    assert result.detected_format == "syslog"


def test_registry_rejects_invalid_detection_confidence(tmp_path: Path) -> None:
    class NegativeDetectionPack:
        pack_id = "negative"
        priority = 10

        def detect(self, envelope):
            return -0.5

    engine = ParsingEngine(packs_dir=tmp_path)
    engine.registry._packs = [NegativeDetectionPack()]
    envelope = RawEventEnvelope.from_bytes(
        b"anything",
        source_id="detect-test",
        transport="file",
    )

    assert engine.registry.match(envelope) is None


# ---- Individual format parser sanity checks --------------------------------


def test_json_parser():
    parser = JSONFormatParser()
    data = parser.parse('{"user": "alice", "action": "login"}')
    assert data["user"] == "alice"


def test_json_parser_strips_non_json_prefix():
    parser = JSONFormatParser()
    data = parser.parse('<134>Oct 11 firewall: {"src": "10.0.0.1", "dst": "10.0.0.2"}')
    assert data["src"] == "10.0.0.1"


def test_kv_parser():
    parser = KeyValueParser()
    data = parser.parse('src=10.1.1.1 dst=10.2.2.2 action="allow" msg="TCP connection established"')
    assert data["src"] == "10.1.1.1"
    assert data["action"] == "allow"
    assert data["msg"] == "TCP connection established"


def test_csv_parser_with_columns():
    parser = CSVFormatParser()
    data = parser.parse(
        "2026-08-31,alice,login,success", columns=["date", "user", "action", "result"]
    )
    assert data["user"] == "alice"
    assert data["result"] == "success"


def test_csv_parser_without_columns():
    parser = CSVFormatParser()
    data = parser.parse("a,b,c")
    assert data == {"col_0": "a", "col_1": "b", "col_2": "c"}


def test_cef_parser():
    parser = CEFFormatParser()
    data = parser.parse(
        "CEF:0|Palo Alto Networks|PAN-OS|10.1|threat|Suspicious DNS Query|5|"
        "src=10.0.0.1 dst=8.8.8.8 act=allowed"
    )
    assert data["device_vendor"] == "Palo Alto Networks"
    assert data["severity"] == "5"
    assert data["extension"]["src"] == "10.0.0.1"


def test_regex_parser():
    parser = RegexFormatParser()
    data = parser.parse(
        "USER=jsmith ACTION=DELETE_RECORD TABLE=customers ROWID=88231",
        patterns=[
            r"USER=(?P<user>\w+)\s+ACTION=(?P<action>\w+)\s+TABLE=(?P<table>\w+)\s+ROWID=(?P<row_id>\d+)"
        ],
    )
    assert data["user"] == "jsmith"
    assert data["row_id"] == "88231"


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS: {name}")
    print("All engine tests passed.")
