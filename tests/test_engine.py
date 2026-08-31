"""
tests/test_engine.py

Core engine tests: routing to the sample Source Pack, and fallback behavior
for unrecognized/malformed payloads. Run with: pytest tests/
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from core.engine import ParsingEngine  # noqa: E402
from core.models import ParsingStatus, RawEventEnvelope  # noqa: E402
from core.parsers.cef_parser import CEFFormatParser  # noqa: E402
from core.parsers.csv_parser import CSVFormatParser  # noqa: E402
from core.parsers.json_parser import JSONFormatParser  # noqa: E402
from core.parsers.kv_parser import KeyValueParser  # noqa: E402
from core.parsers.regex_parser import RegexFormatParser  # noqa: E402

PACKS_DIR = PROJECT_ROOT / "source_packs"


def _engine() -> ParsingEngine:
    return ParsingEngine(packs_dir=PACKS_DIR)


def test_engine_loads_packs():
    engine = _engine()
    pack_ids = [p.pack_id for p in engine.registry.packs]
    assert "generic_linux_syslog" in pack_ids


def test_engine_routes_syslog_to_generic_pack():
    engine = _engine()
    envelope = RawEventEnvelope(
    raw_payload=(
        "<34>Oct 11 22:14:15 mymachine sshd[1234]: "
        "Failed password for invalid user admin"
    )
)
    result = engine.process(envelope)
    assert result.status == ParsingStatus.SUCCESS
    assert result.source_pack_id == "generic_linux_syslog"
    assert result.fields["hostname"] == "mymachine"


def test_engine_falls_back_on_unrecognized_payload():
    engine = _engine()
    envelope = RawEventEnvelope(raw_payload="this is just a plain unstructured line of text")
    result = engine.process(envelope)
    assert result.status == ParsingStatus.UNPARSED_FALLBACK
    assert result.fields["message"] == "this is just a plain unstructured line of text"
    # Fallback must never lose the original envelope
    assert result.raw_event.raw_payload == envelope.raw_payload


def test_engine_never_raises_on_garbage_input():
    engine = _engine()
    garbage_payloads = ["", "{{{{not json", "<not-a-valid-pri>garbled", "\x00\x01binary\x02"]
    for payload in garbage_payloads:
        envelope = RawEventEnvelope(raw_payload=payload)
        result = engine.process(envelope)  # must not raise
        assert result is not None
        assert result.event_id == envelope.event_id


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
