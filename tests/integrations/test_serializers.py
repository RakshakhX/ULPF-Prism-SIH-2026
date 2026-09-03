from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from src.integrations import serialize_cef, serialize_json, serialize_rfc5424

FIXTURE = Path("tests/fixtures/valid_minimal_network_event.json")


def event() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_json_is_deterministic_compact_utf8_and_traceable() -> None:
    value = event()

    first = serialize_json(value)
    second = serialize_json(dict(reversed(list(value.items()))))

    assert first == second
    assert b"\n" not in first
    assert json.loads(first) == value
    assert value["traceability"]["raw_sha256"].encode() in first


def test_cef_escapes_reserved_characters_and_preserves_traceability() -> None:
    value = deepcopy(event())
    value["event"]["message"] = "deny|reason=a\\b\nnext\rline"

    payload = serialize_cef(value)

    assert payload.startswith(b"CEF:0|ULPF|Prism|1.0.0|")
    assert b"deny\\|reason\\=a\\\\b\\nnext\\rline" in payload
    assert value["event"]["id"].encode() in payload
    assert value["traceability"]["raw_sha256"].encode() in payload


def test_syslog_contains_schema_event_identity_pack_and_quality() -> None:
    value = event()

    payload = serialize_rfc5424(value)

    assert payload.startswith(b"<")
    assert b' schemaVersion="1.0.0"' in payload
    assert f' eventId="{value["event"]["id"]}"'.encode() in payload
    assert f' rawSha256="{value["traceability"]["raw_sha256"]}"'.encode() in payload
    assert b' sourcePack="' in payload
    assert b' quality="valid"' in payload

