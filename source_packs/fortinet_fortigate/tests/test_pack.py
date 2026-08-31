"""
source_packs/fortinet_fortigate/tests/test_pack.py

Validation suite for the FortiGate Source Pack.

Loads `manifest.yaml` (indirectly, via FortinetFortigatePack), runs all 25
lines from `samples/raw_logs.txt` through the parsing engine, and asserts:

  1. Each of the 20 valid logs produces `fields` matching
     `samples/expected_outputs.json` exactly.
  2. Each of the 5 malformed logs degrades gracefully to the engine's
     FallbackParser (status == UNPARSED_FALLBACK) instead of raising or
     producing garbage structured output.
  3. The engine never raises on any of the 25 lines.

Run with: pytest source_packs/fortinet_fortigate/tests/test_pack.py -v
"""

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from core.engine import ParsingEngine  # noqa: E402
from core.models import ParsingStatus, RawEventEnvelope, Severity  # noqa: E402
from source_packs.fortinet_fortigate.pack import FortinetFortigatePack  # noqa: E402

PACK_DIR = Path(__file__).resolve().parents[1]
SAMPLES_DIR = PACK_DIR / "samples"
PACKS_DIR = PROJECT_ROOT / "source_packs"

EXPECTED_VALID_COUNT = 20
EXPECTED_MALFORMED_COUNT = 5


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def raw_lines():
    with open(SAMPLES_DIR / "raw_logs.txt", "r", encoding="utf-8") as fh:
        lines = [line.rstrip("\n") for line in fh if line.strip()]
    assert len(lines) == EXPECTED_VALID_COUNT + EXPECTED_MALFORMED_COUNT, (
        f"Expected {EXPECTED_VALID_COUNT + EXPECTED_MALFORMED_COUNT} sample lines, found {len(lines)}"
    )
    return lines


@pytest.fixture(scope="module")
def valid_lines(raw_lines):
    return raw_lines[:EXPECTED_VALID_COUNT]


@pytest.fixture(scope="module")
def malformed_lines(raw_lines):
    return raw_lines[EXPECTED_VALID_COUNT:]


@pytest.fixture(scope="module")
def expected_outputs():
    with open(SAMPLES_DIR / "expected_outputs.json", "r", encoding="utf-8") as fh:
        data = json.load(fh)
    assert len(data) == EXPECTED_VALID_COUNT
    return data


@pytest.fixture(scope="module")
def pack():
    """Loads manifest.yaml via the pack class directly (pack-level tests)."""
    return FortinetFortigatePack()


@pytest.fixture(scope="module")
def engine():
    """Full core engine, pointed at the whole source_packs/ tree (engine-level tests)."""
    return ParsingEngine(packs_dir=PACKS_DIR)


# --------------------------------------------------------------------------
# Task 4a: manifest / pack loads correctly
# --------------------------------------------------------------------------

def test_manifest_loads_and_identifies_pack(pack):
    assert pack.vendor == "Fortinet"
    assert pack.product == "FortiGate"
    assert pack.format_type == "key_value"
    assert pack.pack_id == "fortinet_fortigate"


def test_engine_discovers_fortigate_pack(engine):
    pack_ids = [p.pack_id for p in engine.registry.packs]
    assert "fortinet_fortigate" in pack_ids


# --------------------------------------------------------------------------
# Task 4b: 20 valid logs parse correctly and match expected_outputs.json
# --------------------------------------------------------------------------

@pytest.mark.parametrize("index", range(EXPECTED_VALID_COUNT))
def test_valid_log_matches_expected_fields(index, valid_lines, expected_outputs, pack):
    raw_line = valid_lines[index]
    expected = expected_outputs[index]

    # Sanity check fixtures stay in sync (same line the expected output was derived from)
    assert expected["raw_log"] == raw_line

    envelope = RawEventEnvelope(raw_payload=raw_line)
    assert pack.detect(envelope) is True, f"Pack failed to detect valid FortiGate log at line {index + 1}"

    parsed = pack.parse(envelope)
    assert parsed.status == ParsingStatus.SUCCESS
    assert parsed.vendor == expected["vendor"]
    assert parsed.product == expected["product"]
    assert parsed.fields == expected["fields"], (
        f"Field mismatch on line {index + 1}:\n"
        f"  got:      {parsed.fields}\n"
        f"  expected: {expected['fields']}"
    )


def test_valid_logs_get_normalized_timestamp_and_severity(valid_lines, pack):
    envelope = RawEventEnvelope(raw_payload=valid_lines[0])  # traffic/forward, level=notice
    parsed = pack.parse(envelope)
    assert parsed.event_timestamp is not None
    assert parsed.event_timestamp.year == 2026
    assert parsed.event_timestamp.month == 8
    assert parsed.event_timestamp.day == 30
    assert parsed.severity == Severity.MEDIUM  # "notice" maps to MEDIUM
    assert parsed.host == "FGT-EDGE-01"
    assert parsed.event_category == "traffic.forward"


def test_critical_ips_log_maps_to_critical_severity(valid_lines, pack):
    # line 13 (index 12) is the "alert"-level blocked IPS event
    envelope = RawEventEnvelope(raw_payload=valid_lines[12])
    parsed = pack.parse(envelope)
    assert parsed.severity == Severity.CRITICAL
    assert parsed.fields["action"] == "blocked"
    assert parsed.fields["attack_signature"] is not None


def test_event_log_promotes_logdesc_as_message(valid_lines, pack):
    # line 16 (index 15) is the system reboot event log — no `msg`... actually
    # has msg, but log_description should still populate fields correctly.
    envelope = RawEventEnvelope(raw_payload=valid_lines[15])
    parsed = pack.parse(envelope)
    assert parsed.fields["log_description"] == "System reboot"
    assert parsed.event_category == "event.system"


# --------------------------------------------------------------------------
# Task 4c: 5 malformed logs degrade gracefully to the FallbackParser
# --------------------------------------------------------------------------

def test_malformed_count_matches_spec(malformed_lines):
    assert len(malformed_lines) == EXPECTED_MALFORMED_COUNT


@pytest.mark.parametrize("index", range(EXPECTED_MALFORMED_COUNT))
def test_malformed_log_falls_back_via_engine(index, malformed_lines, engine):
    raw_line = malformed_lines[index]
    envelope = RawEventEnvelope(raw_payload=raw_line)

    # Must never raise.
    result = engine.process(envelope)

    assert result is not None
    assert result.status == ParsingStatus.UNPARSED_FALLBACK, (
        f"Malformed line {index + 1} did not fall back as expected: status={result.status}"
    )
    assert result.raw_event.raw_payload == raw_line
    assert result.fields.get("message") == raw_line
    assert result.errors, "Fallback event should record a reason in `errors`"


@pytest.mark.parametrize("index", range(EXPECTED_MALFORMED_COUNT))
def test_malformed_log_is_not_detected_by_fortigate_pack(index, malformed_lines, pack):
    envelope = RawEventEnvelope(raw_payload=malformed_lines[index])
    assert pack.detect(envelope) is False, (
        f"FortiGate pack incorrectly claimed malformed line {index + 1}"
    )


def test_engine_never_raises_across_all_25_lines(raw_lines, engine):
    for i, raw_line in enumerate(raw_lines, start=1):
        envelope = RawEventEnvelope(raw_payload=raw_line)
        try:
            result = engine.process(envelope)
        except Exception as exc:  # pragma: no cover - the whole point of this test
            pytest.fail(f"engine.process() raised on sample line {i}: {exc}")
        assert result is not None


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
