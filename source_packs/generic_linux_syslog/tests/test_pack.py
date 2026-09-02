"""
source_packs/generic_linux_syslog/tests/test_pack.py

Self-contained validation test for this Source Pack. Every pack is expected
to ship a test like this so CI can validate packs independently of the
core engine's own test suite.
"""

import sys
from pathlib import Path

# Allow running this file directly (python source_packs/.../test_pack.py)
# as well as via pytest from the project root.
PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from source_packs.generic_linux_syslog.pack import GenericLinuxSyslogPack  # noqa: E402
from src.contracts import ParseStatus, RawEventEnvelope  # noqa: E402

PACK_DIR = Path(__file__).resolve().parents[1]


def _load_sample_line() -> str:
    with open(PACK_DIR / "samples" / "sample.log", encoding="utf-8") as fh:
        return fh.readline().strip()


def _envelope(text: str) -> RawEventEnvelope:
    return RawEventEnvelope.from_bytes(text.encode(), source_id="linux-fixture", transport="file")


def test_detection_matches_sample_line():
    pack = GenericLinuxSyslogPack()
    envelope = _envelope(_load_sample_line())
    assert pack.detect(envelope) is True


def test_parse_matches_expected_output():
    pack = GenericLinuxSyslogPack()
    envelope = _envelope(_load_sample_line())
    parsed = pack.parse(envelope)

    assert parsed.status is ParseStatus.SUCCESS
    assert parsed.vendor == "Generic"
    assert parsed.extracted_fields["hostname"] == "mymachine"
    assert parsed.extracted_fields["process"] == "sshd"
    assert parsed.extracted_fields["pid"] == "1234"
    assert parsed.extracted_fields["syslog_facility"] == 4
    assert parsed.extracted_fields["syslog_facility_name"] == "auth"
    assert "Failed password" in parsed.extracted_fields["message"]


def test_detection_rejects_unrelated_payload():
    pack = GenericLinuxSyslogPack()
    envelope = _envelope('{"totally": "not syslog"}')
    assert pack.detect(envelope) is False


if __name__ == "__main__":
    test_detection_matches_sample_line()
    test_parse_matches_expected_output()
    test_detection_rejects_unrelated_payload()
    print("All generic_linux_syslog pack tests passed.")
