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

from core.models import ParsingStatus, RawEventEnvelope  # noqa: E402
from source_packs.generic_linux_syslog.pack import GenericLinuxSyslogPack  # noqa: E402

PACK_DIR = Path(__file__).resolve().parents[1]


def _load_sample_line() -> str:
    with open(PACK_DIR / "samples" / "sample.log", "r", encoding="utf-8") as fh:
        return fh.readline().strip()


def test_detection_matches_sample_line():
    pack = GenericLinuxSyslogPack()
    envelope = RawEventEnvelope(raw_payload=_load_sample_line())
    assert pack.detect(envelope) is True


def test_parse_matches_expected_output():
    pack = GenericLinuxSyslogPack()
    envelope = RawEventEnvelope(raw_payload=_load_sample_line())
    parsed = pack.parse(envelope)

    assert parsed.status == ParsingStatus.SUCCESS
    assert parsed.vendor == "Generic"
    assert parsed.fields["hostname"] == "mymachine"
    assert parsed.fields["process"] == "sshd"
    assert parsed.fields["pid"] == "1234"
    assert parsed.fields["syslog_facility"] == 4
    assert parsed.fields["syslog_facility_name"] == "auth"
    assert "Failed password" in parsed.fields["message"]


def test_detection_rejects_unrelated_payload():
    pack = GenericLinuxSyslogPack()
    envelope = RawEventEnvelope(raw_payload='{"totally": "not syslog"}')
    assert pack.detect(envelope) is False


if __name__ == "__main__":
    test_detection_matches_sample_line()
    test_parse_matches_expected_output()
    test_detection_rejects_unrelated_payload()
    print("All generic_linux_syslog pack tests passed.")
