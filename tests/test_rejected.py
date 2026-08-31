from pathlib import Path

from src.collection.rejected import RejectedEventLog


def test_rejected_event_is_persisted_and_retrievable(tmp_path: Path):
    log = RejectedEventLog(tmp_path)
    rec = log.record(raw=b"", transport="udp", reason="empty_event", source_ip="1.2.3.4")
    fetched = log.retrieve(rec.rejection_id)
    assert fetched is not None
    assert fetched["reason"] == "empty_event"
    assert fetched["transport"] == "udp"


def test_oversized_sample_is_truncated_not_full_payload(tmp_path: Path):
    log = RejectedEventLog(tmp_path)
    huge = b"x" * 100000
    rec = log.record(raw=huge, transport="tcp", reason="oversized_event")
    assert rec.raw_size == 100000
    assert len(rec.raw_sample) <= RejectedEventLog.SAMPLE_BYTES
    assert rec.sample_truncated is True


def test_list_by_reason(tmp_path: Path):
    log = RejectedEventLog(tmp_path)
    log.record(raw=b"", transport="udp", reason="empty_event")
    log.record(raw=b"x" * 100000, transport="udp", reason="oversized_event")
    empties = log.list_by_reason("empty_event")
    assert len(empties) == 1


def test_retrieve_missing_returns_none(tmp_path: Path):
    log = RejectedEventLog(tmp_path)
    assert log.retrieve("does-not-exist") is None
