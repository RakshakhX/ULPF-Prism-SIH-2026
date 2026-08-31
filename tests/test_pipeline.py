from pathlib import Path

import pytest

from src.collection.archive import RawEventArchive
from src.collection.hashing import sha256_hex
from src.collection.pipeline import CollectionPipeline, CollectorConfig
from src.collection.publisher import InMemoryPublisher
from src.collection.rejected import RejectedEventLog


@pytest.fixture
def pipeline(tmp_path: Path) -> CollectionPipeline:
    publisher = InMemoryPublisher()
    archive = RawEventArchive(tmp_path / "archive")
    rejected_log = RejectedEventLog(tmp_path / "rejected")
    cfg = CollectorConfig(max_event_size_bytes=100)
    return CollectionPipeline(
        publisher=publisher, archive=archive, rejected_log=rejected_log, config=cfg
    )


def test_accepts_normal_event_with_id_and_hash(pipeline: CollectionPipeline):
    raw = b"<166>Jan 1 2026 test asa-fw01 %ASA-6-106100: permitted tcp"
    result = pipeline.ingest(raw=raw, transport="tcp", source_ip="1.2.3.4")
    assert result.accepted
    assert result.envelope.event_id
    assert result.envelope.content_hash == sha256_hex(raw)
    assert result.envelope.raw_event == raw


def test_recomputed_hash_matches_stored_hash(pipeline: CollectionPipeline):
    raw = b"some raw event bytes"
    result = pipeline.ingest(raw=raw, transport="udp")
    assert sha256_hex(result.envelope.raw_event) == result.envelope.content_hash


def test_empty_event_rejected_with_reason(pipeline: CollectionPipeline):
    result = pipeline.ingest(raw=b"", transport="udp")
    assert not result.accepted
    assert result.reason == "empty_event"


def test_oversized_event_rejected_with_reason(pipeline: CollectionPipeline):
    raw = b"x" * 1000
    result = pipeline.ingest(raw=raw, transport="tcp")
    assert not result.accepted
    assert result.reason == "oversized_event"


def test_duplicate_event_is_preserved_not_dropped(pipeline: CollectionPipeline):
    raw = b"repeat me"
    r1 = pipeline.ingest(raw=raw, transport="udp")
    r2 = pipeline.ingest(raw=raw, transport="udp")
    assert r1.accepted and r2.accepted
    assert r1.duplicate is False
    assert r2.duplicate is True
    assert r1.envelope.event_id != r2.envelope.event_id


def test_unicode_and_special_chars_preserved(pipeline: CollectionPipeline):
    raw = "unicode 漢字 emoji 🔥".encode()
    result = pipeline.ingest(raw=raw, transport="file")
    assert result.envelope.raw_event == raw


def test_malformed_bytes_do_not_crash_pipeline(pipeline: CollectionPipeline):
    raw = b"\xff\xfe\x00garbage-not-utf8"
    result = pipeline.ingest(raw=raw, transport="tcp")
    assert result.accepted
    assert result.envelope.raw_event == raw


def test_accepted_event_is_published_and_archived(pipeline: CollectionPipeline, tmp_path):
    raw = b"published and archived"
    result = pipeline.ingest(raw=raw, transport="udp")
    messages = pipeline.publisher.messages()
    assert any(m["event_id"] == result.envelope.event_id for m in messages)
    retrieved = pipeline.archive.retrieve(result.envelope.event_id)
    assert retrieved is not None
    meta, raw_bytes = retrieved
    assert raw_bytes == raw
    assert meta["content_hash"] == result.envelope.content_hash


def test_metrics_counts(pipeline: CollectionPipeline):
    pipeline.ingest(raw=b"ok", transport="udp")
    pipeline.ingest(raw=b"", transport="udp")
    pipeline.ingest(raw=b"x" * 1000, transport="udp")
    health = pipeline.metrics.health()
    assert health["received"] == 3
    assert health["accepted"] == 1
    assert health["rejected"] == 2
    assert health["bytes_received"] == 2 + 0 + 1000


def test_rejected_event_is_recorded_with_reason(pipeline: CollectionPipeline):
    result = pipeline.ingest(raw=b"x" * 1000, transport="tcp")
    assert not result.accepted
    matches = pipeline.rejected_log.list_by_reason("oversized_event")
    assert len(matches) == 1
    assert matches[0]["raw_size"] == 1000
