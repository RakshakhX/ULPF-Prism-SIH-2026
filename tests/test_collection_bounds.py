from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from src.collection.archive import RawEventArchive
from src.collection.dedup import BoundedHashCache
from src.collection.pipeline import CollectionPipeline, CollectorConfig
from src.collection.publisher import InMemoryPublisher
from src.collection.rejected import RejectedEventLog


class RecordingArchive:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def store(self, envelope) -> None:
        self.calls.append("archive")


class RecordingPublisher:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def publish(self, envelope) -> None:
        self.calls.append("publish")


def test_archive_occurs_before_publish() -> None:
    calls: list[str] = []
    pipeline = CollectionPipeline(
        publisher=RecordingPublisher(calls),
        archive=RecordingArchive(calls),
    )

    result = pipeline.ingest(b"event", "udp", source_id="fw-1")

    assert result.accepted
    assert calls == ["archive", "publish"]


def test_archive_failure_prevents_publication() -> None:
    calls: list[str] = []

    class FailingArchive(RecordingArchive):
        def store(self, envelope) -> None:
            self.calls.append("archive")
            raise OSError("disk unavailable")

    pipeline = CollectionPipeline(
        publisher=RecordingPublisher(calls),
        archive=FailingArchive(calls),
    )

    result = pipeline.ingest(b"event", "udp", source_id="fw-1")

    assert not result.accepted
    assert result.reason == "archive_failed"
    assert calls == ["archive"]


def test_archive_failure_is_written_to_rejected_log(tmp_path: Path) -> None:
    class FailingArchive:
        def store(self, envelope) -> None:
            raise OSError("disk unavailable")

    rejected_log = RejectedEventLog(tmp_path / "rejected")
    pipeline = CollectionPipeline(
        publisher=InMemoryPublisher(),
        archive=FailingArchive(),
        rejected_log=rejected_log,
    )

    result = pipeline.ingest(b"event", "udp", source_id="fw-1")

    assert result.reason == "archive_failed"
    [record] = rejected_log.list_by_reason("archive_failed")
    assert record["raw_sha256"] == (
        "b8e1f80bd70ae0784c7855a451731b745fddb67749d23f637be9082b75e9575b"
    )
    assert record["metadata"] == {
        "error_type": "OSError",
        "failure_stage": "archive",
    }


def test_publish_failure_retains_archived_evidence(tmp_path: Path) -> None:
    class FailingPublisher:
        def publish(self, envelope) -> None:
            raise RuntimeError("broker unavailable")

    archive = RawEventArchive(tmp_path)
    rejected_log = RejectedEventLog(tmp_path / "rejected")
    pipeline = CollectionPipeline(
        publisher=FailingPublisher(),
        archive=archive,
        rejected_log=rejected_log,
    )

    result = pipeline.ingest(b"event", "tcp", source_id="fw-1")

    assert not result.accepted
    assert result.reason == "publish_failed"
    assert result.envelope is not None
    assert archive.retrieve(result.envelope.event_id) is not None
    [record] = rejected_log.list_by_reason("publish_failed")
    assert record["raw_sha256"] == result.envelope.raw_sha256
    assert record["metadata"] == {
        "error_type": "RuntimeError",
        "failure_stage": "publish",
    }


def test_duplicate_cache_is_bounded_and_thread_safe() -> None:
    cache = BoundedHashCache(max_entries=8)

    with ThreadPoolExecutor(max_workers=16) as executor:
        duplicate_results = list(executor.map(cache.check_and_add, ["same"] * 40))

    assert duplicate_results.count(False) == 1
    assert duplicate_results.count(True) == 39

    for index in range(100):
        cache.check_and_add(f"hash-{index}")
    assert len(cache) == 8


def test_pipeline_state_stays_bounded_under_many_unique_events(tmp_path: Path) -> None:
    config = CollectorConfig(
        max_event_size_bytes=100,
        dedup_max_entries=64,
        latency_window_size=128,
    )
    pipeline = CollectionPipeline(
        publisher=InMemoryPublisher(),
        archive=RawEventArchive(tmp_path),
        config=config,
    )

    for index in range(500):
        result = pipeline.ingest(str(index).encode(), "file", source_id="fixture")
        assert result.accepted

    assert pipeline.dedup_size <= 64
    assert pipeline.metrics.latency_sample_count <= 128
    assert pipeline.metrics.health()["accepted"] == 500
