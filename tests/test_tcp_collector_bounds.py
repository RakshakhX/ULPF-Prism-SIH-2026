from pathlib import Path

from src.collection.archive import RawEventArchive
from src.collection.pipeline import CollectionPipeline, CollectorConfig
from src.collection.publisher import InMemoryPublisher
from src.collection.rejected import RejectedEventLog
from src.collection.tcp_collector import TCPCollector


class ChunkSocket:
    """Deterministic socket boundary for exercising the real frame loop."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = iter(chunks)
        self.recv_calls = 0
        self.timeout: float | None = None

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def recv(self, size: int) -> bytes:
        self.recv_calls += 1
        return next(self._chunks, b"")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        return None


def build_pipeline(tmp_path: Path, max_size: int = 16) -> CollectionPipeline:
    return CollectionPipeline(
        publisher=InMemoryPublisher(),
        archive=RawEventArchive(tmp_path / "archive"),
        rejected_log=RejectedEventLog(tmp_path / "rejected"),
        config=CollectorConfig(max_event_size_bytes=max_size),
    )


def test_tcp_rejects_oversized_frame_before_reading_more_chunks(tmp_path: Path) -> None:
    pipeline = build_pipeline(tmp_path, max_size=16)
    collector = TCPCollector(
        pipeline,
        "127.0.0.1",
        0,
        read_timeout_seconds=0.2,
    )
    connection = ChunkSocket([b"A" * 10, b"B" * 10, b"C" * 10, b""])

    collector._handle_conn(connection, ("192.0.2.10", 5514))

    assert connection.recv_calls == 2
    assert connection.timeout == 0.2
    assert pipeline.publisher.messages() == []
    rejections = pipeline.rejected_log.list_by_reason("oversized_event")
    assert len(rejections) == 1
    assert rejections[0]["raw_size"] == 20


def test_tcp_checks_each_delimited_frame_instead_of_whole_chunk(tmp_path: Path) -> None:
    pipeline = build_pipeline(tmp_path, max_size=16)
    collector = TCPCollector(pipeline, "127.0.0.1", 0)
    connection = ChunkSocket([b"1234567890\nabcdefghij\n", b""])

    collector._handle_conn(connection, ("192.0.2.10", 5514))

    messages = pipeline.publisher.messages()
    assert len(messages) == 2
    assert [message["raw_size"] for message in messages] == [10, 10]
    assert pipeline.rejected_log.list_by_reason("oversized_event") == []


def test_tcp_publishes_canonical_base64_envelope(tmp_path: Path) -> None:
    pipeline = build_pipeline(tmp_path)
    collector = TCPCollector(pipeline, "127.0.0.1", 0)
    connection = ChunkSocket([b"\xffbinary\n", b""])

    collector._handle_conn(connection, ("192.0.2.10", 5514))

    [message] = pipeline.publisher.messages()
    assert message["raw_payload_b64"] == "/2JpbmFyeQ=="
    assert message["raw_size"] == 7
    assert "raw_event" not in message
