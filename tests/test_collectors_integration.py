import socket
import time
from pathlib import Path

from src.collection.archive import RawEventArchive
from src.collection.file_collector import FileCollector
from src.collection.pipeline import CollectionPipeline, CollectorConfig
from src.collection.publisher import InMemoryPublisher
from src.collection.tcp_collector import TCPCollector
from src.collection.udp_collector import UDPCollector

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def build_pipeline(tmp_path, max_size=100000):
    publisher = InMemoryPublisher()
    archive = RawEventArchive(tmp_path / "archive")
    cfg = CollectorConfig(max_event_size_bytes=max_size)
    return CollectionPipeline(publisher=publisher, archive=archive, config=cfg)


def test_file_replay_valid_logs(tmp_path):
    pipeline = build_pipeline(tmp_path)
    collector = FileCollector(pipeline)
    results = collector.replay(SAMPLES / "cisco_asa_valid.log")
    assert len(results) == 20
    assert all(r.accepted for r in results)


def test_file_replay_malformed_logs_rejected_or_accepted_without_crash(tmp_path):
    pipeline = build_pipeline(tmp_path)
    collector = FileCollector(pipeline)
    results = collector.replay(SAMPLES / "cisco_asa_malformed.log")
    assert len(results) == 5
    # empty line -> rejected with reason; the rest are preserved as raw bytes either way
    assert any(r.reason == "empty_event" for r in results)


def test_file_replay_duplicates_recorded_not_dropped(tmp_path):
    pipeline = build_pipeline(tmp_path)
    collector = FileCollector(pipeline)
    results = collector.replay(SAMPLES / "cisco_asa_duplicates.log")
    assert len(results) == 3
    assert all(r.accepted for r in results)
    assert [r.duplicate for r in results] == [False, True, True]


def test_file_replay_oversized_logs_rejected(tmp_path):
    pipeline = build_pipeline(tmp_path, max_size=65536)
    collector = FileCollector(pipeline)
    results = collector.replay(SAMPLES / "cisco_asa_oversized.log")
    assert len(results) == 2
    assert all(not r.accepted and r.reason == "oversized_event" for r in results)


def test_file_replay_removes_only_lf_framing_byte(tmp_path):
    fixture = tmp_path / "significant-carriage-return.log"
    fixture.write_bytes(b"payload\r\n")
    pipeline = build_pipeline(tmp_path)

    [result] = FileCollector(pipeline).replay(fixture)

    assert result.accepted
    assert result.envelope.raw_bytes() == b"payload\r"


def test_udp_collector_end_to_end(tmp_path):
    pipeline = build_pipeline(tmp_path)
    collector = UDPCollector(pipeline, "127.0.0.1", 0)
    collector._sock.bind(("127.0.0.1", 0))
    port = collector._sock.getsockname()[1]
    collector._running = True
    import threading

    collector._thread = threading.Thread(target=collector._loop, daemon=True)
    collector._thread.start()

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.sendto(b"udp test event", ("127.0.0.1", port))
    time.sleep(0.2)
    collector.stop()

    messages = pipeline.publisher.messages()
    assert any(m["transport"] == "udp" for m in messages)


def test_tcp_collector_end_to_end(tmp_path):
    pipeline = build_pipeline(tmp_path)
    collector = TCPCollector(pipeline, "127.0.0.1", 0)
    collector._sock.bind(("127.0.0.1", 0))
    port = collector._sock.getsockname()[1]
    collector._sock.listen(5)
    collector._running = True
    import threading

    collector._thread = threading.Thread(target=collector._accept_loop, daemon=True)
    collector._thread.start()

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", port))
    client.sendall(b"tcp test event\n")
    time.sleep(0.2)
    client.close()
    collector.stop()

    messages = pipeline.publisher.messages()
    assert any(m["transport"] == "tcp" for m in messages)
