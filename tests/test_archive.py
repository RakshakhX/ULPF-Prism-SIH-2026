from pathlib import Path

from src.collection.archive import RawEventArchive
from src.contracts import RawEventEnvelope


def make_envelope(raw: bytes) -> RawEventEnvelope:
    return RawEventEnvelope.from_bytes(
        raw,
        source_id="s1",
        source_ip="10.0.0.1",
        transport="tcp",
        collector_id="c1",
        collector_version="0.1.0",
    )


def test_store_and_retrieve_by_event_id(tmp_path: Path):
    archive = RawEventArchive(tmp_path)
    env = make_envelope(b"archive me")
    archive.store(env)

    meta, raw = archive.retrieve(env.event_id)
    assert raw == b"archive me"
    assert meta["event_id"] == str(env.event_id)


def test_verify_detects_intact_data(tmp_path: Path):
    archive = RawEventArchive(tmp_path)
    env = make_envelope(b"intact bytes")
    archive.store(env)
    assert archive.verify(env.event_id) is True


def test_verify_detects_tampering(tmp_path: Path):
    archive = RawEventArchive(tmp_path)
    env = make_envelope(b"original bytes")
    archive.store(env)
    # simulate corruption of the stored raw file
    (tmp_path / f"{env.event_id}.raw").write_bytes(b"tampered bytes")
    assert archive.verify(env.event_id) is False


def test_retrieve_missing_event_returns_none(tmp_path: Path):
    archive = RawEventArchive(tmp_path)
    assert archive.retrieve("does-not-exist") is None
