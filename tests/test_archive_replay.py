from __future__ import annotations

import base64
import json
from uuid import uuid4

from src.collection.archive import RawEventArchive
from src.collection.publisher import InMemoryPublisher
from src.collection.replay import replay_events
from src.contracts import RawEventEnvelope


def test_replay_keeps_exact_original_identity_and_evidence(tmp_path):
    archive, publisher = RawEventArchive(tmp_path), InMemoryPublisher()
    event = RawEventEnvelope.from_bytes(
        b"\xff\x00raw evidence\n", source_id="edge", transport="udp"
    )
    archive.store(event)
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    result = replay_events(archive, [event.event_id], publisher)
    assert result == {"attempted": 1, "published": 1, "failed": 0, "errors": []}
    assert publisher.messages() == [event.model_dump(mode="json")]
    assert before == {path.name: path.read_bytes() for path in tmp_path.iterdir()}


def test_missing_and_corrupt_evidence_are_counted_and_never_published(tmp_path):
    archive, publisher = RawEventArchive(tmp_path), InMemoryPublisher()
    event = RawEventEnvelope.from_bytes(b"original", source_id="edge", transport="tcp")
    archive.store(event)
    (tmp_path / f"{event.event_id}.raw").write_bytes(b"tampered")
    result = replay_events(archive, [event.event_id, uuid4()], publisher)
    assert (result["attempted"], result["published"], result["failed"]) == (2, 0, 2)
    assert publisher.messages() == []


def test_replay_rejects_metadata_for_a_different_event_id(tmp_path):
    archive, publisher = RawEventArchive(tmp_path), InMemoryPublisher()
    event = RawEventEnvelope.from_bytes(b"original", source_id="edge", transport="tcp")
    archive.store(event)
    path = tmp_path / f"{event.event_id}.json"
    metadata = json.loads(path.read_text())
    metadata["event_id"] = str(uuid4())
    path.write_text(json.dumps(metadata))
    result = replay_events(archive, [event.event_id], publisher)
    assert result["failed"] == 1
    assert publisher.messages() == []


def test_replay_reports_delivery_failure_without_deleting_evidence(tmp_path):
    class UnavailablePublisher:
        def publish(self, _event):
            raise RuntimeError("delivery failed")

    archive = RawEventArchive(tmp_path)
    event = RawEventEnvelope.from_bytes(b"original", source_id="edge", transport="tcp")
    archive.store(event)
    result = replay_events(archive, [event.event_id], UnavailablePublisher())
    assert result["failed"] == 1
    assert result["published"] == 0
    assert archive.verify(event.event_id)


def test_replay_errors_do_not_disclose_raw_or_encoded_evidence(tmp_path):
    archive, publisher = RawEventArchive(tmp_path), InMemoryPublisher()
    event = RawEventEnvelope.from_bytes(b"initial", source_id="edge", transport="tcp")
    archive.store(event)
    synthetic_secret = b"key=1234"
    (tmp_path / f"{event.event_id}.raw").write_bytes(synthetic_secret)
    result = replay_events(archive, [event.event_id], publisher)
    serialized = json.dumps(result)
    assert result["failed"] == 1
    assert synthetic_secret.decode() not in serialized
    assert base64.b64encode(synthetic_secret).decode() not in serialized
    assert result["errors"][0]["error_code"] == "ARCHIVE_VALIDATION_FAILED"
