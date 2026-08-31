import json
from pathlib import Path

from .envelope import RawEventEnvelope
from .hashing import verify_hash


class RawEventArchive:
    """Stores accepted raw events on disk, keyed by event_id, and lets
    them be retrieved/verified later. One event = one .raw + one .json."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def _raw_path(self, event_id: str) -> Path:
        return self.root / f"{event_id}.raw"

    def _meta_path(self, event_id: str) -> Path:
        return self.root / f"{event_id}.json"

    def store(self, envelope: RawEventEnvelope) -> None:
        self._raw_path(envelope.event_id).write_bytes(envelope.raw_event)
        meta = envelope.to_dict(embed_raw_as_text=False)
        self._meta_path(envelope.event_id).write_text(
            json.dumps(meta, ensure_ascii=False), encoding="utf-8"
        )

    def retrieve(self, event_id: str) -> tuple[dict, bytes] | None:
        raw_path, meta_path = self._raw_path(event_id), self._meta_path(event_id)
        if not raw_path.exists() or not meta_path.exists():
            return None
        raw = raw_path.read_bytes()
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        return meta, raw

    def verify(self, event_id: str) -> bool:
        """Recompute the hash of the archived bytes and compare to the
        hash recorded at ingestion time."""
        result = self.retrieve(event_id)
        if result is None:
            return False
        meta, raw = result
        return verify_hash(raw, meta["content_hash"])
