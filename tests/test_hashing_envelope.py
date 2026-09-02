from src.collection.hashing import new_event_id, sha256_hex, verify_hash
from src.contracts import RawEventEnvelope


def test_sha256_deterministic():
    raw = "café — düpe 日本語".encode()
    h1 = sha256_hex(raw)
    h2 = sha256_hex(raw)
    assert h1 == h2
    assert len(h1) == 64
    assert h1 == h1.lower()


def test_verify_hash_true_and_false():
    raw = b"hello world"
    h = sha256_hex(raw)
    assert verify_hash(raw, h) is True
    assert verify_hash(b"tampered", h) is False


def test_event_id_unique():
    assert new_event_id() != new_event_id()


def test_envelope_roundtrip_preserves_unicode():
    raw = "unicode: 漢字, emoji: 🔥, special: ñ".encode()
    env = RawEventEnvelope.from_bytes(
        raw,
        source_id="s1",
        source_ip="10.0.0.1",
        transport="udp",
        collector_id="c1",
        collector_version="0.1.0",
    )
    restored = RawEventEnvelope.model_validate_json(env.model_dump_json())
    assert restored.raw_bytes() == raw
