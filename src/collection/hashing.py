import hashlib
import uuid


def sha256_hex(raw: bytes) -> str:
    """Lowercase 64-char SHA-256 hex digest of the exact raw bytes."""
    return hashlib.sha256(raw).hexdigest()


def new_event_id() -> str:
    """UUID4 string, matching the traceability.raw_event_id UUID format."""
    return str(uuid.uuid4())


def verify_hash(raw: bytes, expected_hash: str) -> bool:
    return sha256_hex(raw) == expected_hash
