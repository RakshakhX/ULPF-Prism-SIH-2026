"""RFC 5424 serialization with ULPF structured traceability data."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def _param(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def _token(value: Any, fallback: str = "-") -> str:
    text = str(value or fallback)
    return "".join(character if 33 <= ord(character) <= 126 else "_" for character in text)[:48]


def serialize_rfc5424(event: dict[str, Any]) -> bytes:
    observed = datetime.fromisoformat(event["time"]["observed_at"].replace("Z", "+00:00"))
    timestamp = observed.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    observer = event["observer"]
    metadata = event["event"]
    trace = event["traceability"]
    quality = event["quality"]
    params = {
        "schemaVersion": event["schema_version"],
        "eventId": metadata["id"],
        "rawSha256": trace["raw_sha256"],
        "sourcePack": trace["source_pack"]["name"],
        "sourcePackVersion": trace["source_pack"]["version"],
        "parser": trace["parser"]["name"],
        "parserVersion": trace["parser"]["version"],
        "quality": quality["status"],
    }
    structured = " ".join(f'{key}="{_param(value)}"' for key, value in params.items())
    message = str(metadata.get("message") or metadata["name"]).replace("\r", " ").replace("\n", " ")
    priority = 128 + min(max(int(event["severity"]["normalized"]), 0), 7)
    payload = (
        f"<{priority}>1 {timestamp} {_token(observer.get('hostname'))} ulpf-prism - "
        f"{_token(metadata['type'])} [ulpf@32473 {structured}] {message}"
    )
    return payload.encode("utf-8")
