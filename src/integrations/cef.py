"""Common Event Format serialization for SIEM-compatible delivery."""

from __future__ import annotations

from typing import Any


def _escape(value: Any, *, extension: bool = False) -> str:
    text = str(value)
    text = text.replace("\\", "\\\\")
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    text = text.replace("|", "\\|")
    if extension:
        text = text.replace("=", "\\=")
    return text


def serialize_cef(event: dict[str, Any]) -> bytes:
    """Serialize one UnifiedEvent without losing its evidence identity."""

    metadata = event["event"]
    trace = event["traceability"]
    action = event["action"]
    severity = event["severity"]
    fields: list[tuple[str, Any]] = [
        ("schemaVersion", event["schema_version"]),
        ("externalId", metadata["id"]),
        ("rawSha256", trace["raw_sha256"]),
        ("sourcePack", trace["source_pack"]["name"]),
        ("sourcePackVersion", trace["source_pack"]["version"]),
        ("parser", trace["parser"]["name"]),
        ("parserVersion", trace["parser"]["version"]),
        ("quality", event["quality"]["status"]),
        ("act", action["normalized"]),
    ]
    if metadata.get("message"):
        fields.append(("msg", metadata["message"]))
    for prefix, endpoint in (("s", event.get("source", {})), ("d", event.get("destination", {}))):
        if endpoint.get("ip"):
            fields.append((f"{prefix}rc" if prefix == "s" else "dst", endpoint["ip"]))
        if endpoint.get("port") is not None:
            fields.append((f"{prefix}pt", endpoint["port"]))
    extension = " ".join(f"{key}={_escape(value, extension=True)}" for key, value in fields)
    header = "|".join(
        [
            "CEF:0",
            "ULPF",
            "Prism",
            _escape(event["schema_version"]),
            _escape(metadata["type"]),
            _escape(metadata["name"]),
            str(severity["normalized"]),
        ]
    )
    return f"{header}|{extension}".encode()
