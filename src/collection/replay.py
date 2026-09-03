"""Republish verified archived envelopes without generating new identities."""

from __future__ import annotations

import argparse
import base64
import json
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from uuid import UUID

from src.collection.archive import RawEventArchive
from src.collection.publisher import KafkaStreamPublisher, RawEventPublisher
from src.contracts import RawEventEnvelope


def replay_events(
    archive: RawEventArchive, event_ids: Sequence[UUID], publisher: RawEventPublisher
) -> dict[str, Any]:
    published = 0
    errors = []
    for requested_id in event_ids:
        error_code = "ARCHIVE_READ_FAILED"
        try:
            event_id = UUID(str(requested_id))  # No caller-controlled archive path fragments.
            stored = archive.retrieve(event_id)
            if stored is None:
                raise ValueError("archived event was not found or is incomplete")
            metadata, raw = stored
            error_code = "ARCHIVE_VALIDATION_FAILED"
            envelope = RawEventEnvelope.model_validate(
                {**metadata, "raw_payload_b64": base64.b64encode(raw).decode("ascii")}
            )
            if envelope.event_id != event_id:
                raise ValueError("archive metadata does not match requested event ID")
            error_code = "REPLAY_DELIVERY_FAILED"
            publisher.publish(envelope)
            published += 1
        except Exception:
            # Validation/transport errors may contain evidence or credentials.
            # Only expose the failing stage; the archive remains authoritative.
            errors.append({"event_id": str(requested_id), "error_code": error_code})
    return {
        "attempted": len(event_ids),
        "published": published,
        "failed": len(event_ids) - published,
        "errors": errors,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive-dir", type=Path, default=Path("/var/lib/ulpf/raw-archive"))
    parser.add_argument("--event-id", action="append", type=UUID, required=True)
    parser.add_argument("--brokers", default=os.environ.get("ULPF_KAFKA_BROKERS"))
    args = parser.parse_args(argv)
    if not args.brokers:
        parser.error("supply --brokers or ULPF_KAFKA_BROKERS")
    if not args.archive_dir.is_dir():
        parser.error("archive directory does not exist")

    from confluent_kafka import Producer

    publisher = KafkaStreamPublisher(
        Producer(
            {
                "bootstrap.servers": args.brokers,
                "acks": "all",
                "enable.idempotence": True,
                "compression.type": "zstd",
            }
        )
    )
    result = replay_events(RawEventArchive(args.archive_dir), args.event_id, publisher)
    print(json.dumps(result, sort_keys=True))
    return 1 if result["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
