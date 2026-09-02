#!/usr/bin/env python3
"""
setup_topics.py — ULPF topic bootstrap

Idempotently creates the Kafka/Redpanda topics required by the Universal
Log Pre-processing Framework, with partitioning, replication and retention
tuned for a "billions of events/day" workload.

-------------------------------------------------------------------------
PARTITION KEY STRATEGY (read this before changing partition counts)
-------------------------------------------------------------------------
raw-event is keyed by log SOURCE identity (device hostname or source IP),
e.g. b"fw-edge-0042". Rationale:

  * Per-source ordering. A single firewall's event stream must be
    processed in order (state-table transitions, dedup windows, etc).
    Keying by source guarantees all of one device's events land on the
    same partition, hence the same consumer, hence in order.
  * Even fan-out at scale. In production this framework ingests from
    thousands-to-hundreds-of-thousands of edge devices, so source
    cardinality vastly exceeds partition count -> good load balance
    even though the key space isn't uniformly hashed by design.
parsed-event / normalized-event / retry / dead-letter are keyed by canonical
EVENT ID. The collector assigns this UUID once and every stage preserves it.
That key enables traceability and idempotent retry/replay handling without
incorrectly merging two independently collected logs that happen to contain
identical bytes.

Retry and dead-letter also deliberately break source affinity: one failed
event from source A must not head-of-line block source A's healthy traffic.

framework-metrics is keyed by worker_id (one logical stream per worker
instance, cheap to fan out to a single metrics aggregator consumer).
-------------------------------------------------------------------------
"""
from __future__ import annotations

import argparse
import logging
import sys

from confluent_kafka import KafkaException
from confluent_kafka.admin import AdminClient, NewTopic

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s setup_topics %(message)s",
)
log = logging.getLogger("setup_topics")

DAY_MS = 24 * 60 * 60 * 1000


def topic_specs(replication_factor: int) -> list[NewTopic]:
    """
    Return the full ULPF topic set.

    Partition counts assume a broker/cluster sized for ~billions of
    events/day (roughly tens of thousands of events/sec sustained).
    Rule of thumb used here: partitions = target_peak_partition_throughput
    headroom for consumer parallelism, sized generously since partition
    count can only be increased later, never decreased.
    """
    return [
        NewTopic(
            topic="raw-event",
            num_partitions=48,
            replication_factor=replication_factor,
            config={
                # Raw events are the framework's durable source of truth —
                # this is what makes "replay without losing accepted raw
                # events" possible. Keep them around for a while.
                "retention.ms": str(7 * DAY_MS),
                "cleanup.policy": "delete",
                "compression.type": "zstd",
                "min.insync.replicas": str(min(2, replication_factor)),
                "max.message.bytes": str(2 * 1024 * 1024),
            },
        ),
        NewTopic(
            topic="parsed-event",
            num_partitions=48,
            replication_factor=replication_factor,
            config={
                "retention.ms": str(3 * DAY_MS),
                "cleanup.policy": "delete",
                "compression.type": "zstd",
                "min.insync.replicas": str(min(2, replication_factor)),
            },
        ),
        NewTopic(
            topic="normalized-event",
            num_partitions=48,
            replication_factor=replication_factor,
            config={
                # Final output stage — kept longest, downstream sinks
                # (SIEM loaders, lakehouse writers) may lag.
                "retention.ms": str(7 * DAY_MS),
                "cleanup.policy": "delete",
                "compression.type": "zstd",
                "min.insync.replicas": str(min(2, replication_factor)),
            },
        ),
        NewTopic(
            topic="retry",
            num_partitions=12,
            replication_factor=replication_factor,
            config={
                # Retry volume is a small fraction of primary volume;
                # fewer partitions is fine and keeps backoff-scheduling
                # consumers simple.
                "retention.ms": str(1 * DAY_MS),
                "cleanup.policy": "delete",
                "compression.type": "zstd",
                "min.insync.replicas": str(min(2, replication_factor)),
            },
        ),
        NewTopic(
            topic="dead-letter",
            num_partitions=6,
            replication_factor=replication_factor,
            config={
                # Kept much longer for forensics / manual replay tooling.
                "retention.ms": str(30 * DAY_MS),
                "cleanup.policy": "delete",
                "compression.type": "zstd",
                "min.insync.replicas": str(min(2, replication_factor)),
            },
        ),
        NewTopic(
            topic="framework-metrics",
            num_partitions=6,
            replication_factor=replication_factor,
            config={
                "retention.ms": str(1 * DAY_MS),
                "cleanup.policy": "delete",
                "compression.type": "zstd",
                "min.insync.replicas": "1",
            },
        ),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Create ULPF topics")
    parser.add_argument("--brokers", default="localhost:9092")
    parser.add_argument(
        "--replication-factor",
        type=int,
        default=1,
        help="Use 3 in any real multi-broker deployment; 1 for single-node local dev.",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    admin = AdminClient({"bootstrap.servers": args.brokers})

    existing = set(admin.list_topics(timeout=15).topics.keys())
    specs = topic_specs(args.replication_factor)
    to_create = [t for t in specs if t.topic not in existing]

    if not to_create:
        log.info("All %d ULPF topics already exist. Nothing to do.", len(specs))
        return 0

    log.info(
        "Creating %d topic(s): %s",
        len(to_create),
        ", ".join(t.topic for t in to_create),
    )
    if args.dry_run:
        for t in to_create:
            log.info(
                "  [dry-run] %s partitions=%d rf=%d config=%s",
                t.topic, t.num_partitions, t.replication_factor, t.config,
            )
        return 0

    futures = admin.create_topics(to_create, request_timeout=30)
    failures = 0
    for topic, future in futures.items():
        try:
            future.result()
            log.info("  created: %s", topic)
        except KafkaException as e:
            failures += 1
            log.error("  FAILED: %s -> %s", topic, e)

    if failures:
        log.error("%d topic(s) failed to create.", failures)
        return 1

    log.info("Topic bootstrap complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
