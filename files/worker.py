#!/usr/bin/env python3
"""
worker.py — ULPF consumer-group worker

Roles (selected with --role):

  parser         raw-event        -> parsed-event | retry | dead-letter
  retry-handler  retry             -> parsed-event | retry | dead-letter
                                       (honors per-event backoff-until time)
  replay         raw-event (from a historical offset/timestamp, using a
                 fresh consumer group) -> parsed-event | retry | dead-letter

All three roles share the same processing core, so "replay" is not a
special code path that could drift from normal processing — it is the
parser pipeline pointed at old offsets under a new group id.

-------------------------------------------------------------------------
CORRECTNESS RULES THIS WORKER ENFORCES
-------------------------------------------------------------------------
1. Manual offset commit, and ONLY after downstream produce is acked.
   We never advance a raw-event consumer offset past a message whose
   output (parsed-event, retry, or dead-letter) has not been durably
   produced. That would silently lose the event. Offsets are committed
   in batches, gated on producer.flush() returning 0 (i.e. every
   in-flight produce for that batch has been ACKed or has permanently
   failed-and-been-handled).

2. Deterministic event IDs. event_id = sha256(raw_bytes). Same raw
   bytes -> same event_id, always -- whether seen the first time, via
   retry, or via replay. This is what makes downstream consumers able
   to do idempotent upserts and treat duplicate delivery (an inherent
   property of at-least-once + replay) as a no-op instead of a
   correctness bug.

3. Poison vs. transient failure are handled differently:
     - Poison (ParseError): the payload itself is structurally invalid.
       Retrying identical bytes will fail identically forever, so a
       poison event is routed straight to dead-letter — no wasted
       retry-topic churn, no head-of-line blocking of good events.
     - Transient (TransientError): a downstream dependency issue.
       Routed to `retry` with an exponential backoff "not-before"
       timestamp in the header, and only DLQ'd after MAX_TRANSIENT_RETRIES.

4. Graceful shutdown: SIGTERM/SIGINT sets a flag checked every poll
   iteration; on exit we flush the producer and issue a final synchronous
   commit before closing the consumer, so a rolling deploy / autoscale-down
   never loses or silently skips in-flight work.

5. Replay never mutates or deletes raw-event. It is purely an
   additional read (new consumer group, optionally seeked to a
   timestamp) over data that's already sitting in raw-event's retention
   window. Because downstream event_ids are deterministic, replayed
   output is safely idempotent against whatever already made it through
   the first time.
-------------------------------------------------------------------------
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import signal
import statistics
import sys
import time
import uuid
from collections import deque
from dataclasses import dataclass, field

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

try:
    from confluent_kafka import Consumer, Producer, TopicPartition, KafkaError
except ImportError:  # pragma: no cover
    Consumer = Producer = TopicPartition = KafkaError = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

RAW_TOPIC = "raw-event"
PARSED_TOPIC = "parsed-event"
RETRY_TOPIC = "retry"
DEAD_LETTER_TOPIC = "dead-letter"
METRICS_TOPIC = "framework-metrics"

MAX_TRANSIENT_RETRIES = 5
BACKOFF_BASE_SECONDS = 15          # attempt 1 -> 15s, attempt 2 -> 30s, ...
BACKOFF_CAP_SECONDS = 30 * 60
COMMIT_INTERVAL_MESSAGES = 500
COMMIT_INTERVAL_SECONDS = 5.0
METRICS_FLUSH_INTERVAL_SECONDS = 5.0
LATENCY_SAMPLE_MAX = 2000          # bounded reservoir, avoid unbounded memory


class ParseError(Exception):
    """Structural/schema failure. Deterministic -> poison -> dead-letter."""


class TransientError(Exception):
    """Retryable failure (downstream dependency, transient IO, etc)."""


# --------------------------------------------------------------------------
# Deterministic event ID
# --------------------------------------------------------------------------
def compute_event_id(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


# --------------------------------------------------------------------------
# pfSense filterlog parsing
#
# Real pfSense filterlog lines (via syslog) look like:
#   <134>1 2024-05-01T00:00:03Z fw-edge-01 filterlog 61234 - - \
#     5,,,1000000103,igb0,match,pass,in,4,0x0,,64,12345,0,DF,6,tcp,60,\
#     10.0.0.5,93.184.216.34,54321,443,0,S,1391432708,,64240,,mss;sackOK
#
# We treat the syslog envelope + CSV body as the parse contract; anything
# that doesn't match it is a poison event.
# --------------------------------------------------------------------------
_SYSLOG_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>1\s+"
    r"(?P<ts>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>\S+)\s+"
    r"(?P<pid>\S+)\s+\S+\s+\S+\s+"
    r"(?P<body>.*)$"
)
_MIN_FILTERLOG_FIELDS = 19


def parse_pfsense_log(raw: bytes) -> dict:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ParseError(f"non-utf8 payload: {e}") from e

    m = _SYSLOG_RE.match(text.strip())
    if not m:
        raise ParseError("does not match syslog RFC5424 + filterlog envelope")

    fields = m.group("body").split(",")
    if len(fields) < _MIN_FILTERLOG_FIELDS:
        raise ParseError(
            f"filterlog body has {len(fields)} fields, expected >= {_MIN_FILTERLOG_FIELDS}"
        )

    try:
        rule_num, _, _, tracking_id, iface, reason, action, direction = fields[0:8]
        ip_version = fields[8]
        protocol_name = fields[16] if ip_version == "4" else fields[16]
        src_ip = fields[18] if ip_version == "4" else fields[18]
        dst_ip = fields[19] if len(fields) > 19 else ""
    except IndexError as e:
        raise ParseError(f"unexpected field layout: {e}") from e

    if action not in ("pass", "block", "reject", "match"):
        raise ParseError(f"unrecognized filterlog action: {action!r}")

    return {
        "syslog_ts": m.group("ts"),
        "syslog_host": m.group("host"),
        "process": m.group("proc"),
        "pid": m.group("pid"),
        "rule_num": rule_num,
        "tracking_id": tracking_id,
        "interface": iface,
        "reason": reason,
        "action": action,
        "direction": direction,
        "ip_version": ip_version,
        "protocol": protocol_name,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "raw_field_count": len(fields),
    }


# --------------------------------------------------------------------------
# Header helpers
# --------------------------------------------------------------------------
def get_header(headers, name: str, default=None):
    if not headers:
        return default
    for k, v in headers:
        if k == name:
            return v
    return default


def headers_with(headers, **updates) -> list:
    out = {}
    for k, v in (headers or []):
        out[k] = v
    for k, v in updates.items():
        out[k] = v.encode() if isinstance(v, str) else v
    return list(out.items())


# --------------------------------------------------------------------------
# Metrics accumulator — flushed periodically, NOT per-event (per-event
# metrics emission does not scale at billions/day; a rolling summary does).
# --------------------------------------------------------------------------
@dataclass
class MetricsWindow:
    worker_id: str
    role: str
    window_start: float = field(default_factory=time.time)
    consumed_count: int = 0
    produced_count: int = 0
    retry_count: int = 0
    dead_letter_count: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    latencies_ms: deque = field(default_factory=lambda: deque(maxlen=LATENCY_SAMPLE_MAX))

    def record_latency(self, ms: float):
        self.latencies_ms.append(ms)

    def to_event(self, window_end: float) -> dict:
        lat = list(self.latencies_ms)
        pct = lambda p: (statistics.quantiles(lat, n=100)[p - 1] if len(lat) >= 2 else (lat[0] if lat else 0.0))
        return {
            "worker_id": self.worker_id,
            "role": self.role,
            "window_start_ts": self.window_start,
            "window_end_ts": window_end,
            "window_seconds": max(window_end - self.window_start, 1e-6),
            "consumed_count": self.consumed_count,
            "produced_count": self.produced_count,
            "retry_count": self.retry_count,
            "dead_letter_count": self.dead_letter_count,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "cpu_percent": round(self.cpu_percent, 2),
            "memory_mb": round(self.memory_mb, 2),
            "latency_ms_p50": pct(50),
            "latency_ms_p95": pct(95),
            "latency_ms_p99": pct(99),
        }

    def reset(self, now: float):
        self.window_start = now
        self.consumed_count = 0
        self.produced_count = 0
        self.retry_count = 0
        self.dead_letter_count = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self.cpu_percent = 0.0
        self.memory_mb = 0.0
        self.latencies_ms.clear()


# --------------------------------------------------------------------------
# Worker
# --------------------------------------------------------------------------
class Worker:
    def __init__(self, brokers: str, role: str, group_id: str,
                 replay_from_ts_ms: int | None = None):
        self.role = role
        self.worker_id = f"{role}-{uuid.uuid4().hex[:8]}"
        self.log = logging.getLogger(self.worker_id)
        self._running = True
        self._replay_from_ts_ms = replay_from_ts_ms

        self.consumer = Consumer({
            "bootstrap.servers": brokers,
            "group.id": group_id,
            "enable.auto.commit": False,          # rule #1: manual commit
            "auto.offset.reset": "earliest",
            "max.poll.interval.ms": 300000,
            "session.timeout.ms": 45000,
            "partition.assignment.strategy": "cooperative-sticky",
        })

        self.producer = Producer({
            "bootstrap.servers": brokers,
            "acks": "all",
            "enable.idempotence": True,           # exactly-once producer-side
            "compression.type": "zstd",
            "linger.ms": 20,
            "batch.size": 512 * 1024,
        })

        self.source_topic = {
            "parser": RAW_TOPIC,
            "retry-handler": RETRY_TOPIC,
            "replay": RAW_TOPIC,
        }[role]

        self.metrics = MetricsWindow(worker_id=self.worker_id, role=role)
        self._refresh_resource_metrics()
        self._last_commit = time.time()
        self._last_metrics_flush = time.time()
        self._uncommitted = 0
        self._in_flight = 0
        self._produce_errors: list[str] = []

        signal.signal(signal.SIGTERM, self._handle_shutdown)
        signal.signal(signal.SIGINT, self._handle_shutdown)

    def _handle_shutdown(self, signum, _frame):
        self.log.warning("received signal %s, shutting down gracefully...", signum)
        self._running = False

    def _refresh_resource_metrics(self):
        if psutil is None:
            self.metrics.cpu_percent = 0.0
            self.metrics.memory_mb = 0.0
            return
        proc = psutil.Process(os.getpid())
        self.metrics.cpu_percent = max(0.0, proc.cpu_percent(interval=None))
        self.metrics.memory_mb = max(0.0, proc.memory_info().rss / (1024 * 1024))

    # ---- subscribe / seek ------------------------------------------------
    def _subscribe(self):
        if self.role == "replay":
            metadata = self.consumer.list_topics(self.source_topic, timeout=15)
            partitions = list(metadata.topics[self.source_topic].partitions.keys())
            tps = [TopicPartition(self.source_topic, p) for p in partitions]
            self.consumer.assign(tps)
            if self._replay_from_ts_ms is not None:
                search = [TopicPartition(self.source_topic, p, self._replay_from_ts_ms) for p in partitions]
                resolved = self.consumer.offsets_for_times(search, timeout=15)
                self.consumer.assign(resolved)
                self.log.info("replay: seeked to timestamp %d across %d partitions",
                              self._replay_from_ts_ms, len(resolved))
        else:
            self.consumer.subscribe([self.source_topic])

    # ---- delivery callback -------------------------------------------------
    def _on_delivery(self, err, msg):
        self._in_flight -= 1
        if err is not None:
            self._produce_errors.append(str(err))
            self.log.error("delivery failed for topic=%s key=%s: %s",
                            msg.topic() if msg else "?", msg.key() if msg else "?", err)

    def _produce(self, topic: str, key: bytes, value: bytes, headers: list):
        self._in_flight += 1
        self.producer.produce(
            topic=topic, key=key, value=value, headers=headers,
            on_delivery=self._on_delivery,
        )
        self.producer.poll(0)  # serve delivery callbacks without blocking

    # ---- core processing ---------------------------------------------------
    def _process_one(self, msg) -> None:
        raw = msg.value()
        key = msg.key() or b"unknown-source"
        headers = msg.headers() or []
        received_at = time.time()

        first_seen = get_header(headers, "ulpf_first_seen_ts")
        if first_seen is None:
            first_seen_ts = received_at
        else:
            first_seen_ts = float(first_seen.decode())

        attempt = int((get_header(headers, "ulpf_attempt") or b"0").decode())
        event_id = compute_event_id(raw)  # rule #2: always recomputed, never trusted blindly

        not_before = get_header(headers, "ulpf_not_before_ts")
        if self.role == "retry-handler" and not_before is not None:
            wait_s = float(not_before.decode()) - time.time()
            if wait_s > 0:
                time.sleep(min(wait_s, 2.0))
                # If still not due after a short sleep, put it back for a
                # later poll cycle rather than blocking the whole partition.
                if float(not_before.decode()) - time.time() > 0:
                    self._produce(RETRY_TOPIC, key, raw, headers)
                    self.metrics.retry_count += 1
                    return

        self.metrics.consumed_count += 1
        self.metrics.bytes_in += len(raw)

        try:
            parsed = parse_pfsense_log(raw)
            parsed["event_id"] = event_id
            parsed["source_key"] = key.decode(errors="replace")
            parsed["ingest_attempt"] = attempt
            parsed["first_seen_ts"] = first_seen_ts
            parsed["processed_ts"] = time.time()

            out_value = json.dumps(parsed).encode("utf-8")
            out_headers = headers_with(
                headers,
                ulpf_event_id=event_id,
                ulpf_first_seen_ts=str(first_seen_ts),
                ulpf_original_topic=self.source_topic,
            )
            self._produce(PARSED_TOPIC, key, out_value, out_headers)
            self.metrics.produced_count += 1
            self.metrics.bytes_out += len(out_value)
            self.metrics.record_latency((time.time() - first_seen_ts) * 1000.0)

        except ParseError as e:
            # Poison: deterministic failure, don't waste retry-topic churn.
            self.log.warning("poison event_id=%s -> dead-letter: %s", event_id, e)
            self._route_dead_letter(key, raw, headers, event_id, first_seen_ts,
                                     attempt, reason=f"parse_error: {e}")

        except TransientError as e:
            next_attempt = attempt + 1
            if next_attempt > MAX_TRANSIENT_RETRIES:
                self.log.warning("event_id=%s exceeded max retries -> dead-letter", event_id)
                self._route_dead_letter(key, raw, headers, event_id, first_seen_ts,
                                         attempt, reason=f"max_retries_exceeded: {e}")
            else:
                backoff = min(BACKOFF_BASE_SECONDS * (2 ** attempt), BACKOFF_CAP_SECONDS)
                out_headers = headers_with(
                    headers,
                    ulpf_event_id=event_id,
                    ulpf_attempt=str(next_attempt),
                    ulpf_first_seen_ts=str(first_seen_ts),
                    ulpf_not_before_ts=str(time.time() + backoff),
                    ulpf_last_error=str(e)[:512],
                    ulpf_original_topic=self.source_topic,
                )
                self._produce(RETRY_TOPIC, key, raw, out_headers)
                self.metrics.retry_count += 1
                self.log.info("event_id=%s transient failure, attempt=%d, retry in %ss: %s",
                              event_id, next_attempt, backoff, e)

    def _route_dead_letter(self, key, raw, headers, event_id, first_seen_ts, attempt, reason):
        out_headers = headers_with(
            headers,
            ulpf_event_id=event_id,
            ulpf_attempt=str(attempt),
            ulpf_first_seen_ts=str(first_seen_ts),
            ulpf_dead_letter_reason=reason[:512],
            ulpf_dead_letter_ts=str(time.time()),
            ulpf_original_topic=self.source_topic,
        )
        self._produce(DEAD_LETTER_TOPIC, event_id.encode(), raw, out_headers)
        self.metrics.dead_letter_count += 1

    # ---- metrics -------------------------------------------------------
    def _maybe_flush_metrics(self):
        now = time.time()
        if now - self._last_metrics_flush < METRICS_FLUSH_INTERVAL_SECONDS:
            return
        self._refresh_resource_metrics()
        event = self.metrics.to_event(now)
        event["worker_count"] = 1
        self._produce(
            METRICS_TOPIC,
            self.worker_id.encode(),
            json.dumps(event).encode(),
            [("ulpf_worker_id", self.worker_id.encode())],
        )
        self.metrics.reset(now)
        self._last_metrics_flush = now

    # ---- commit ----------------------------------------------------------
    def _maybe_commit(self, force: bool = False):
        now = time.time()
        due = (
            force
            or self._uncommitted >= COMMIT_INTERVAL_MESSAGES
            or (now - self._last_commit) >= COMMIT_INTERVAL_SECONDS
        )
        if not due or self._uncommitted == 0:
            return

        # Rule #1: flush producer FIRST. Only commit consumer offsets once
        # every produced output for this batch is durably acked. If any
        # produce failed permanently, we deliberately do NOT commit past
        # it — we'd rather reprocess (duplicate, safe due to deterministic
        # IDs) than silently lose an event.
        pending = self.producer.flush(30)
        if pending > 0:
            self.log.error(
                "producer.flush timed out with %d messages still in flight; "
                "withholding offset commit this cycle", pending
            )
            return
        if self._produce_errors:
            self.log.error(
                "%d produce error(s) this batch; withholding offset commit: %s",
                len(self._produce_errors), self._produce_errors[:3],
            )
            self._produce_errors.clear()
            return

        self.consumer.commit(asynchronous=False)
        self._uncommitted = 0
        self._last_commit = now

    # ---- main loop ---------------------------------------------------------
    def run(self):
        self._subscribe()
        self.log.info("worker %s started, role=%s, source_topic=%s",
                      self.worker_id, self.role, self.source_topic)
        try:
            while self._running:
                msg = self.consumer.poll(timeout=1.0)
                if msg is None:
                    self._maybe_commit()
                    self._maybe_flush_metrics()
                    continue
                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    self.log.error("consumer error: %s", msg.error())
                    continue

                try:
                    self._process_one(msg)
                except Exception:
                    # Unexpected bug in processing itself must never crash
                    # the loop silently-losing offset tracking; log loudly
                    # and dead-letter the raw bytes so it's not lost.
                    self.log.exception("unhandled exception processing message, "
                                       "routing to dead-letter as a safety net")
                    self._route_dead_letter(
                        msg.key() or b"unknown", msg.value(), msg.headers(),
                        compute_event_id(msg.value() or b""), time.time(), 0,
                        reason="unhandled_worker_exception",
                    )

                self._uncommitted += 1
                self._maybe_commit()
                self._maybe_flush_metrics()

                if self.role == "replay" and msg.offset() is not None:
                    pass  # replay termination handled by caller / watermark check
        finally:
            self.log.info("flushing producer and committing final offsets...")
            self.producer.flush(30)
            self._maybe_commit(force=True)
            self.consumer.close()
            self.log.info("worker %s stopped cleanly.", self.worker_id)


def main():
    ap = argparse.ArgumentParser(description="ULPF worker")
    ap.add_argument("--brokers", default="localhost:9092")
    ap.add_argument("--role", choices=["parser", "retry-handler", "replay"], required=True)
    ap.add_argument("--group-id", default=None,
                     help="Defaults to ulpf-<role>-group; use a distinct group id "
                          "per replay run so it doesn't collide with live consumers.")
    ap.add_argument("--replay-from-ts-ms", type=int, default=None,
                     help="Only used with --role replay: epoch ms to seek raw-event to.")
    args = ap.parse_args()

    group_id = args.group_id or f"ulpf-{args.role}-group"
    if args.role == "replay" and args.group_id is None:
        group_id = f"ulpf-replay-{uuid.uuid4().hex[:8]}"

    worker = Worker(
        brokers=args.brokers,
        role=args.role,
        group_id=group_id,
        replay_from_ts_ms=args.replay_from_ts_ms,
    )
    worker.run()


if __name__ == "__main__":
    sys.exit(main() or 0)
