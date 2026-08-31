#!/usr/bin/env python3
"""
metrics_report.py — ULPF scalability report generator

Consumes the `framework-metrics` topic, which workers populate with a
per-instance rolling summary every METRICS_FLUSH_INTERVAL_SECONDS (see
worker.py). This script aggregates those summaries over a chosen window
to answer the questions a scalability report needs:

  * input EPS   = sum(consumed_count) / wall-clock window seconds
  * output EPS  = sum(produced_count) / wall-clock window seconds
  * byte throughput in/out
  * end-to-end processing latency distribution (p50/p95/p99), computed
    from first_seen_ts (load-gen production time or first raw ingest)
    to processed_ts, and reported per-worker so you can see the effect
    of adding worker replicas / partitions on tail latency, not just
    on throughput.

Usage:
    python metrics_report.py --brokers localhost:9092 --duration-seconds 60

For a live view instead of a one-shot window, add --follow to keep
printing rolling stats every --duration-seconds until interrupted.

For raw consumer-lag numbers (a good live proxy for "are we falling
behind the load generator"), also run in parallel:
    rpk group describe ulpf-parser-group --brokers localhost:9092
  or, on plain Kafka:
    kafka-consumer-groups.sh --bootstrap-server localhost:9092 \\
        --describe --group ulpf-parser-group
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

FILE_DIR = Path(__file__).resolve().parent
if str(FILE_DIR) not in sys.path:
    sys.path.insert(0, str(FILE_DIR))

from benchmark_metrics import summarize_metrics_window

try:
    from confluent_kafka import Consumer
except ImportError:  # pragma: no cover
    Consumer = None

METRICS_TOPIC = "framework-metrics"


def run_window(consumer: Consumer, window_seconds: float) -> None:
    per_worker = defaultdict(lambda: {
        "consumed": 0, "produced": 0, "retried": 0, "dead_lettered": 0,
        "bytes_in": 0, "bytes_out": 0, "latencies": [],
        "cpu_percent": 0.0, "memory_mb": 0.0,
    })
    deadline = time.time() + window_seconds
    n_summaries = 0

    while time.time() < deadline:
        msg = consumer.poll(timeout=1.0)
        if msg is None or msg.error():
            continue
        try:
            evt = json.loads(msg.value())
        except (json.JSONDecodeError, TypeError):
            continue
        n_summaries += 1
        w = per_worker[evt.get("worker_id", "unknown")]
        w["consumed"] += evt.get("consumed_count", 0)
        w["produced"] += evt.get("produced_count", 0)
        w["retried"] += evt.get("retry_count", 0)
        w["dead_lettered"] += evt.get("dead_letter_count", 0)
        w["bytes_in"] += evt.get("bytes_in", 0)
        w["bytes_out"] += evt.get("bytes_out", 0)
        w["cpu_percent"] = max(w["cpu_percent"], float(evt.get("cpu_percent", 0.0)))
        w["memory_mb"] = max(w["memory_mb"], float(evt.get("memory_mb", 0.0)))
        for key in ("latency_ms_p50", "latency_ms_p95", "latency_ms_p99"):
            if key in evt:
                w["latencies"].append(evt[key])

    summary = summarize_metrics_window(per_worker, window_seconds)

    print("=" * 72)
    print(f"ULPF scalability report — window={window_seconds:.0f}s, "
          f"{summary['worker_count']} worker(s), {n_summaries} summaries")
    print("=" * 72)
    print(f"  input EPS       : {summary['input_eps']:,.1f} events/s")
    print(f"  output EPS      : {summary['output_eps']:,.1f} events/s")
    print(f"  retry EPS       : {summary['retry_eps']:,.1f} events/s")
    print(f"  dead-letter EPS : {summary['dead_letter_eps']:,.1f} events/s")
    print(f"  bytes in/s      : {summary['bytes_in_per_s']:,.0f} B/s")
    print(f"  bytes out/s     : {summary['bytes_out_per_s']:,.0f} B/s")
    print(f"  avg CPU usage   : {summary['cpu_percent_avg']:.1f}%")
    print(f"  avg memory      : {summary['memory_mb_avg']:.1f} MB")
    if summary["latency_p50_ms"]:
        print(f"  latency p50     : {summary['latency_p50_ms']:,.1f} ms")
        print(f"  latency p95     : {summary['latency_p95_ms']:,.1f} ms")
        print(f"  latency p99     : {summary['latency_p99_ms']:,.1f} ms")
    print("-" * 72)
    for worker_id, w in sorted(per_worker.items()):
        print(f"  {worker_id:<24} consumed={w['consumed']:>8} "
              f"produced={w['produced']:>8} retried={w['retried']:>6} "
              f"dlq={w['dead_lettered']:>5} cpu={w['cpu_percent']:.1f}% mem={w['memory_mb']:.1f}MB")
    print()


def main():
    ap = argparse.ArgumentParser(description="ULPF scalability report")
    ap.add_argument("--brokers", default="localhost:9092")
    ap.add_argument("--duration-seconds", type=float, default=60.0)
    ap.add_argument("--follow", action="store_true",
                     help="Keep printing a fresh window forever instead of exiting once.")
    args = ap.parse_args()

    if Consumer is None:
        raise RuntimeError(
            "confluent-kafka is required. Install the project dependencies with: "
            "python -m pip install -r requirements-dev.txt"
        )

    consumer = Consumer({
        "bootstrap.servers": args.brokers,
        "group.id": f"ulpf-metrics-report-{int(time.time())}",
        "enable.auto.commit": False,
        "auto.offset.reset": "latest",
    })
    consumer.subscribe([METRICS_TOPIC])

    try:
        run_window(consumer, args.duration_seconds)
        while args.follow:
            run_window(consumer, args.duration_seconds)
    except KeyboardInterrupt:
        pass
    finally:
        consumer.close()


if __name__ == "__main__":
    main()
