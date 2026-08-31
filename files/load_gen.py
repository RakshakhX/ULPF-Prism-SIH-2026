#!/usr/bin/env python3
"""
load_gen.py — ULPF synthetic pfSense log load generator

Produces mock pfSense `filterlog` syslog messages to `raw-event`, keyed by
a synthetic source device identity (matching the worker's partitioning
strategy — see setup_topics.py). Designed for benchmarking the pipeline
under realistic-but-controllable conditions:

  * sustained EPS with periodic bursts (token-bucket-ish pacing)
  * malformed-event injection (poison events, to exercise dead-lettering)
  * duplicate-event injection (to exercise idempotent/dedup behavior)
  * timestamp jitter incl. occasional out-of-order / late-arriving events
  * a configurable pool of synthetic source devices/IPs

It also self-reports achieved EPS/throughput every second to stdout, since
"requested EPS" and "actually achievable EPS" diverge once you saturate a
broker or your own producer -- both numbers matter for a scalability report.
"""
from __future__ import annotations

import argparse
import random
import string
import sys
import time
from dataclasses import dataclass
from pathlib import Path

FILE_DIR = Path(__file__).resolve().parent
if str(FILE_DIR) not in sys.path:
    sys.path.insert(0, str(FILE_DIR))

from benchmark_metrics import summarize_metrics_window

try:
    from confluent_kafka import Producer
except ImportError:  # pragma: no cover
    Producer = None

RAW_TOPIC = "raw-event"

ACTIONS = ["pass", "block", "reject", "match"]
PROTOCOLS = [("tcp", 6), ("udp", 17), ("icmp", 1)]
INTERFACES = ["igb0", "igb1", "igb2", "vlan10", "vlan20", "wan"]
DIRECTIONS = ["in", "out"]


@dataclass
class Source:
    hostname: str
    ip: str


def make_sources(n: int) -> list[Source]:
    sources = []
    for i in range(n):
        octet_c = (i // 254) % 254 + 1
        octet_d = (i % 254) + 1
        sources.append(Source(hostname=f"fw-edge-{i:05d}", ip=f"10.{octet_c}.{octet_d}.1"))
    return sources


def random_public_ip() -> str:
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def format_syslog_ts(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def build_filterlog_line(src: Source, ts: float, rule_num: int = None) -> str:
    """Build one well-formed RFC5424-ish pfSense filterlog line."""
    action = random.choice(ACTIONS)
    direction = random.choice(DIRECTIONS)
    iface = random.choice(INTERFACES)
    proto_name, proto_num = random.choice(PROTOCOLS)
    src_ip = src.ip
    dst_ip = random_public_ip()
    src_port = random.randint(1024, 65535)
    dst_port = random.choice([80, 443, 22, 53, 3389, 8080, random.randint(1, 65535)])
    tracking_id = random.randint(1_000_000_000, 1_999_999_999)
    rule_num = rule_num if rule_num is not None else random.randint(0, 500)

    fields = [
        str(rule_num), "", "", str(tracking_id), iface, "match", action, direction,
        "4", "0x0", "", "64", str(random.randint(1, 65535)), "0", "DF",
        str(proto_num), proto_name, "60",
        src_ip, dst_ip, str(src_port), str(dst_port), "0", "S",
        str(random.randint(1_000_000_000, 4_000_000_000)), "", "64240", "",
        "mss;sackOK;TS;nop;wscale",
    ]
    body = ",".join(fields)
    pri = 134
    return f"<{pri}>1 {format_syslog_ts(ts)} {src.hostname} filterlog {random.randint(100,99999)} - - {body}"


def build_fortinet_line(src: Source, ts: float, *, target_size: int | None = None) -> str:
    """Generate a Fortinet-like event for synthetic multi-vendor benchmarking."""
    event = (
        f"date={format_syslog_ts(ts)} time={format_syslog_ts(ts)} "
        f"device_name={src.hostname} src={src.ip} dst={random_public_ip()} "
        f"action={random.choice(['allow', 'deny', 'detect'])} "
        f"proto={random.choice(['tcp', 'udp'])} sport={random.randint(1024, 65535)} "
        f"dport={random.choice([80, 443, 22, 53])} status={random.choice(['success', 'blocked'])} "
        f"msg='session {random.randint(1000, 9999)}'"
    )
    return _resize_payload(event, target_size)


def build_generic_syslog_line(src: Source, ts: float, *, target_size: int | None = None) -> str:
    """Generate a Linux syslog-like event for mixed-vendor benchmark scenarios."""
    event = (
        f"{format_syslog_ts(ts)} {src.hostname} kernel: "
        f"{random.choice(['ALERT', 'NOTICE', 'INFO'])} "
        f"src={src.ip} dst={random_public_ip()} "
        f"proto={random.choice(['tcp', 'udp', 'icmp'])} "
        f"action={random.choice(['accepted', 'rejected', 'dropped'])} "
        f"rule={random.randint(1, 500)}"
    )
    return _resize_payload(event, target_size)


def _resize_payload(payload: str, target_size: int | None) -> str:
    if target_size is None or target_size <= 0:
        return payload
    if len(payload.encode("utf-8")) <= target_size:
        padding = ("x" * (target_size - len(payload.encode("utf-8"))))
        return payload + padding
    return payload[: max(1, target_size - 32)]


def build_event_for_vendor(vendor: str, src: Source, ts: float, *, target_size: int | None = None) -> str:
    """Dispatch to a vendor-specific event generator for benchmark flexibility."""
    vendor = (vendor or "pfsense").lower()
    if vendor == "pfsense":
        return _resize_payload(build_filterlog_line(src, ts), target_size)
    if vendor == "fortinet":
        return build_fortinet_line(src, ts, target_size=target_size)
    if vendor in {"linux", "generic-linux", "syslog"}:
        return build_generic_syslog_line(src, ts, target_size=target_size)
    return _resize_payload(build_filterlog_line(src, ts), target_size)


def corrupt(line: str) -> str:
    """Produce a plausibly-malformed variant to exercise poison-event handling."""
    mode = random.choice(["truncate", "garbage_field", "encoding", "empty", "wrong_header"])
    if mode == "truncate":
        cut = random.randint(10, max(11, len(line) - 10))
        return line[:cut]
    if mode == "garbage_field":
        parts = line.split(",")
        if len(parts) > 5:
            idx = random.randint(1, len(parts) - 1)
            parts[idx] = "".join(random.choices(string.punctuation, k=6))
        return ",".join(parts)
    if mode == "encoding":
        return line + "\xff\xfe\x00broken"
    if mode == "empty":
        return ""
    if mode == "wrong_header":
        return line.replace("<134>1", "NOT-A-SYSLOG-HEADER", 1)
    return line


class RateController:
    """
    Alternates between a sustained EPS baseline and periodic bursts.
    e.g. --sustained-eps 2000 --burst-eps 20000 --burst-every-seconds 60
    --burst-duration-seconds 5 means: 2000 eps normally, spike to
    20000 eps for 5 seconds once a minute.
    """
    def __init__(self, sustained_eps: float, burst_eps: float,
                 burst_every_s: float, burst_duration_s: float):
        self.sustained_eps = sustained_eps
        self.burst_eps = burst_eps
        self.burst_every_s = burst_every_s
        self.burst_duration_s = burst_duration_s
        self.start = time.time()

    def current_target_eps(self) -> float:
        if self.burst_eps <= 0 or self.burst_every_s <= 0:
            return self.sustained_eps
        elapsed = time.time() - self.start
        phase = elapsed % self.burst_every_s
        if phase < self.burst_duration_s:
            return self.burst_eps
        return self.sustained_eps


def main():
    ap = argparse.ArgumentParser(description="ULPF synthetic load generator")
    ap.add_argument("--brokers", default="localhost:9092")
    ap.add_argument("--topic", default=RAW_TOPIC)
    ap.add_argument("--vendor", choices=["pfsense", "fortinet", "linux", "generic-linux", "syslog"], default="pfsense")
    ap.add_argument("--sustained-eps", type=float, default=1000.0)
    ap.add_argument("--burst-eps", type=float, default=0.0, help="0 disables bursting")
    ap.add_argument("--burst-every-seconds", type=float, default=60.0)
    ap.add_argument("--burst-duration-seconds", type=float, default=5.0)
    ap.add_argument("--event-size-bytes", type=int, default=0, help="0 disables size targeting")
    ap.add_argument("--malformed-pct", type=float, default=1.0, help="0-100")
    ap.add_argument("--duplicate-pct", type=float, default=2.0, help="0-100")
    ap.add_argument("--num-sources", type=int, default=500)
    ap.add_argument("--timestamp-jitter-seconds", type=float, default=3.0,
                     help="Max +/- jitter, occasional late arrivals for realism")
    ap.add_argument("--duration-seconds", type=float, default=0.0, help="0 = run forever")
    args = ap.parse_args()

    if Producer is None:
        raise RuntimeError(
            "confluent-kafka is required to run the load generator. Install the project dependencies with: "
            "python -m pip install -r requirements-dev.txt"
        )

    producer = Producer({
        "bootstrap.servers": args.brokers,
        "acks": "1",  # throughput-oriented for the generator; the pipeline's
                       # own durability comes from raw-event's replication + retention
        "compression.type": "zstd",
        "linger.ms": 10,
        "batch.size": 512 * 1024,
        "queue.buffering.max.messages": 500_000,
    })

    sources = make_sources(args.num_sources)
    rate = RateController(args.sustained_eps, args.burst_eps,
                          args.burst_every_seconds, args.burst_duration_seconds)

    last_line_by_source: dict[str, str] = {}

    sent_this_second = 0
    bytes_this_second = 0
    malformed_this_second = 0
    duplicate_this_second = 0
    second_start = time.time()
    run_start = time.time()

    def on_delivery(err, _msg):
        if err is not None:
            print(f"[load_gen] delivery error: {err}")

    print(f"[load_gen] starting: sustained={args.sustained_eps}eps "
          f"burst={args.burst_eps}eps every {args.burst_every_seconds}s "
          f"for {args.burst_duration_seconds}s, sources={args.num_sources}")

    try:
        while True:
            now = time.time()
            if args.duration_seconds and (now - run_start) >= args.duration_seconds:
                break

            target_eps = rate.current_target_eps()
            # Emit in small slices to stay responsive to burst transitions
            slice_s = 0.05
            n_events = max(1, int(target_eps * slice_s))

            for _ in range(n_events):
                src = random.choice(sources)
                is_duplicate = random.uniform(0, 100) < args.duplicate_pct
                if is_duplicate and src.hostname in last_line_by_source:
                    line = last_line_by_source[src.hostname]
                    duplicate_this_second += 1
                else:
                    jitter = random.uniform(-args.timestamp_jitter_seconds,
                                            args.timestamp_jitter_seconds)
                    line = build_event_for_vendor(
                        args.vendor,
                        src,
                        now + jitter,
                        target_size=args.event_size_bytes or None,
                    )
                    last_line_by_source[src.hostname] = line

                is_malformed = random.uniform(0, 100) < args.malformed_pct
                if is_malformed:
                    line = corrupt(line)
                    malformed_this_second += 1

                payload = line.encode("utf-8", errors="replace")
                producer.produce(
                    topic=args.topic,
                    key=src.hostname.encode(),
                    value=payload,
                    headers=[("ulpf_first_seen_ts", str(now).encode())],
                    on_delivery=on_delivery,
                )
                sent_this_second += 1
                bytes_this_second += len(payload)

            producer.poll(0)
            time.sleep(slice_s)

            if time.time() - second_start >= 1.0:
                elapsed = time.time() - second_start
                print(
                    f"[load_gen] t={int(time.time()-run_start):>5}s "
                    f"target_eps={target_eps:>7.0f} "
                    f"actual_eps={sent_this_second/elapsed:>7.1f} "
                    f"bytes/s={bytes_this_second/elapsed:>9.0f} "
                    f"malformed={malformed_this_second} duplicate={duplicate_this_second}"
                )
                sent_this_second = 0
                bytes_this_second = 0
                malformed_this_second = 0
                duplicate_this_second = 0
                second_start = time.time()

    except KeyboardInterrupt:
        print("[load_gen] interrupted, flushing...")
    finally:
        producer.flush(30)
        print("[load_gen] done.")


if __name__ == "__main__":
    main()
