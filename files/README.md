# ULPF — Universal Log Pre-processing Framework (streaming backbone)

## Architecture

```
load_gen.py ──► raw-event ──► parser ──► parsed-event ──► normalizer ──► normalized-event
                    ▲            │              │               │
                    │            ├──────────────┴──► retry ──────┤
                    │            │                 (stage-aware) │
                    │            └──────────────────► dead-letter ◄────────┘
                    │
                    └── replay reads the same immutable canonical envelopes

all roles ──► framework-metrics ──► metrics_report.py (EPS / bytes / latency)
```

Every hop validates the canonical input contract before processing. Raw,
parsed, normalized, retry, and dead-letter outputs retain the same event
identity, while the raw bytes and SHA-256 remain available through the
embedded raw envelope.

## Why these design choices

- **Source identity keys raw ingestion** for useful device-level
  distribution. Canonical worker outputs use **event ID** so downstream
  retry, replay, and idempotent upserts share one stable correlation key.
- **Stable event identity plus a separate SHA-256** avoids conflating two
  independently collected identical log lines. Retries and replay preserve
  the collector-assigned UUID; SHA-256 independently proves raw integrity.
- **Commit-after-produce-ack**: consumer offsets only advance once
  `producer.flush()` confirms every output for that batch is durably
  acked. This is the one rule that actually prevents raw-event data
  loss; see the `_maybe_commit` method in `worker.py`.
- **Poison vs. transient** are handled differently on purpose: poison
  (contract-invalid) events go straight to dead-letter since retrying
  identical bytes cannot succeed; transient dependency failures get
  exponential backoff via the `retry` topic and only reach dead-letter
  after `MAX_TRANSIENT_RETRIES`.
- **Replay is non-destructive**: it's the same processing pipeline
  pointed at raw-event under a fresh consumer group (optionally seeked
  to a timestamp with `--replay-from-ts-ms`). Nothing about raw-event's
  data or retention is touched.

## Running the benchmark

```bash
docker compose up -d redpanda redpanda-console
docker compose up topic-init                     # one-shot; exits 0

# Scale workers to however many replicas you want to benchmark:
docker compose up -d --scale worker-parser=3 --scale worker-normalizer=3 \
    --scale worker-retry=2 worker-parser worker-normalizer worker-retry

docker compose up -d load-gen
docker compose logs -f metrics-report
```

Redpanda Console: http://localhost:8080 — inspect topics, partition
distribution, consumer group lag, and dead-letter contents live.

## Measuring for a scalability report

Every worker replica emits a rolling summary (counts, bytes, latency
percentiles) to `framework-metrics` every 5s (see `MetricsWindow` in
`worker.py`) rather than one metrics event per processed message —
per-event metrics emission does not scale at billions-of-events/day
volumes, a periodic rollup does.

```bash
python metrics_report.py --brokers localhost:9092 --duration-seconds 60
```

reports aggregate input/output EPS, retry/DLQ EPS, byte throughput, and
p50/p95/p99 end-to-end latency (measured from `first_seen_ts`, stamped
at ingestion, to `processed_ts`).

For a live proxy of "is the pipeline keeping up with the load
generator", watch consumer lag directly:

```bash
docker compose exec redpanda rpk group describe ulpf-parser-group
```

To build a scalability curve: hold load-gen's EPS fixed, sweep
`--scale worker-parser=N` across N=1,2,3,6,12 (up to `raw-event`'s
partition count — 48 here, since partitions cap consumer parallelism),
and record steady-state input/output EPS and p99 latency from
`metrics_report.py` at each N. Plot EPS and p99 latency vs. N to show
where the pipeline stops scaling linearly (broker I/O saturation,
partition-count ceiling, or downstream produce backpressure).

## Files

| File | Purpose |
|---|---|
| `setup_topics.py` | Idempotent topic creation with partitioning/retention rationale |
| `worker.py` | Consumer-group worker: parser, normalizer, retry-handler, and replay roles |
| `load_gen.py` | Canonical-envelope, multi-vendor synthetic generator with load controls |
| `metrics_report.py` | Aggregates worker metrics into an EPS/throughput/latency report |
| `docker-compose.yml` | Redpanda + console + scalable workers + load-gen, all wired together |
| `Dockerfile` | Shared image for all Python components |
