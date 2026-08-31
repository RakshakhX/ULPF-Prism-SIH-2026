# ULPF — Universal Log Pre-processing Framework (streaming backbone)

## Architecture

```
load_gen.py ──► raw-event ──► worker.py --role parser ──► parsed-event
                    ▲                  │
                    │ (replay: new     ├──► retry (backoff) ──► worker.py --role retry-handler
                    │  consumer group, │                              │
                    │  same topic)     └──► dead-letter ◄─────────────┘
                    │
                    └── never mutated by replay — it's the durable source of truth

all roles ──► framework-metrics ──► metrics_report.py (EPS / bytes / latency)
```

`normalized-event` is provisioned by `setup_topics.py` for the next hop
(parsed-event -> normalized-event); it follows the identical worker
pattern shown in `worker.py` and is omitted here only because component 2
of the brief scoped the worker to raw -> parsed.

## Why these design choices

- **Partition key = source device identity** for raw/parsed/normalized
  (per-source ordering + partition affinity for hot caches), **event_id**
  for retry/dead-letter (so one poisoned event can't head-of-line-block
  a source's good traffic). Full rationale is in the `setup_topics.py`
  docstring.
- **Deterministic event IDs** (`sha256(raw_bytes)`) mean at-least-once
  delivery, retries, and replay are all safe — duplicate output is
  detectable and idempotent-upsertable downstream instead of a
  correctness problem.
- **Commit-after-produce-ack**: consumer offsets only advance once
  `producer.flush()` confirms every output for that batch is durably
  acked. This is the one rule that actually prevents raw-event data
  loss; see the `_maybe_commit` method in `worker.py`.
- **Poison vs. transient** are handled differently on purpose: poison
  (structurally invalid) events go straight to dead-letter since
  retrying identical bytes can't succeed; transient failures get
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
docker compose up -d --scale worker-parser=3 --scale worker-retry=2 \
    worker-parser worker-retry

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
| `worker.py` | Consumer-group worker: parse, retry-handler, and replay roles |
| `load_gen.py` | Synthetic pfSense filterlog generator with EPS/malformed/duplicate controls |
| `metrics_report.py` | Aggregates worker metrics into an EPS/throughput/latency report |
| `docker-compose.yml` | Redpanda + console + scalable workers + load-gen, all wired together |
| `Dockerfile` | Shared image for all Python components |
