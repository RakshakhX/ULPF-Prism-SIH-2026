# Epic 4: Streaming Backbone and Worker Execution Model

## Scope and status

This Epic focuses on the durable streaming layer required for horizontal scaling, backpressure control, retry handling, replay, and durable event processing.

The repository now includes the core backbone artifacts:

- topic bootstrap and partition configuration in `files/setup_topics.py`
- Kafka-style worker runner in `files/worker.py`
- canonical-envelope, multi-vendor load generator in `files/load_gen.py`
- transport-independent decisions and Kafka adapter in `src/streaming/`
- metrics aggregation in `files/metrics_report.py`
- local Redpanda benchmark stack in `files/docker-compose.yml`

This document records the design, assumptions, benchmark template, and validation approach. It does not claim untested billion-event throughput.

## Streaming topics

The framework provisions the following topics:

- raw-event
- parsed-event
- normalized-event
- retry
- dead-letter
- framework-metrics

Retention and compression settings are intentionally tuned for durable replay and operational observability. Raw events are retained as the source-of-truth for replay. Retry and dead-letter topics are separate to avoid blocking source ordering on poison or transient failures.

## Partitioning model

Partition key choice:

- raw-event: source identity (device or host)
- parsed-event / normalized-event: canonical event ID
- retry / dead-letter: event ID
- framework-metrics: worker ID

This preserves per-source ordering while preventing one poison event from head-of-line blocking an entire source stream.

Partition count assumptions:

- raw-event, parsed-event, normalized-event: 48 partitions
- retry: 12 partitions
- dead-letter: 6 partitions
- framework-metrics: 6 partitions

A worker group can only consume as many partitions in parallel as there are assigned partitions, so partition count is the ceiling on consumer parallelism for a given topic.

## Worker execution model

The worker runner supports four roles:

- parser
- normalizer
- retry-handler
- replay

The worker includes:

- manual offset commit after durable produce ack
- graceful shutdown via SIGINT/SIGTERM
- stable collector-assigned event IDs preserved across every stage
- raw SHA-256 retained independently for evidence integrity
- contract-invalid event routing to dead-letter
- transient failure routing to retry with backoff
- replay mode keyed to timestamp or offset range

## Reliability expectations

The streaming design is intended to tolerate:

- worker crashes
- worker restarts
- broker interruption
- duplicate delivery
- downstream slowdown
- retry exhaustion
- dead-letter routing
- backlog recovery

The code makes replay and idempotent downstream handling safe because the canonical envelope's event ID is preserved unchanged and the raw-event topic is retained as durable evidence.

## Synthetic load generator

The generator supports:

- configurable EPS
- burst mode
- malformed-event percentage
- duplicate-event percentage
- source variation
- timestamp jitter
- event-size targeting
- multiple vendor payload families (pfSense, Fortinet, generic syslog)

## Metrics and report model

The project records:

- input EPS
- output EPS
- retry EPS
- dead-letter EPS
- byte throughput
- latency percentiles
- average CPU usage
- average memory usage
- worker count

The required projection formula is:

Measured EPS per worker × effective worker count × safe utilization factor = projected cluster throughput

Where:

- measured EPS per worker is taken from a steady-state benchmark window
- effective worker count is the number of healthy replicas sharing partitions
- safe utilization factor is a conservative multiplier below 100% utilization to leave headroom for bursts and broker variance

## Benchmark and scaling template

A benchmark should include:

1. One-worker benchmark
2. Multi-worker benchmark
3. Scaling-efficiency calculation
4. Average vs peak workload comparison
5. Capacity headroom
6. Production node-count estimate
7. Known limitations and assumptions

The benchmark is intentionally scoped to the local environment and avoids claiming billion-scale results without measured evidence.

## Reliability and validation checklist

Required validation items include:

- multiple workers sharing partitions
- worker count increase improving available processing capacity
- accepted raw events not being lost on worker failure
- failed events reaching retry or dead-letter topics
- replay from a historical timestamp
- backlog visibility
- accepted / processed reconciliation
- sustained benchmark completion
- burst benchmark completion
- CPU, memory, latency and throughput all captured

## Production assumptions and limits

This design assumes:

- a Kafka-compatible broker such as Redpanda or Kafka is available
- worker counts remain below the partition count ceiling for the active topic
- durable retention for raw-event is enabled for replay and incident investigation
- measured values are workload-specific and should not be generalized across unrelated production environments

## Deliverables present in the repo

- streaming configuration
- topic definitions
- worker runner
- retry / dead-letter workflow
- replay mechanism
- synthetic load generator
- metrics collection
- benchmark scripts
- Docker Compose integration
- design notes for production scaling

## Next milestone

The remaining work for a full issue-completion signoff is operational verification in a live benchmark environment: run the stack, generate sustained and burst traffic, collect metrics, and confirm the reliability assertions against actual broker and worker behavior.
