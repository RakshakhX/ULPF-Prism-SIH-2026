# Local container stack

Run commands from the repository root. Install Docker with the Compose plugin,
start its daemon (Docker Desktop on macOS/Windows), then check `docker info`.
This is a single-host evaluation topology, not a production capacity claim.

## Build and start

```bash
docker compose config --quiet
docker compose build ulpf-engine
docker compose up -d
docker compose ps -a
docker compose logs --tail=100 topic-init collector parser-worker normalizer-worker sink
```

`topic-init` should exit successfully with code 0; it is a one-shot initializer,
not a continuously running service. It creates six topics: `raw-event`,
`parsed-event`, `normalized-event`, `retry`, `dead-letter`, and `framework-metrics`.
Topic existence does not imply a metrics publisher is implemented.

Parser, normalizer, retry and sink services have no fixed container names, so
Compose can create multiple consumers in the same stage-specific group:

```bash
docker compose up -d --scale parser-worker=2 --scale normalizer-worker=2
```

The default topics have three partitions, limiting active consumers per group
to three. This is a configuration capability, not a measured scaling result.

The API remains named `ulpf-engine` for compatibility with existing team commands.
All application roles use the same `ulpf-engine:0.1.0` image. The image runs as
the non-root `ulpf` user and contains runtime code, contracts and source packs.
Tests, local environments and generated data are excluded from the build context.

## Two entry paths

| Input | Current processing path |
| --- | --- |
| UDP 5514 / TCP 5601 | Collector archives raw evidence, then publishes to Redpanda; parser, normalizer and sink workers consume successive topics. |
| `POST /v1/events` on port 8080 | API uses the synchronous canonical runner: archive, local stream record, parsing, normalization and ClickHouse insertion. This endpoint does not enqueue to Redpanda. |

The collectors use the project's documented TCP framing and size limits, not
arbitrary packet capture. UDP itself provides no sender acknowledgement or
delivery guarantee. Workers commit input offsets only after their durable output
succeeds. An uncertain output causes the runtime to stop without committing that
input; container restart allows redelivery. This is at-least-once processing,
not an exactly-once delivery claim.

Retries pause only the affected partition until the recorded deadline. Other
partitions keep polling; held records remain uncommitted on shutdown/rebalance.
Malformed stage/deadline metadata is retained in the dead-letter topic. The
current scheduler accepts the default retry policy's maximum 30-minute horizon
(plus five seconds of clock tolerance); changing that policy requires changing
the scheduler bound too.

Open the API documentation at <http://localhost:8080/docs>, the application
dashboard at <http://localhost:8080/dashboard>, and Grafana at
<http://localhost:3000>. Local Grafana defaults are `admin` / `ulpf-admin`.

## Persistent data and stopping

Named volumes hold raw evidence/application data (`ulpf-data`), broker data,
ClickHouse data and Grafana data. Source packs are mounted read-only.

```bash
docker compose stop
docker compose start
```

Do not use `docker compose down --volumes` unless you intend to delete the named
volumes, including retained raw evidence. Source control does not back them up.

## Replay one archived event

Replace `EVENT_UUID` with an actual event ID returned by ingestion or found in
the archive. This verifies the archived bytes, hash and ID before republishing:

```bash
docker compose run --rm --no-deps collector python -m src.collection.replay --event-id EVENT_UUID
```

Repeat `--event-id` to select more events. Original IDs, ingestion timestamps,
transport metadata and payload are preserved; archive files are not modified.
The command reports attempted/published/failed counts and exits nonzero on any
failure. Republishing is intentional redelivery and can create downstream
duplicates; sinks must apply their documented idempotency behavior. Broker
offset/timestamp-range replay is not exposed by this command.

## Optional search target

See [OpenSearch integration](../deploy/opensearch/README.md) for the
`siem-search` profile. Starting that profile initializes a search target; it does
not currently start an OpenSearch delivery consumer. The tested bulk adapter
must still be wired to a transport/worker by the deployment.

## Evaluation limits and outstanding verification

- The broker uses one node and replication factor 1; it does not tolerate loss
  of that node's disk. Partition count is not a throughput benchmark.
- Local defaults are not hardened for shared networks. Do not use real sensitive
  logs or expose unauthenticated services; TLS, authentication and access control
  require a separate deployment configuration.
- Grafana currently downloads its pinned plugin during startup. Preparing an
  offline image/bundle is a remaining Milestone 4 task; this stack is not yet an
  air-gapped installation.
- Dependency constraints are not yet a complete hash-locked release dependency
  set. Offline/release packaging must lock and verify artifacts.
- Worker liveness and broker lag are not currently exposed as health endpoints;
  inspect process state and logs. An API health check is not worker readiness.
- The 2026-09-03 local verification ran unit/contract tests and Compose rendering.
  Image build and live broker-to-storage verification were not run because the
  Docker daemon was unavailable. Re-run those checks before presenting this as
  a demonstrated container deployment.

Implementation references: [Redpanda topic creation](https://docs.redpanda.com/streaming/current/reference/rpk/rpk-topic/rpk-topic-create/),
[Redpanda health](https://docs.redpanda.com/streaming/current/reference/rpk/rpk-cluster/rpk-cluster-health/),
and [Confluent Python client](https://docs.confluent.io/kafka-clients/python/current/overview.html).
