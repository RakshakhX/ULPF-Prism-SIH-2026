#!/usr/bin/env bash
set -euo pipefail

broker="${ULPF_KAFKA_BROKERS:-redpanda:9092}"
partitions="${ULPF_TOPIC_PARTITIONS:-3}"

topics=(
  raw-event
  parsed-event
  normalized-event
  retry
  dead-letter
  framework-metrics
)

for topic in "${topics[@]}"; do
  rpk topic create "$topic" \
    --brokers "$broker" \
    --partitions "$partitions" \
    --replicas 1 \
    --if-not-exists
done
