# Optional OpenSearch integration target

This profile demonstrates delivery of `UnifiedEvent` records to the OpenSearch Bulk API. OpenSearch provides indexing and search; it is not presented as a complete SIEM. Alerting, case management, correlation content, retention policy and operational security remain deployment responsibilities.

Start the local-only evaluation profile:

```bash
docker compose --profile siem-search up -d opensearch opensearch-init
```

The profile pins OpenSearch 3.8.0, binds port 9200 only to loopback, persists data in a named volume and installs `schemas/opensearch-index-template-v1.json`. It disables the Security plugin strictly for a laptop demonstration. Do not expose this configuration to another host or network. A shared deployment must enable authentication and TLS and size heap, shards, replicas and retention for its actual workload.

Recommended local minimum: 2 CPU cores and 2 GiB available memory. The configured JVM heap is 512 MiB to keep the optional SIH demonstration lightweight; it is not a production sizing claim.
