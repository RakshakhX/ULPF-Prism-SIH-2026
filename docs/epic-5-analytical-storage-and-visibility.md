# Epic 5: Analytical Storage and Unified Visibility

## Scope and Objectives

Epic 5 implements how validated `UnifiedEvent` (v1.0.0) records are indexed, queried, and visualized across heterogeneous perimeter and security devices. The current executable path includes Cisco ASA, Fortinet FortiGate, generic Linux Syslog and Suricata EVE JSON.

The deployed visibility stack is ClickHouse plus Grafana. ClickHouse keeps the complete normalized JSON alongside projected analytical columns; Grafana's datasource and dashboards are provisioned from repository files. The older OpenSearch template remains an optional integration artifact, not the primary Epic 5 store.

### Implemented assets

- `deploy/clickhouse/init/001_events.sql`: valid-event and quarantine tables.
- `src/storage/clickhouse.py`: batch writes, bound-parameter search, trace lookup and aggregations.
- `deploy/grafana/provisioning/`: immutable datasource and dashboard-provider configuration.
- `deploy/grafana/dashboards/ulpf-overview.json`: security and pipeline-health overview.
- `deploy/grafana/dashboards/ulpf-investigation.json`: event, parser, Source Pack and raw-hash drill-down.
- `source_packs/suricata/samples/`: 20 valid and 5 invalid fictional EVE records.

---

## 1. Analytical Storage Representation

Normalized records are written to `ulpf.events_v1`, a monthly partitioned `ReplacingMergeTree` ordered by observed time and event ID. Repeated event IDs are logically deduplicated, while invalid normalized records are written to `ulpf.quarantine_v1`. The full JSON remains available for lossless investigation, and frequently filtered fields are projected into typed columns.

### 1.1 Field Mapping and Indexing Strategy

| Schema Section | ClickHouse Representation | Indexing & Aggregation Strategy |
|---|---|---|
| `schema_version` | `keyword` | Exact match filtering |
| `event.id` | `keyword` | Unique document identifier & deduplication key |
| `event.category` | `keyword` | High-level categorization aggregation (`network`, `intrusion_detection`, `authentication`, `web`, `system`) |
| `event.type` | `keyword` | Sub-category filtering (`connection`, `signature_match`, `acl_match`) |
| `event.name` | `text` with `.keyword` (256) | Multi-field for tokenized search and terms aggregation |
| `event.message` | `text` (`security_message_analyzer`) | Tokenized message search with lowercase and word-delimiter graph |
| `time.observed_at` | `date` (`strict_date_time`) | Primary time-series sort and time-window bounding |
| `time.ingested_at` | `date` (`strict_date_time`) | Pipeline latency tracking (`ingested_at - observed_at`) |
| `time.normalized_at`| `date` (`strict_date_time`) | Worker processing latency tracking (`normalized_at - ingested_at`) |
| `source.ip` | `ip` | Native IPv4 / IPv6 indexing with CIDR subnet search support |
| `source.port` | `integer` (0–65535) | Port range and exact port matching |
| `destination.ip` | `ip` | Native IPv4 / IPv6 indexing with CIDR subnet search support |
| `destination.port` | `integer` (0–65535) | Service port filtering and top-destination-port aggregations |
| `observer.vendor` | `keyword` | Cross-vendor comparison and breakdown facets |
| `observer.product` | `keyword` | Device product breakdown facets |
| `observer.type` | `keyword` | Device classification (`firewall`, `ids`, `router`, `waf`, `vpn`, `proxy`) |
| `network.transport`| `keyword` | Transport protocol facet (`tcp`, `udp`, `icmp`, `gre`) |
| `network.direction`| `keyword` | Ingress/egress traffic breakdown (`inbound`, `outbound`, `internal`, `external`) |
| `network.bytes` | `long` | Volume throughput metric aggregations (`sum`, `avg`) |
| `network.packets` | `long` | Packet rate metric aggregations |
| `action.normalized`| `keyword` | Security decision facet (`allow`, `deny`, `block`, `detect`, `authenticate`) |
| `action.outcome` | `keyword` | Policy enforcement success/failure state (`success`, `failure`, `unknown`) |
| `severity.normalized` | `byte` (0–10) | Numeric threshold range queries (`>= 7` for High/Critical) |
| `severity.label` | `keyword` | Tiered severity distribution (`informational`, `low`, `medium`, `high`, `critical`) |
| `threat.name` | `text` with `.keyword` (256) | Threat intelligence search and signature occurrence counts |
| `threat.category` | `keyword` | Threat classification facet (`exploit`, `command_and_control`, `malware`) |
| `threat.confidence` | `float` (0.0–1.0) | High-confidence alert filtering (`>= 0.85`) |
| `traceability.raw_event_id` | `keyword` | Evidence envelope UUID reference |
| `traceability.raw_sha256` | `keyword` | Cryptographic evidence integrity verification lookup |
| `traceability.raw_event.content` | `text` (`index: false`) | Preserved raw string for inspection without token indexing overhead |
| `quality.status` | `keyword` | Normalization health auditing (`valid`, `partial`, `invalid`) |
| `quality.parsing_confidence` | `float` (0.0–1.0) | Parser quality monitoring |
| `extensions` | `flattened` | Dynamic vendor fields without mapping explosions |

---

## 2. Dashboard Fields & Filter Controls

The visibility layer provides a unified filter bar enabling analysts to isolate threats and anomalies without writing complex queries.

```
+-------------------------------------------------------------------------------------------------------------------------------+
|  TIME RANGE          VENDOR / PRODUCT       ACTION          SEVERITY       CATEGORY           IP / CIDR SEARCH                |
|  [ Last 1 Hour  v ]  [ All Vendors   v ]   [ All Actions v][ High+Crit v] [ All Categories v] [ 198.51.100.0/24           ]   |
+-------------------------------------------------------------------------------------------------------------------------------+
```

### Core Filter Dimensions
1. **Time Range**: Absolute date-time window or rolling presets (`Last 15m`, `Last 1h`, `Last 24h`, `Last 7d`).
2. **Vendor & Product Hierarchy**: Filter by vendor (e.g. `cisco`, `pfsense`, `suricata`, `juniper`) or specific product model.
3. **Action Filter**: Multi-select quick buttons for `allow`, `deny`, `block`, `detect`.
4. **Severity Level**: Multi-tier filter (`critical`, `high`, `medium`, `low`, `informational`).
5. **Source & Destination CIDR**: Direct IP (`10.0.0.5`) or subnet mask matching (`192.168.1.0/24`).
6. **Data Quality & Provenance**: Filter by `quality.status: partial` to discover unparsed attributes or parser warnings.

---

## 3. Minimal Actionable Dashboard Layout

```
+-----------------------------------------------------------------------------------------------------------------------+
|  ULPF PRISM UNIFIED VISIBILITY DASHBOARD                                         [Auto-refresh: 10s v] [Last 1 Hour v] |
+-----------------------------------------------------------------------------------------------------------------------+
|  FILTERS: [ Vendor: All v ] [ Action: All v ] [ Severity: All v ] [ Quality: All v ] [ Search: action:deny AND ...  ] |
+-----------------------------------------------------------------------------------------------------------------------+
|                                                                                                                       |
|  +------------------------+  +--------------------------+  +--------------------------+  +--------------------------+ |
|  |  TOTAL EVENTS          |  |  ALLOW VS. DENY RATIO    |  |  HIGH/CRITICAL SEVERITY  |  |  DATA QUALITY VALID      | |
|  |  1,428,950             |  |  78.4% Allow | 21.6% Deny|  |  1,248 (0.09%)           |  |  99.94% (82 partial)     | |
|  |  [ +12.4% vs last hr ] |  |  [====Allow===|==Deny==] |  |  [!! 14 critical alerts] |  |  [ 0 invalid records ]   | |
|  +------------------------+  +--------------------------+  +--------------------------+  +--------------------------+ |
|                                                                                                                       |
|  +------------------------------------------------------+  +--------------------------------------------------------+ |
|  |  PANEL 1: Events by Source (Vendor & Product)        |  |  PANEL 2: Severity Distribution Breakdown              | |
|  |  [Bar Chart / Treemap: Cisco ASA, pfSense, Suricata] |  |  [Donut / Stacked Bar: Info / Low / Med / High / Crit] | |
|  +------------------------------------------------------+  +--------------------------------------------------------+ |
|                                                                                                                       |
|  +------------------------------------------------------------------------------------------------------------------+ |
|  |  PANEL 3: Recent Events Stream (Live Normalized Stream Table)                                                    | |
|  |  [ Timestamp ] [ Severity ] [ Action ] [ Vendor / Product ] [ Src IP:Port ] -> [ Dst IP:Port ] [ Category/Name ]  | |
|  |  10:25:30Z   | HIGH       | DETECT   | Suricata / IDS    | 192.0.2.30:51888 -> 198.51.100.30:443 | C2 Traffic     | |
|  |  10:20:30Z   | MEDIUM     | DENY     | Cisco / ASA-FW    | 203.0.113.11:49321 -> 198.51.100.21:22| Drop Policy    | |
|  |  10:40:30Z   | MEDIUM     | DENY     | Juniper / Router  | 203.0.113.60:5353 -> 192.0.2.60:53    | ACL Violation  | |
|  +------------------------------------------------------------------------------------------------------------------+ |
|                                                                                                                       |
|  +-- [DRAWER / EXPANDABLE INSPECTOR PANEL (When Row Selected)] -----------------------------------------------------+ |
|  |  Event ID: c2d6e3f4... | Observed At: 2026-08-30T10:20:30Z | Raw Event ID: d3e7f405... (SHA256: 7ae0bc1f...)     | |
|  |  Parser: syslog_parser v1.0.0 | Source Pack: cisco_asa v1.0.0 | Confidence: 1.00                                   | |
|  |  [ Tab 1: Normalized JSON View ]  [ Tab 2: Raw Evidence Drill-Down ]  [ Tab 3: Quality & Field Provenance ]      | |
|  +------------------------------------------------------------------------------------------------------------------+ |
+-----------------------------------------------------------------------------------------------------------------------+
```

### Dashboard Panels
1. **Total Events KPI**: Real-time event counter with rolling delta indicator.
2. **Events by Source**: Visual distribution of incoming logs aggregated by `observer.vendor` and `observer.product`.
3. **Allowed vs. Denied Access Decisions**: Ratio of allowed connections against denied/blocked traffic for access control anomaly detection.
4. **Severity Distribution**: Tiered breakdown (`critical` > `high` > `medium` > `low` > `informational`).
5. **Recent Events Stream**: Live tabular grid displaying normalized timestamps, endpoints, actions, and severity with an expandable Raw Evidence & Provenance Inspector drawer.

---

## 4. Search and Filtering Query Expectations

The API uses bound ClickHouse query parameters for all caller-provided values. Grafana uses version-controlled SQL and escaped template variables. Supported dimensions include time, vendor, product, category, action, severity, quality, event ID and raw SHA-256.

- **Free text:** case-insensitive search over retained `normalized_json`.
- **Facets:** exact case-insensitive vendor, category, action, severity and quality filters.
- **Time:** inclusive start and exclusive end boundaries on `observed_at`.
- **Provenance:** parameterized event-ID and raw-SHA-256 lookup.
- **Bounded results:** API search limits are clamped to 500 records.
- **Dashboard health:** quarantine counts expose parse failures and storage-related dead-letter evidence.

## 5. Run the persistent visibility stack

```bash
docker compose up -d clickhouse ulpf-engine grafana
```

Open `http://localhost:3000`, sign in with `GRAFANA_ADMIN_USER` and `GRAFANA_ADMIN_PASSWORD`, then open the **ULPF Prism** folder. For local evaluation only, the Compose defaults are `admin` / `ulpf-admin`; set both variables before any shared deployment. Anonymous access and self-service sign-up are disabled.

The first start installs the pinned official ClickHouse datasource plugin. Air-gapped packaging must preload the same image and plugin version rather than downloading them at runtime.

---

## 6. Normalized Sample Fixtures

Representative schema-compliant sample files are located in `examples/visibility/`:
- `examples/visibility/cisco_asa_firewall_deny.json` (Cisco ASA Firewall Access Drop)
- `examples/visibility/suricata_ids_threat_alert.json` (Suricata IDS Log4j Exploit Detection)
- `examples/visibility/juniper_router_acl_deny.json` (Juniper SRX Router ACL Filter Discard)

All fixtures are verified by automated test suites against `schemas/unified-event-v1.schema.json`.
