CREATE DATABASE IF NOT EXISTS ulpf;

CREATE TABLE IF NOT EXISTS ulpf.events_v1
(
    event_id UUID,
    observed_at DateTime64(6, 'UTC'),
    ingested_at DateTime64(6, 'UTC'),
    normalized_at DateTime64(6, 'UTC'),
    vendor LowCardinality(String),
    product LowCardinality(String),
    category LowCardinality(String),
    event_type LowCardinality(String),
    action LowCardinality(String),
    severity UInt8,
    severity_label LowCardinality(String),
    source_ip String,
    source_port Nullable(UInt16),
    destination_ip String,
    destination_port Nullable(UInt16),
    quality_status LowCardinality(String),
    raw_event_id UUID,
    raw_sha256 FixedString(64),
    source_pack_name LowCardinality(String),
    source_pack_version String,
    parser_name LowCardinality(String),
    parser_version String,
    normalized_json String
)
ENGINE = ReplacingMergeTree(normalized_at)
PARTITION BY toYYYYMM(observed_at)
ORDER BY (observed_at, event_id);

CREATE TABLE IF NOT EXISTS ulpf.quarantine_v1
(
    event_id String,
    raw_sha256 String,
    payload_json String,
    error_codes Array(String),
    quarantined_at DateTime64(6, 'UTC')
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(quarantined_at)
ORDER BY (quarantined_at, event_id);
