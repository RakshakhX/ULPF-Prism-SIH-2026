"""Deployment contract tests for the persistent analytical store."""

from __future__ import annotations

from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _compose() -> dict:
    return yaml.safe_load((PROJECT_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))


def test_clickhouse_data_survives_container_recreation() -> None:
    """Removing the ClickHouse volume mount must break this test."""

    compose = _compose()
    clickhouse = compose["services"]["clickhouse"]

    assert clickhouse["image"].startswith("clickhouse/clickhouse-server:")
    assert not clickhouse["image"].endswith(":latest")
    assert "clickhouse-data:/var/lib/clickhouse" in clickhouse["volumes"]
    assert "clickhouse-data" in compose["volumes"]


def test_clickhouse_schema_is_initialized_before_engine_starts() -> None:
    """Removing initialization or readiness ordering must break this test."""

    compose = _compose()
    services = compose["services"]
    clickhouse = services["clickhouse"]
    engine = services["ulpf-engine"]

    assert "./deploy/clickhouse/init:/docker-entrypoint-initdb.d:ro" in clickhouse["volumes"]
    assert clickhouse["healthcheck"]["test"]
    assert engine["depends_on"]["clickhouse"]["condition"] == "service_healthy"
    assert engine["environment"]["ULPF_CLICKHOUSE_URL"].startswith("http://")
