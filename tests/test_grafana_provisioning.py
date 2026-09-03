"""Executable contracts for repository-provisioned unified visibility."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DASHBOARDS = ROOT / "deploy/grafana/dashboards"


def _dashboards() -> list[dict]:
    return [json.loads(path.read_text(encoding="utf-8")) for path in DASHBOARDS.glob("*.json")]


def test_datasource_and_dashboard_provider_use_stable_identifiers() -> None:
    datasource = yaml.safe_load(
        (ROOT / "deploy/grafana/provisioning/datasources/clickhouse.yaml").read_text()
    )["datasources"][0]
    provider = yaml.safe_load(
        (ROOT / "deploy/grafana/provisioning/dashboards/default.yaml").read_text()
    )["providers"][0]

    assert datasource["uid"] == "ulpf-clickhouse"
    assert datasource["type"] == "grafana-clickhouse-datasource"
    assert datasource["jsonData"]["protocol"] == "http"
    assert datasource["jsonData"]["port"] == 8123
    assert datasource["secureJsonData"]["password"] == "$ULPF_CLICKHOUSE_PASSWORD"
    assert provider["options"]["path"] == "/var/lib/grafana/dashboards"


def test_dashboards_cover_required_visibility_and_provenance() -> None:
    dashboards = _dashboards()
    titles = {panel["title"] for dashboard in dashboards for panel in dashboard["panels"]}
    required = {
        "Total events",
        "Events over time",
        "Allow vs deny",
        "Severity",
        "Parse failures",
        "Dead letters",
        "Raw SHA-256",
    }

    assert len(dashboards) == 2
    assert required <= titles
    assert all(dashboard["schemaVersion"] >= 39 for dashboard in dashboards)
    assert all(dashboard["uid"] for dashboard in dashboards)

    all_queries = "\n".join(
        target.get("rawSql", "")
        for dashboard in dashboards
        for panel in dashboard["panels"]
        for target in panel.get("targets", [])
    )
    for field in (
        "event_id",
        "raw_sha256",
        "source_pack_name",
        "source_pack_version",
        "parser_name",
        "parser_version",
    ):
        assert field in all_queries


def test_dashboards_offer_common_cross_vendor_filters() -> None:
    for dashboard in _dashboards():
        variables = {item["name"] for item in dashboard["templating"]["list"]}
        assert {"vendor", "product", "category", "action", "severity", "quality"} <= variables
        assert dashboard["time"]["from"] == "now-1h"


def test_compose_runs_pinned_secured_grafana_with_read_only_provisioning() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    grafana = compose["services"]["grafana"]

    assert grafana["image"] == "grafana/grafana:13.2.0"
    assert grafana["environment"]["GF_PLUGINS_PREINSTALL"] == (
        "grafana-clickhouse-datasource@4.20.0"
    )
    assert grafana["environment"]["GF_AUTH_ANONYMOUS_ENABLED"] == "false"
    assert grafana["depends_on"]["clickhouse"]["condition"] == "service_healthy"
    assert "./deploy/grafana/provisioning:/etc/grafana/provisioning:ro" in grafana["volumes"]
    assert "./deploy/grafana/dashboards:/var/lib/grafana/dashboards:ro" in grafana["volumes"]
    assert "grafana-data:/var/lib/grafana" in grafana["volumes"]
    assert "grafana-data" in compose["volumes"]
