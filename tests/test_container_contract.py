from __future__ import annotations

import shlex
from pathlib import Path

import yaml

COMPOSE = Path("docker-compose.yml")


def _compose() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


def test_image_packages_all_runtime_code_and_runs_non_root() -> None:
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")

    for required in ["COPY core/", "COPY src/", "COPY schemas/", "COPY source_packs/"]:
        assert required in dockerfile
    assert "USER ulpf" in dockerfile
    assert "COPY tests/" not in dockerfile
    assert "pyarrow==25.0.1" in Path("requirements.txt").read_text(encoding="utf-8")


def test_compose_declares_complete_pipeline_roles() -> None:
    services = _compose()["services"]

    assert {
        "redpanda",
        "topic-init",
        "collector",
        "parser-worker",
        "normalizer-worker",
        "retry-worker",
        "sink",
        "ulpf-engine",
        "clickhouse",
        "grafana",
    } <= set(services)

    application_roles = [
        "collector",
        "parser-worker",
        "normalizer-worker",
        "retry-worker",
        "sink",
        "ulpf-engine",
    ]
    assert {services[name]["image"] for name in application_roles} == {"ulpf-engine:0.1.0"}
    for name in application_roles:
        dependency = services[name]["depends_on"]["topic-init"]
        assert dependency["condition"] == "service_completed_successfully"


def test_redpanda_and_topic_initialization_are_pinned_and_durable() -> None:
    compose = _compose()
    services = compose["services"]
    broker = services["redpanda"]

    assert broker["image"] == "docker.redpanda.com/redpandadata/redpanda:v26.2.1"
    assert "redpanda-data:/var/lib/redpanda/data" in broker["volumes"]
    assert "redpanda-data" in compose["volumes"]
    assert "healthcheck" in broker

    initializer = services["topic-init"]
    assert initializer["image"] == broker["image"]
    assert "./deploy/redpanda/init-topics.sh:/init-topics.sh:ro" in initializer["volumes"]


def test_broker_health_uses_admin_api_not_kafka_flags() -> None:
    # Health is an Admin API command: Kafka's --brokers flag prevents startup.
    command = shlex.split(_compose()["services"]["redpanda"]["healthcheck"]["test"][1])
    assert command[:3] == ["rpk", "cluster", "health"]
    assert "--brokers" not in command
    options = [command[i + 1] for i, value in enumerate(command[:-1]) if value == "-X"]
    assert "admin.hosts=127.0.0.1:9644" in options


def test_initializer_creates_all_canonical_topics_idempotently() -> None:
    script = Path("deploy/redpanda/init-topics.sh").read_text(encoding="utf-8")

    for topic in [
        "raw-event",
        "parsed-event",
        "normalized-event",
        "retry",
        "dead-letter",
        "framework-metrics",
    ]:
        assert topic in script
    assert "--if-not-exists" in script


def test_build_context_excludes_local_and_generated_data() -> None:
    ignored = Path(".dockerignore").read_text(encoding="utf-8")

    for entry in [".git", ".venv", "__pycache__", "data", ".pytest_cache"]:
        assert entry in ignored


def test_consumer_group_workers_can_be_scaled_without_fixed_container_names() -> None:
    services = _compose()["services"]
    for role in ("parser-worker", "normalizer-worker", "retry-worker", "sink"):
        assert "container_name" not in services[role], f"{role} would reject compose --scale"
