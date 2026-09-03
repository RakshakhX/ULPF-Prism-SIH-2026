from __future__ import annotations

import base64
import importlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from core.engine import ParsingEngine
from src.collection.archive import RawEventArchive
from src.collection.pipeline import CollectionPipeline
from src.collection.publisher import InMemoryPublisher
from src.normalization import UniversalNormalizer, default_registry
from src.pipeline.exporter import DataLakeExporter
from src.pipeline.runner import PipelineRunner
from src.pipeline.storage import AnalyticalVisibilityStore


@pytest.fixture
def real_runner(tmp_path: Path) -> PipelineRunner:
    archive = RawEventArchive(tmp_path / "raw")
    publisher = InMemoryPublisher()
    collector = CollectionPipeline(publisher=publisher, archive=archive)
    return PipelineRunner(
        collector=collector,
        engine=ParsingEngine(Path("source_packs")),
        normalizer=UniversalNormalizer(default_registry()),
        store=AnalyticalVisibilityStore(),
        exporter=DataLakeExporter(tmp_path / "lake"),
    )


@pytest.mark.parametrize(
    ("raw", "expected_pack", "expected_vendor"),
    [
        (
            b"<166>Oct 12 2023 14:23:01 asa-fw1 : %ASA-4-106023: "
            b"Deny tcp src outside:203.0.113.5/54321 dst inside:10.0.0.5/443 "
            b'by access-group "OUTSIDE_IN"',
            "cisco_asa",
            "Cisco",
        ),
        (
            b'date=2026-08-30 time=14:20:00 devname="FGT-EDGE-01" '
            b'devid="FG100" logid="0000000013" type="traffic" '
            b'subtype="forward" level="notice" action="deny" '
            b"srcip=10.0.0.1 dstip=10.0.0.2",
            "fortinet_fortigate",
            "Fortinet",
        ),
        (
            b"<34>Oct 11 22:14:15 server-1 sshd[42]: Failed password for alice",
            "generic_linux_syslog",
            "Generic",
        ),
    ],
)
def test_real_runner_executes_every_stage_for_each_vendor(
    real_runner: PipelineRunner,
    raw: bytes,
    expected_pack: str,
    expected_vendor: str,
) -> None:
    result = real_runner.process(raw, transport="file", source_id="demo-device")

    assert real_runner.archive.verify(result.raw_event.event_id)
    assert result.parsed.raw_event == result.raw_event
    assert result.parsed.source_pack_id == expected_pack
    assert result.unified["observer"]["vendor"] == expected_vendor
    assert result.unified["traceability"]["raw_sha256"] == result.raw_event.raw_sha256
    assert result.validation.valid
    assert real_runner.store.get_by_id(str(result.raw_event.event_id)) == result.unified
    assert result.stage_status == {
        "collection": "accepted",
        "parsing": result.parsed.status.value,
        "normalization": result.unified["quality"]["status"],
        "validation": "valid",
        "storage": "indexed",
    }


def test_unknown_binary_event_remains_lossless_and_analytics_visible(
    real_runner: PipelineRunner,
) -> None:
    raw = b"\xff\x00future-vendor\xfe"

    result = real_runner.process(raw, transport="udp", source_id="future-appliance")

    assert result.raw_event.raw_bytes() == raw
    assert result.parsed.raw_event.raw_bytes() == raw
    assert result.unified["quality"]["status"] == "unknown"
    assert result.validation.valid
    assert real_runner.archive.verify(result.raw_event.event_id)


def test_batch_uses_real_pipeline_and_exports_all_results(real_runner: PipelineRunner) -> None:
    results = real_runner.process_batch(
        [
            b"<34>Oct 11 22:14:15 server-1 sshd[42]: Accepted password for alice",
            b"future vendor unrecognized record",
        ],
        transport="file",
        source_id="batch-fixture",
    )

    assert len(results) == 2
    assert all(real_runner.archive.verify(result.raw_event.event_id) for result in results)
    manifest = real_runner.exporter.base_dir / "ulpf_lake_manifest.json"
    assert manifest.exists()


def test_universal_api_accepts_text_and_returns_stage_status(
    real_runner: PipelineRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import main

    monkeypatch.setattr(main, "pipeline_runner", real_runner)
    client = TestClient(main.app)
    response = client.post(
        "/v1/events",
        json={
            "raw_text": "<34>Oct 11 22:14:15 server-1 sshd[42]: Failed password for alice",
            "source_id": "api-linux",
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["source_pack_id"] == "generic_linux_syslog"
    assert body["stages"]["collection"] == "accepted"
    assert body["stages"]["validation"] == "valid"
    assert real_runner.archive.verify(body["event_id"])


def test_universal_api_accepts_lossless_base64_bytes(
    real_runner: PipelineRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import main

    monkeypatch.setattr(main, "pipeline_runner", real_runner)
    raw = b"\xff\x00binary-event\xfe"
    response = TestClient(main.app).post(
        "/v1/events",
        json={
            "raw_base64": base64.b64encode(raw).decode("ascii"),
            "source_id": "api-binary",
        },
    )

    assert response.status_code == 201
    archived = real_runner.archive.retrieve(response.json()["event_id"])
    assert archived is not None
    assert archived[1] == raw


@pytest.mark.parametrize(
    "request_body",
    [
        {"source_id": "missing-payload"},
        {"source_id": "two-payloads", "raw_text": "x", "raw_base64": "eA=="},
        {"source_id": "bad-base64", "raw_base64": "not base64!"},
        {"source_id": "empty-event", "raw_text": ""},
    ],
)
def test_universal_api_rejects_ambiguous_or_invalid_input(
    real_runner: PipelineRunner,
    monkeypatch: pytest.MonkeyPatch,
    request_body: dict[str, str],
) -> None:
    import main

    monkeypatch.setattr(main, "pipeline_runner", real_runner)

    response = TestClient(main.app).post("/v1/events", json=request_body)

    assert response.status_code == 422


def test_application_import_does_not_insert_demo_events(monkeypatch: pytest.MonkeyPatch) -> None:
    import main
    from src.pipeline.storage import global_visibility_store

    try:
        with monkeypatch.context() as isolated:
            isolated.delenv("ULPF_CLICKHOUSE_URL", raising=False)
            global_visibility_store.clear()
            importlib.reload(main)

            assert global_visibility_store.event_count == 0
            assert main.healthz()["indexed_events"] == 0
    finally:
        importlib.reload(main)
