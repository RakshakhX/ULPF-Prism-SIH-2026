"""Explicit multi-vendor demonstration command: ``python -m src.pipeline.demo``."""

from __future__ import annotations

import json
from pathlib import Path

from core.engine import ParsingEngine
from src.collection.archive import RawEventArchive
from src.collection.pipeline import CollectionPipeline
from src.collection.publisher import InMemoryPublisher
from src.normalization import UniversalNormalizer, default_registry
from src.pipeline.exporter import DataLakeExporter
from src.pipeline.runner import PipelineResult, PipelineRunner
from src.pipeline.storage import AnalyticalVisibilityStore

SAMPLE_EVENTS: tuple[tuple[str, bytes], ...] = (
    (
        "cisco-edge-fw",
        b"<166>Oct 12 2023 14:23:01 edge-fw-01 : %ASA-4-106023: "
        b"Deny tcp src outside:203.0.113.11/49321 dst inside:198.51.100.21/22 "
        b'by access-group "outside_in"',
    ),
    (
        "fortinet-edge-fw",
        b'date=2026-08-30 time=14:20:00 devname="FGT-EDGE-01" '
        b'devid="FG100" logid="0000000013" type="traffic" subtype="forward" '
        b'level="notice" action="deny" srcip=10.0.0.1 dstip=10.0.0.2',
    ),
    (
        "linux-auth",
        b"<34>Oct 11 22:14:15 server-1 sshd[42]: Failed password for alice",
    ),
    ("future-device", b"future vendor unrecognized event preserved verbatim"),
)


def build_demo_runner(output_dir: Path) -> PipelineRunner:
    return PipelineRunner(
        collector=CollectionPipeline(
            publisher=InMemoryPublisher(),
            archive=RawEventArchive(output_dir / "raw-archive"),
        ),
        engine=ParsingEngine(Path("source_packs")),
        normalizer=UniversalNormalizer(default_registry()),
        store=AnalyticalVisibilityStore(),
        exporter=DataLakeExporter(output_dir / "exports"),
    )


def run_demonstration(output_dir: Path = Path("data/demo")) -> list[PipelineResult]:
    """Run fixtures only when explicitly invoked; application startup stays empty."""

    runner = build_demo_runner(output_dir)
    results = [
        runner.process(raw, transport="file", source_id=source_id)
        for source_id, raw in SAMPLE_EVENTS
    ]
    manifest = runner.exporter.export_events([result.unified for result in results])

    print("ULPF PRISM — CANONICAL MULTI-VENDOR PIPELINE DEMO")
    for index, result in enumerate(results, start=1):
        print(
            f"[{index}] event_id={result.raw_event.event_id} "
            f"pack={result.parsed.source_pack_id or 'unrecognized'} "
            f"parse={result.parsed.status.value} "
            f"quality={result.unified['quality']['status']} "
            f"sha256={result.raw_event.raw_sha256[:16]}..."
        )
    print("Aggregations:")
    print(json.dumps(runner.store.get_aggregations(), indent=2))
    print("Export manifest:")
    print(json.dumps(manifest, indent=2))
    return results


if __name__ == "__main__":
    run_demonstration()
