"""Pipeline behavior at the analytical-store durability boundary."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.engine import ParsingEngine
from src.collection.archive import RawEventArchive
from src.collection.pipeline import CollectionPipeline
from src.collection.publisher import InMemoryPublisher
from src.normalization import UniversalNormalizer, default_registry
from src.pipeline.exporter import DataLakeExporter
from src.pipeline.runner import PipelineRunner, StorageWriteError
from src.storage.models import WriteResult


class FailingStore:
    def write_batch(self, events: list[dict]) -> WriteResult:
        return WriteResult(0, 0, 0, len(events), ("analytical store unavailable",))


def test_pipeline_never_reports_indexed_when_durable_write_fails(tmp_path: Path) -> None:
    archive = RawEventArchive(tmp_path / "raw")
    runner = PipelineRunner(
        collector=CollectionPipeline(publisher=InMemoryPublisher(), archive=archive),
        engine=ParsingEngine(Path("source_packs")),
        normalizer=UniversalNormalizer(default_registry()),
        store=FailingStore(),
        exporter=DataLakeExporter(tmp_path / "lake"),
    )

    with pytest.raises(StorageWriteError) as caught:
        runner.process(
            b"<34>Oct 11 22:14:15 server-1 sshd[42]: Failed password for alice",
            transport="file",
            source_id="store-failure-test",
        )

    assert caught.value.result.failed_count == 1
    assert len(list((tmp_path / "raw").glob("*.raw"))) == 1
