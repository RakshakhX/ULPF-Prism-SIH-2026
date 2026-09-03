"""Canonical in-process orchestration for every supported log source."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from core.engine import ParsingEngine
from src.collection.archive import RawEventArchive
from src.collection.pipeline import CollectionPipeline, IngestResult
from src.contracts import ParsedEvent, RawEventEnvelope
from src.normalization import UniversalNormalizer
from src.pipeline.exporter import DataLakeExporter
from src.storage.base import AnalyticalEventStore
from src.storage.models import WriteResult
from src.validation.result import ValidationResult
from src.validation.validate_unified_event import validate_event

Transport = Literal["udp", "tcp", "file", "api", "replay"]


class CollectionRejectedError(ValueError):
    """The collection boundary rejected an event before canonical processing."""

    def __init__(self, result: IngestResult) -> None:
        self.result = result
        super().__init__(result.reason or "collection rejected event")


class StorageWriteError(RuntimeError):
    """The normalized event could not be durably stored or quarantined."""

    def __init__(self, result: WriteResult) -> None:
        self.result = result
        super().__init__("; ".join(result.errors) or "analytical storage write failed")


@dataclass(frozen=True)
class PipelineResult:
    """Evidence and status returned after every real pipeline stage executes."""

    raw_event: RawEventEnvelope
    parsed: ParsedEvent
    unified: dict[str, Any]
    validation: ValidationResult
    stage_status: dict[str, str]

    def response(self) -> dict[str, Any]:
        """Stable API representation without discarding the normalized record."""

        return {
            "event_id": str(self.raw_event.event_id),
            "raw_sha256": self.raw_event.raw_sha256,
            "stages": dict(self.stage_status),
            "source_pack_id": self.parsed.source_pack_id,
            "unified_event": self.unified,
        }


class PipelineRunner:
    """Run collection, parsing, normalization, validation, and indexing."""

    def __init__(
        self,
        *,
        collector: CollectionPipeline,
        engine: ParsingEngine,
        normalizer: UniversalNormalizer,
        store: AnalyticalEventStore,
        exporter: DataLakeExporter,
    ) -> None:
        self.collector = collector
        self.engine = engine
        self.normalizer = normalizer
        self.store = store
        self.exporter = exporter

    @property
    def archive(self) -> RawEventArchive:
        return self.collector.archive

    @property
    def publisher(self):
        return self.collector.publisher

    def process(
        self,
        raw: bytes | str,
        *,
        transport: Transport,
        source_id: str,
        source_ip: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> PipelineResult:
        raw_bytes = raw.encode("utf-8") if isinstance(raw, str) else raw
        ingest = self.collector.ingest(
            raw_bytes,
            transport,
            source_ip=source_ip,
            source_id=source_id,
            metadata=metadata,
        )
        if not ingest.accepted or ingest.envelope is None:
            raise CollectionRejectedError(ingest)

        envelope = ingest.envelope
        parsed = self.engine.process(envelope)
        unified = self.normalizer.normalize(parsed)
        validation = validate_event(unified)
        if not validation.valid:
            unified["quality"]["status"] = "invalid"
            unified["quality"]["warnings"].extend(
                f"{issue.path}: {issue.message}" for issue in validation.issues
            )

        write_result = self.store.write_batch([unified])
        if write_result.failed_count:
            raise StorageWriteError(write_result)
        storage_status = "quarantined" if write_result.quarantine_count else "indexed"
        return PipelineResult(
            raw_event=envelope,
            parsed=parsed,
            unified=unified,
            validation=validation,
            stage_status={
                "collection": "accepted",
                "parsing": parsed.status.value,
                "normalization": unified["quality"]["status"],
                "validation": "valid" if validation.valid else "invalid",
                "storage": storage_status,
            },
        )

    def process_batch(
        self,
        raw_events: list[bytes | str],
        *,
        transport: Transport,
        source_id: str,
    ) -> list[PipelineResult]:
        results = [
            self.process(raw, transport=transport, source_id=source_id) for raw in raw_events
        ]
        self.exporter.export_events([result.unified for result in results])
        return results
