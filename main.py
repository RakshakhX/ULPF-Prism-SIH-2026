"""FastAPI service for the vendor-agnostic ULPF Prism pipeline."""

from __future__ import annotations

import base64
import binascii
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, model_validator

from core.engine import ParsingEngine
from src.collection.archive import RawEventArchive
from src.collection.pipeline import CollectionPipeline
from src.collection.publisher import FileStreamPublisher
from src.contracts import ParsedEvent, RawEventEnvelope
from src.normalization import UniversalNormalizer, default_registry
from src.pipeline.dashboard_html import DASHBOARD_HTML
from src.pipeline.exporter import DataLakeExporter
from src.pipeline.runner import CollectionRejectedError, PipelineRunner, StorageWriteError
from src.pipeline.storage import global_visibility_store
from src.storage import ClickHouseEventStore, create_clickhouse_client
from src.storage.base import AnalyticalEventStore

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("ulpf.main")

PROJECT_ROOT = Path(__file__).parent
PACKS_DIR = PROJECT_ROOT / "source_packs"
DATA_DIR = Path(os.environ.get("ULPF_DATA_DIR", PROJECT_ROOT / "data"))


class EventIngestRequest(BaseModel):
    """One API event encoded as text or exact Base64 bytes."""

    model_config = ConfigDict(extra="forbid")

    raw_text: str | None = None
    raw_base64: str | None = None
    source_id: str = Field(min_length=1, max_length=256)
    source_ip: IPvAnyAddress | None = None
    transport: Literal["udp", "tcp", "file", "api", "replay"] = "api"
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def require_one_payload(self):
        if (self.raw_text is None) == (self.raw_base64 is None):
            raise ValueError("provide exactly one of raw_text or raw_base64")
        return self

    def payload_bytes(self) -> bytes:
        if self.raw_text is not None:
            return self.raw_text.encode("utf-8")
        try:
            return base64.b64decode(self.raw_base64 or "", validate=True)
        except (binascii.Error, ValueError) as error:
            raise ValueError("raw_base64 must be valid Base64") from error


def build_analytical_store(url: str | None = None) -> AnalyticalEventStore:
    """Select persistent storage when configured and zero-setup memory otherwise."""

    configured_url = os.environ.get("ULPF_CLICKHOUSE_URL", "") if url is None else url
    if not configured_url:
        return global_visibility_store
    return ClickHouseEventStore(create_clickhouse_client(configured_url))


analytical_store = build_analytical_store()


def build_default_runner(
    data_dir: Path = DATA_DIR,
    store: AnalyticalEventStore | None = None,
) -> PipelineRunner:
    """Compose production-facing services without inserting sample events."""

    archive = RawEventArchive(data_dir / "raw-archive")
    publisher = FileStreamPublisher(data_dir / "streams" / "raw-event.jsonl")
    return PipelineRunner(
        collector=CollectionPipeline(publisher=publisher, archive=archive),
        engine=ParsingEngine(PACKS_DIR),
        normalizer=UniversalNormalizer(default_registry()),
        store=store or analytical_store,
        exporter=DataLakeExporter(data_dir / "exports"),
    )


pipeline_runner = build_default_runner()
engine = pipeline_runner.engine
exporter = pipeline_runner.exporter

app = FastAPI(
    title="Universal Log Pre-processing Framework (ULPF Prism)",
    description=(
        "Lossless multi-vendor collection, parsing, normalization, visibility, "
        "and data-lake export service."
    ),
    version="1.0.0",
)


@app.get("/healthz")
def healthz():
    return {
        "status": "ok",
        "loaded_packs": len(engine.registry.packs),
        "indexed_events": analytical_store.event_count,
    }


@app.get("/dashboard", response_class=HTMLResponse)
def view_dashboard():
    """Render the unified analytical visibility dashboard."""

    return HTMLResponse(content=DASHBOARD_HTML)


@app.get("/packs")
def list_packs():
    return [
        {
            "pack_id": pack.pack_id,
            "vendor": pack.vendor,
            "product": pack.product,
            "pack_version": pack.pack_version,
            "priority": pack.priority,
            "format": pack.format_type,
        }
        for pack in engine.registry.packs
    ]


@app.post("/packs/reload")
def reload_packs():
    engine.reload_packs()
    return {"status": "reloaded", "loaded_packs": len(engine.registry.packs)}


@app.post("/v1/parse", response_model=ParsedEvent)
def parse_event(envelope: RawEventEnvelope):
    return engine.process(envelope)


@app.post("/v1/events", status_code=201)
def process_event(request: EventIngestRequest):
    """Execute the complete vendor-agnostic pipeline for one event."""

    try:
        payload = request.payload_bytes()
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    try:
        result = pipeline_runner.process(
            payload,
            transport=request.transport,
            source_id=request.source_id,
            source_ip=str(request.source_ip) if request.source_ip is not None else None,
            metadata=request.metadata,
        )
    except CollectionRejectedError as error:
        status_code = 413 if error.result.reason == "oversized_event" else 422
        raise HTTPException(status_code=status_code, detail=error.result.reason) from error
    except StorageWriteError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    return result.response()


@app.post("/v1/pipeline/cisco-asa", deprecated=True)
def process_cisco_asa_pipeline(
    raw_payload: str = Body(..., media_type="text/plain", description="Raw Cisco ASA Syslog line"),
):
    """Compatibility endpoint routed through the universal pipeline."""

    request = EventIngestRequest(raw_text=raw_payload, source_id="legacy-cisco-api")
    return process_event(request)


@app.get("/v1/analytics/events")
def get_analytics_events(
    query: str | None = Query(None, description="Free text or field query"),
    vendor: str | None = Query(None, description="Vendor filter"),
    category: str | None = Query(None, description="Event-category filter"),
    action: str | None = Query(None, description="Action filter"),
    severity: str | None = Query(None, description="Severity filter"),
    quality_status: str | None = Query(None, description="Quality status filter"),
    start_time: Annotated[
        datetime | None, Query(description="Inclusive observed-time boundary")
    ] = None,
    end_time: Annotated[
        datetime | None, Query(description="Exclusive observed-time boundary")
    ] = None,
    limit: int = Query(50, ge=1, le=500),
):
    events = analytical_store.search(
        query=query,
        vendor=vendor,
        category=category,
        action=action,
        severity=severity,
        quality_status=quality_status,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
    )
    return {"events": events, "aggregations": analytical_store.get_aggregations()}


@app.post("/v1/export/data-lake")
def export_data_lake():
    events = analytical_store.list_events(limit=1000)
    return exporter.export_events(events)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=False)
