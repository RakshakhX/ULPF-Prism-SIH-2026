"""
main.py

FastAPI service for Universal Log Pre-processing Framework (ULPF Prism).
Provides parsing APIs, end-to-end Cisco ASA normalization pipeline,
interactive analytical visibility dashboard, and data-lake exporter.

Run locally:   uvicorn main:app --reload
Run in Docker: see Dockerfile (CMD runs uvicorn on 0.0.0.0:8080)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse

from core.engine import ParsingEngine
from core.models import ParsedEvent, RawEventEnvelope
from src.pipeline.dashboard_html import DASHBOARD_HTML
from src.pipeline.demo import SAMPLE_LOGS
from src.pipeline.exporter import DataLakeExporter
from src.pipeline.runner import CiscoASAPipelineRunner
from src.pipeline.storage import global_visibility_store

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("ulpf.main")

PACKS_DIR = Path(__file__).parent / "source_packs"

app = FastAPI(
    title="Universal Log Pre-processing Framework (ULPF Prism)",
    description="Unified log parsing, schema normalization, analytical visibility, and data-lake export service.",
    version="1.0.0",
)

engine = ParsingEngine(packs_dir=PACKS_DIR)
cisco_runner = CiscoASAPipelineRunner(store=global_visibility_store)
exporter = DataLakeExporter()

# Pre-populate sample events so visibility dashboard is immediately populated
for sample in SAMPLE_LOGS:
    cisco_runner.process_raw_log(sample)


@app.get("/healthz")
def healthz():
    return {
        "status": "ok",
        "loaded_packs": len(engine.registry.packs),
        "indexed_events": len(global_visibility_store._events),
    }


@app.get("/dashboard", response_class=HTMLResponse)
def view_dashboard():
    """Renders the Unified Analytical Visibility Dashboard."""
    return HTMLResponse(content=DASHBOARD_HTML)


@app.get("/packs")
def list_packs():
    return [
        {
            "pack_id": p.pack_id,
            "vendor": p.vendor,
            "product": p.product,
            "pack_version": p.pack_version,
            "priority": p.priority,
            "format": p.format_type,
        }
        for p in engine.registry.packs
    ]


@app.post("/packs/reload")
def reload_packs():
    engine.reload_packs()
    return {"status": "reloaded", "loaded_packs": len(engine.registry.packs)}


@app.post("/v1/parse", response_model=ParsedEvent)
def parse_event(envelope: RawEventEnvelope):
    try:
        return engine.process(envelope)
    except Exception as exc:
        logger.exception("Unhandled error processing event %s", envelope.event_id)
        raise HTTPException(status_code=500, detail=f"Unhandled engine error: {exc}") from exc


@app.post("/v1/pipeline/cisco-asa")
def process_cisco_asa_pipeline(
    raw_payload: str = Body(..., media_type="text/plain", description="Raw Cisco ASA Syslog line")
):
    """
    Complete end-to-end pipeline execution for a single Cisco ASA log:
    Raw Bytes -> RawEventEnvelope + Hash -> Cisco Source Pack -> UnifiedEvent Normalization -> Analytical Indexing.
    """
    try:
        result = cisco_runner.process_raw_log(raw_payload)
        return JSONResponse(content=result)
    except Exception as exc:
        logger.exception("Failed to process Cisco ASA pipeline")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/v1/analytics/events")
def get_analytics_events(
    query: Optional[str] = Query(None, description="Free text or field query"),
    vendor: Optional[str] = Query(None, description="Vendor filter"),
    action: Optional[str] = Query(None, description="Action filter"),
    severity: Optional[str] = Query(None, description="Severity filter"),
    quality_status: Optional[str] = Query(None, description="Quality status filter"),
    limit: int = Query(50, ge=1, le=500),
):
    """Returns indexed normalized events and live analytical aggregations."""
    events = global_visibility_store.search(
        query=query,
        vendor=vendor,
        action=action,
        severity=severity,
        quality_status=quality_status,
        limit=limit,
    )
    aggregations = global_visibility_store.get_aggregations()
    return {"events": events, "aggregations": aggregations}


@app.post("/v1/export/data-lake")
def export_data_lake():
    """Triggers data lake export to JSON-Lines."""
    events = global_visibility_store.list_events(limit=1000)
    manifest = exporter.export_events(events)
    return manifest


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=False)
