"""
main.py

Minimal FastAPI wrapper around the ULPF ParsingEngine so it can run as a
standalone containerized service, e.g. behind a collection/ingestion layer
that POSTs RawEventEnvelope JSON and receives ParsedEvent JSON back.

Run locally:   uvicorn main:app --reload
Run in Docker: see Dockerfile (CMD runs uvicorn on 0.0.0.0:8080)
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from core.engine import ParsingEngine
from core.models import ParsedEvent, RawEventEnvelope

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("ulpf.main")

PACKS_DIR = Path(__file__).parent / "source_packs"

app = FastAPI(
    title="Universal Log Pre-processing Framework (ULPF)",
    description="Core parsing engine: ingest a RawEventEnvelope, route it through a Source Pack, return a ParsedEvent.",
    version="1.0.0",
)

engine = ParsingEngine(packs_dir=PACKS_DIR)


@app.get("/healthz")
def healthz():
    return {"status": "ok", "loaded_packs": len(engine.registry.packs)}


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
    except Exception as exc:  # engine.process() already guards internally; this is a last-resort safety net
        logger.exception("Unhandled error processing event %s", envelope.event_id)
        raise HTTPException(status_code=500, detail=f"Unhandled engine error: {exc}") from exc


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=False)
