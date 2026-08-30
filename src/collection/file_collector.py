from pathlib import Path

from .pipeline import CollectionPipeline, IngestResult


class FileCollector:
    """Reads one raw event per line for testing / replay. Each line's raw
    bytes (as written in the file) are passed through unchanged."""

    def __init__(self, pipeline: CollectionPipeline, source_id: str = "file-replay") -> None:
        self.pipeline = pipeline
        self.source_id = source_id

    def replay(self, path: Path) -> list[IngestResult]:
        results = []
        with path.open("rb") as f:
            for line in f:
                raw = line.rstrip(b"\n").rstrip(b"\r")
                results.append(
                    self.pipeline.ingest(raw=raw, transport="file", source_id=self.source_id)
                )
        return results
