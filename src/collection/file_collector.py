from pathlib import Path

from .pipeline import CollectionPipeline, IngestResult


class FileCollector:
    """Replay LF-delimited events, removing exactly one LF framing byte."""

    def __init__(self, pipeline: CollectionPipeline, source_id: str = "file-replay") -> None:
        self.pipeline = pipeline
        self.source_id = source_id

    def replay(self, path: Path) -> list[IngestResult]:
        results = []
        with path.open("rb") as f:
            for line in f:
                raw = line[:-1] if line.endswith(b"\n") else line
                results.append(
                    self.pipeline.ingest(raw=raw, transport="file", source_id=self.source_id)
                )
        return results
