"""Data-lake export formats and integrity manifests."""

from typing import TYPE_CHECKING, Any

from src.exports.jsonl import JsonlExporter
from src.exports.models import ExportFile, ExportManifest, verify_manifest

if TYPE_CHECKING:
    from src.exports.parquet import ParquetExporter

__all__ = [
    "ExportFile",
    "ExportManifest",
    "JsonlExporter",
    "ParquetExporter",
    "verify_manifest",
]


def __getattr__(name: str) -> Any:
    """Keep JSONL usable when the optional PyArrow extra is not installed."""
    if name == "ParquetExporter":
        from src.exports.parquet import ParquetExporter

        return ParquetExporter
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
