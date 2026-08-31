"""
core/parsers/csv_parser.py

Parses a single CSV log line into a dict, given an ordered list of column
names (typically supplied by the Source Pack manifest, since CSV carries no
schema of its own). Falls back to positional keys (col_0, col_1, ...) if no
column list is supplied.
"""

from __future__ import annotations

import csv
import io
from typing import Any, Dict, List, Optional

from core.exceptions import FormatParsingError
from core.parsers.base import BaseFormatParser


class CSVFormatParser(BaseFormatParser):
    format_name = "csv"

    def can_parse(self, raw_payload: str, **options: Any) -> bool:
        delimiter = options.get("delimiter", ",")
        return delimiter in raw_payload

    def parse(self, raw_payload: str, **options: Any) -> Dict[str, Any]:
        delimiter: str = options.get("delimiter", ",")
        columns: Optional[List[str]] = options.get("columns")
        quotechar: str = options.get("quotechar", '"')

        text = raw_payload.strip()
        if not text:
            raise FormatParsingError("Empty CSV payload")

        try:
            reader = csv.reader(io.StringIO(text), delimiter=delimiter, quotechar=quotechar)
            row = next(reader)
        except (csv.Error, StopIteration) as exc:
            raise FormatParsingError(f"Failed to parse CSV row: {exc}") from exc

        if columns:
            if len(row) < len(columns):
                # Pad short rows rather than crash — enterprise CSV logs are messy.
                row = row + [""] * (len(columns) - len(row))
            return {col: row[i] for i, col in enumerate(columns)}

        return {f"col_{i}": val for i, val in enumerate(row)}
