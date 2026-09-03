from __future__ import annotations

from typing import Any


class FakeClickHouseClient:
    def __init__(self) -> None:
        self.inserts: list[dict[str, Any]] = []
        self.fail_with: Exception | None = None

    def insert(self, table: str, data: list[list[Any]], column_names: list[str]) -> None:
        if self.fail_with is not None:
            raise self.fail_with
        self.inserts.append({"table": table, "data": data, "column_names": column_names})
