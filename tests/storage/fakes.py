from __future__ import annotations

from typing import Any


class FakeClickHouseClient:
    def __init__(self) -> None:
        self.inserts: list[dict[str, Any]] = []
        self.queries: list[dict[str, Any]] = []
        self.query_rows: list[tuple[Any, ...]] = []
        self.query_responses: list[list[tuple[Any, ...]]] = []
        self.fail_with: Exception | None = None

    def insert(self, table: str, data: list[list[Any]], column_names: list[str]) -> None:
        if self.fail_with is not None:
            raise self.fail_with
        self.inserts.append({"table": table, "data": data, "column_names": column_names})

    def query(self, query: str, parameters: dict[str, Any] | None = None):
        if self.fail_with is not None:
            raise self.fail_with
        self.queries.append({"query": query, "parameters": parameters or {}})
        rows = self.query_responses.pop(0) if self.query_responses else self.query_rows
        return type("FakeQueryResult", (), {"result_rows": rows})()
