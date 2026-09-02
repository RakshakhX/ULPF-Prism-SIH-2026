"""Bounded, concurrency-safe duplicate tracking for collectors."""

from collections import OrderedDict
from threading import Lock


class BoundedHashCache:
    """Track recently observed hashes without allowing unbounded growth."""

    def __init__(self, max_entries: int) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be greater than zero")
        self._entries: OrderedDict[str, None] = OrderedDict()
        self._max_entries = max_entries
        self._lock = Lock()

    def check_and_add(self, hash_value: str) -> bool:
        """Return whether ``hash_value`` was present, then mark it recent."""

        with self._lock:
            duplicate = hash_value in self._entries
            self._entries[hash_value] = None
            self._entries.move_to_end(hash_value)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)
            return duplicate

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
