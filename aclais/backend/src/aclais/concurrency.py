"""Per-task serialization shared by lifecycle decisions and broker effects."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass


@dataclass
class _Entry:
    lock: threading.RLock
    users: int = 0


class TaskLockRegistry:
    """Provide one reentrant lock per task without retaining completed task IDs."""

    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._entries: dict[str, _Entry] = {}

    @contextmanager
    def hold(self, task_id: str) -> Iterator[None]:
        if not isinstance(task_id, str) or not task_id:
            raise ValueError("task lock requires a task identifier")
        with self._guard:
            entry = self._entries.get(task_id)
            if entry is None:
                entry = _Entry(threading.RLock())
                self._entries[task_id] = entry
            entry.users += 1
        entry.lock.acquire()
        try:
            yield
        finally:
            entry.lock.release()
            with self._guard:
                entry.users -= 1
                if entry.users == 0 and self._entries.get(task_id) is entry:
                    del self._entries[task_id]
