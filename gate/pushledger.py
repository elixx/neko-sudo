"""Append-only JSONL record of push delivery attempts.

Diagnostics, never a dependency: :meth:`PushLedger.append` never raises
into the delivery path.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path

LEDGER_MAX_BYTES = 1_000_000


class PushLedger:
    """Rotates once to ``<name>.1`` when the live file would pass
    ``max_bytes``, so disk use is bounded at roughly twice that. Appends
    are serialised: background sends run in a threadpool, and rotation is
    check-then-act."""

    def __init__(self, path, *, max_bytes: int = LEDGER_MAX_BYTES):
        self.path = Path(path)
        self.max_bytes = int(max_bytes)
        self._lock = threading.Lock()

    def append(self, record: dict) -> bool:
        try:
            line = json.dumps(record, separators=(",", ":"), default=str) + "\n"
            size = len(line.encode("utf-8"))
            with self._lock:
                if self.path.exists() and self.path.stat().st_size + size > self.max_bytes:
                    os.replace(self.path, self.path.with_name(self.path.name + ".1"))
                with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                    handle.write(line)
            return True
        except Exception as exc:  # noqa: BLE001 — diagnostics never break delivery
            print(
                f"neko-sudo push: ledger {self.path} not written: {exc!r}",
                file=sys.stderr,
            )
            return False
