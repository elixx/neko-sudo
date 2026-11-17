"""Push subscription persistence for the gate console.

Browsers subscribe once per origin; the gate stores the subscription info
as JSON on the data volume. One row per endpoint: re-subscribing refreshes
the keys, dead endpoints (410/404 from the push service) are pruned by the
sender.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path


class SubscriptionStore:
    def __init__(self, path: Path):
        self._path = Path(path)
        self._lock = threading.Lock()

    def _load(self) -> list[dict]:
        if not self._path.exists():
            return []
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []
        return data if isinstance(data, list) else []

    def _save(self, subs: list[dict]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(subs, indent=2), encoding="utf-8")
        tmp.replace(self._path)

    def _validate(self, sub: dict) -> None:
        endpoint = sub.get("endpoint")
        if not isinstance(endpoint, str) or not endpoint.startswith("https://"):
            raise ValueError("subscription.endpoint must be an https URL")
        keys = sub.get("keys")
        if not isinstance(keys, dict) or not keys.get("p256dh") or not keys.get("auth"):
            raise ValueError("subscription.keys must carry p256dh and auth")

    def add(self, sub: dict) -> None:
        self._validate(sub)
        with self._lock:
            subs = [
                s for s in self._load() if s.get("endpoint") != sub["endpoint"]
            ]
            subs.append(
                {
                    "endpoint": sub["endpoint"],
                    "keys": {
                        "p256dh": sub["keys"]["p256dh"],
                        "auth": sub["keys"]["auth"],
                    },
                }
            )
            self._save(subs)

    def remove(self, endpoint: str) -> None:
        with self._lock:
            self._save(
                [s for s in self._load() if s.get("endpoint") != endpoint]
            )

    def clear(self) -> None:
        """Drop every subscription (a VAPID rotation retires them all)."""
        with self._lock:
            self._save([])

    def all(self) -> list[dict]:
        with self._lock:
            return self._load()
