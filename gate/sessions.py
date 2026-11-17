"""Browser sign-in sessions for the gate console.

A session is an opaque random ID carried in a ``__Host-`` cookie. The server
keeps only the SHA-256 of each ID. With a ``path`` the hashes (never the raw
IDs) are persisted, so a gate restart does not sign the owner out
mid-restart; deleting that file signs every browser out. Sessions expire
after an idle period and at an absolute lifetime, and logout revokes them
server-side, so a replayed cookie value stops working the moment the owner
logs out.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from typing import Callable, Optional

COOKIE_NAME = '__Host-neko_sudo_session'
DEFAULT_IDLE_S = 12 * 60 * 60
DEFAULT_ABSOLUTE_S = 7 * 24 * 60 * 60
DEFAULT_MAX_SESSIONS = 32
TOUCH_PERSIST_S = 60.0


def _digest(raw: str) -> str:
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


class SessionStore:
    """Hashed, expiring session IDs; optionally persisted (hashes only) to ``path``."""

    def __init__(self, *, clock: Callable[[], float] = time.time,
                 idle_s: float = DEFAULT_IDLE_S, absolute_s: float = DEFAULT_ABSOLUTE_S,
                 max_sessions: int = DEFAULT_MAX_SESSIONS, path: Optional[Path] = None):
        self._clock = clock
        self.idle_s = float(idle_s)
        self.absolute_s = float(absolute_s)
        self.max_sessions = int(max_sessions)
        self.path = Path(path) if path else None
        self._sessions: dict[str, dict] = {}
        self._persisted_at = 0.0
        self._load()

    def _load(self) -> None:
        if self.path is None:
            return
        try:
            data = json.loads(self.path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            return   # missing or corrupt: start with nobody signed in
        rows = data.get('sessions') if isinstance(data, dict) else None
        if not isinstance(rows, dict):
            return
        for key, rec in rows.items():
            if (isinstance(key, str) and len(key) == 64 and isinstance(rec, dict)
                    and isinstance(rec.get('created_at'), (int, float))
                    and isinstance(rec.get('last_seen'), (int, float))):
                self._sessions[key] = {'created_at': float(rec['created_at']),
                                       'last_seen': float(rec['last_seen']),
                                       'method': str(rec.get('method', ''))[:16],
                                       'detail': str(rec.get('detail', ''))[:120]}
        self._sweep(float(self._clock()))

    def _persist(self) -> None:
        if self.path is None:
            return
        self._persisted_at = float(self._clock())
        tmp = self.path.with_name(self.path.name + '.tmp')
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps({'version': 1, 'sessions': self._sessions}), encoding='utf-8')
            os.replace(tmp, self.path)
        except OSError:
            pass   # persistence is a convenience; the in-memory store stays authoritative

    def _sweep(self, now: float) -> None:
        dead = [key for key, rec in self._sessions.items() if not self._alive(rec, now)]
        for key in dead:
            self._sessions.pop(key, None)

    def _alive(self, rec: dict, now: float) -> bool:
        return (now - rec['last_seen'] < self.idle_s
                and now - rec['created_at'] < self.absolute_s)

    def create(self, *, method: str, detail: str = '') -> str:
        """Start a session; returns the raw ID for the cookie (never stored)."""
        now = float(self._clock())
        self._sweep(now)
        while len(self._sessions) >= self.max_sessions:
            oldest = min(self._sessions, key=lambda key: self._sessions[key]['last_seen'])
            self._sessions.pop(oldest, None)
        raw = secrets.token_urlsafe(32)
        self._sessions[_digest(raw)] = {'created_at': now, 'last_seen': now,
                                        'method': method, 'detail': detail[:120]}
        self._persist()
        return raw

    def check(self, raw: Optional[str], *, touch: bool = True) -> Optional[dict]:
        """The live session record for ``raw`` (refreshing its idle timer), else None."""
        if not raw or len(raw) > 256:
            return None
        key = _digest(raw)
        rec = self._sessions.get(key)
        if rec is None:
            return None
        now = float(self._clock())
        if not self._alive(rec, now):
            self._sessions.pop(key, None)
            self._persist()
            return None
        if touch:
            rec['last_seen'] = now
            if now - self._persisted_at >= TOUCH_PERSIST_S:
                self._persist()
        return dict(rec)

    def alive_digest(self, key: str) -> bool:
        """Is the session with SHA-256 digest ``key`` still live? (no touch).

        For holders of a session-bound resource keyed by the digest to
        notice expiry and eviction."""
        rec = self._sessions.get(key) if isinstance(key, str) else None
        return rec is not None and self._alive(rec, float(self._clock()))

    def revoke(self, raw: Optional[str]) -> bool:
        if not raw or len(raw) > 256:
            return False
        gone = self._sessions.pop(_digest(raw), None) is not None
        if gone:
            self._persist()
        return gone

    def revoke_all(self) -> int:
        count = len(self._sessions)
        self._sessions.clear()
        self._persist()
        return count

    def __len__(self) -> int:
        self._sweep(float(self._clock()))
        return len(self._sessions)


class FailureLimiter:
    """Global back-off: after ``max_failures`` within ``window_s`` refuse for ``lockout_s``."""

    def __init__(self, *, clock: Callable[[], float] = time.time, max_failures: int = 5,
                 window_s: float = 60.0, lockout_s: float = 60.0):
        self._clock = clock
        self.max_failures = int(max_failures)
        self.window_s = float(window_s)
        self.lockout_s = float(lockout_s)
        self._failures: list[float] = []
        self._locked_until = 0.0

    def retry_after(self) -> float:
        """Seconds until attempts are allowed again (0 when allowed now)."""
        return max(0.0, self._locked_until - float(self._clock()))

    def fail(self) -> None:
        now = float(self._clock())
        self._failures = [t for t in self._failures if now - t < self.window_s] + [now]
        if len(self._failures) >= self.max_failures:
            self._locked_until = now + self.lockout_s
            self._failures.clear()

    def reset(self) -> None:
        self._failures.clear()
        self._locked_until = 0.0


def cookie_value(cookie_header: str, name: str = COOKIE_NAME) -> Optional[str]:
    """The value of cookie ``name`` from a raw ``Cookie`` header, if present."""
    for part in (cookie_header or '').split(';'):
        key, sep, value = part.strip().partition('=')
        if sep and key == name:
            return value.strip().strip('"') or None
    return None


def set_cookie_header(raw: str, *, max_age_s: float) -> str:
    return (f'{COOKIE_NAME}={raw}; Path=/; Secure; HttpOnly; SameSite=Strict; '
            f'Max-Age={int(max_age_s)}')


def clear_cookie_header() -> str:
    return f'{COOKIE_NAME}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0'
