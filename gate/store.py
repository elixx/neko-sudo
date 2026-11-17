"""SQLite-backed store for approval requests.

Fail-closed lifecycle: a request is pending until the owner explicitly
approves or denies it, or its TTL elapses. Statuses are terminal — a
decided request can never change status again (single use).
"""

import hashlib
import json
import secrets
import sqlite3
import threading
import time


def payload_digest(host: str, user: str, argv: list[str], cwd: str) -> str:
    canonical = json.dumps(
        {"host": host, "user": user, "argv": argv, "cwd": cwd},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class RequestStore:
    def __init__(self, path, clock=time.time):
        self._clock = clock
        # One connection is shared across threads (check_same_thread=False),
        # and one connection means one shared prepared-statement cache:
        # unsynchronized cross-thread use interleaves bind/step on the same
        # sqlite3_stmt and corrupts reads (json.loads(None)). Every
        # operation is atomic under this lock.
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS requests (
                id TEXT PRIMARY KEY,
                host TEXT NOT NULL,
                user TEXT NOT NULL,
                argv TEXT NOT NULL,
                cwd TEXT NOT NULL,
                digest TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                decided_at REAL
            )
            """
        )
        self._conn.commit()

    def create_request(self, host, user, argv, cwd, ttl_s):
        now = self._clock()
        request_id = secrets.token_urlsafe(12)
        digest = payload_digest(host, user, argv, cwd)
        with self._lock:
            self._conn.execute(
                "INSERT INTO requests (id, host, user, argv, cwd, digest, status,"
                " created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
                (
                    request_id,
                    host,
                    user,
                    json.dumps(argv),
                    cwd,
                    digest,
                    now,
                    now + ttl_s,
                ),
            )
            self._conn.commit()
            return self._get_locked(request_id)

    def get_request(self, request_id):
        with self._lock:
            return self._get_locked(request_id)

    def _get_locked(self, request_id):
        row = self._conn.execute(
            "SELECT * FROM requests WHERE id = ?", (request_id,)
        ).fetchone()
        if row is None:
            return None
        request = self._row_to_request(row)
        if request["status"] == "pending" and self._clock() >= request["expires_at"]:
            self._lazy_expire(request_id)
            request["status"] = "expired"
        return request

    def _lazy_expire(self, request_id):
        self._conn.execute(
            "UPDATE requests SET status = 'expired', decided_at = ?"
            " WHERE id = ? AND status = 'pending'",
            (self._clock(), request_id),
        )
        self._conn.commit()

    def decide(self, request_id, decision):
        """Set a terminal decision. Raises LookupError if unknown,
        ValueError if the request is no longer pending."""
        status = "approved" if decision == "approve" else "denied"
        with self._lock:  # read-check-update must be one atomic step
            request = self._get_locked(request_id)
            if request is None:
                raise LookupError(f"unknown request {request_id}")
            if request["status"] != "pending":
                raise ValueError(
                    f"request {request_id} is {request['status']}, not pending"
                )
            self._conn.execute(
                "UPDATE requests SET status = ?, decided_at = ?"
                " WHERE id = ? AND status = 'pending'",
                (status, self._clock(), request_id),
            )
            self._conn.commit()
            return self._get_locked(request_id)

    def pending_requests(self):
        """All still-pending requests, oldest first; lazy-expires stale rows."""
        now = self._clock()
        with self._lock:
            self._expire_stale_locked(now)
            rows = self._conn.execute(
                "SELECT * FROM requests WHERE status = 'pending' ORDER BY created_at ASC"
            ).fetchall()
            return [self._row_to_request(row) for row in rows]

    def finished_requests(self, limit, offset):
        """Decided or expired requests, newest first, plus their total.
        Lazy-expires stale pending rows first, so unanswered cards show."""
        now = self._clock()
        with self._lock:
            self._expire_stale_locked(now)
            rows = self._conn.execute(
                "SELECT * FROM requests WHERE status != 'pending'"
                " ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            total = self._conn.execute(
                "SELECT COUNT(*) FROM requests WHERE status != 'pending'"
            ).fetchone()[0]
            return {"items": [self._row_to_request(r) for r in rows], "total": total}

    def _expire_stale_locked(self, now):
        self._conn.execute(
            "UPDATE requests SET status = 'expired', decided_at = ?"
            " WHERE status = 'pending' AND expires_at <= ?",
            (now, now),
        )
        self._conn.commit()

    def _row_to_request(self, row):
        return {
            "id": row["id"],
            "host": row["host"],
            "user": row["user"],
            "argv": json.loads(row["argv"]),
            "cwd": row["cwd"],
            "digest": row["digest"],
            "status": row["status"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "decided_at": row["decided_at"],
        }
