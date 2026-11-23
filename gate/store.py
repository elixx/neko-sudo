"""SQLite-backed store for approval requests.

Fail-closed lifecycle: a request is pending until the owner explicitly
approves or denies it, or its TTL elapses. Statuses are terminal — a
decided request can never change status again (single use).
"""

import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import sys
import threading
import time
from pathlib import Path

# An approved request nobody collected stops holding back later
# same-host requests, and can no longer be delivered, this long after its
# expiry. A live wrapper's last poll lands by about expires_at + 12 s
# (5 s grace + 2 s poll interval + 5 s transport timeout).
UNCOLLECTED_CUTOFF_S = 30


class EarlierPending(Exception):
    """Approve refused: earlier requests from the same host are still
    pending. Deny is never refused."""

    def __init__(self, earlier_ids):
        super().__init__(f"earlier same-host requests pending: {earlier_ids}")
        self.earlier_ids = list(earlier_ids)


def payload_digest(host: str, user: str, argv: list[str], cwd: str) -> str:
    canonical = json.dumps(
        {"host": host, "user": user, "argv": argv, "cwd": cwd},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _db_generation(path):
    """Judge a candidate db file: (usable, generation). Corrupt or
    unreadable files are unusable; a valid db predating store_meta (the
    legacy share schema) counts as generation 0."""
    if not path.exists():
        return False, None
    try:
        conn = sqlite3.connect(str(path))
        try:
            if conn.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                return False, None
            try:
                row = conn.execute(
                    "SELECT value FROM store_meta WHERE key = 'generation'"
                ).fetchone()
                return True, (row[0] if row else 0)
            except sqlite3.OperationalError:
                return True, 0  # legacy schema, valid db
        finally:
            conn.close()
    except sqlite3.DatabaseError:
        return False, None


def _quarantine_state(path, suffix):
    """Move a state file (and its WAL/SHM companions) aside, preserving it
    for forensics. `suffix` carries the reason (.corrupt- / .superseded-)."""
    aside = path.with_name(f"{path.name}{suffix}{int(time.time())}")
    os.replace(path, aside)
    for companion in ("-wal", "-shm"):
        src = path.with_name(path.name + companion)
        if src.exists():
            os.replace(src, aside.with_name(aside.name + companion))
    return aside


def _restore_into_state(src, state_path):
    """Copy a chosen artifact to the live state path: tmp + atomic rename,
    so a crash mid-copy never leaves a half-written live db."""
    state_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = state_path.with_name(state_path.name + ".restore.tmp")
    shutil.copyfile(src, tmp)
    os.replace(tmp, state_path)


def reconcile_state(state_path, snapshots_dir, legacy_path=None):
    """Boot-time reconcile for the node-local state layout.

    Decide where the live gate db comes from at boot:
      - healthy local state vs newest good snapshot: highest generation
        wins; a tie goes to local live (it is the artifact this node
        wrote itself, and equals-or-exceeds every snapshot it published);
      - corrupt local state is quarantined (.corrupt-<ts>), never deleted;
      - a newer snapshot restores over older live state (.superseded-<ts>);
      - the legacy share db (pre-Design-A /data/gate.sqlite3) imports only
        when neither state nor any good snapshot exists, then is moved
        aside (.imported-<ts>) so it can never silently win again.

    Generations live inside the data (store_meta), never in mtimes —
    clock skew between nodes must not reorder history. Returns a short
    source descriptor for the boot log.
    """
    state_path = Path(state_path)

    live_usable, live_gen = _db_generation(state_path)

    best_snap, best_gen = None, None
    if snapshots_dir is not None and Path(snapshots_dir).is_dir():
        candidates = []
        for p in Path(snapshots_dir).iterdir():
            if not re.match(r"^gate-\d+-\d+\.db$", p.name):
                continue
            usable, gen = _db_generation(p)
            if usable and gen is not None:
                candidates.append((gen, p))
        if candidates:
            candidates.sort(key=lambda item: (item[0], item[1].name))
            best_gen, best_snap = candidates[-1]

    if live_usable:
        if best_gen is None or live_gen >= best_gen:
            return "live"
        assert best_snap is not None  # best_gen set implies a candidate
        _quarantine_state(state_path, ".superseded-")
        _restore_into_state(best_snap, state_path)
        return f"snapshot:{best_snap.name}"

    # local state absent or corrupt
    if best_snap is not None:
        if state_path.exists():
            _quarantine_state(state_path, ".corrupt-")
        _restore_into_state(best_snap, state_path)
        return f"snapshot:{best_snap.name}"

    if state_path.exists():
        _quarantine_state(state_path, ".corrupt-")

    if legacy_path is not None:
        legacy = Path(legacy_path)
        if legacy.exists():
            # Fold any un-checkpointed WAL frames into the share file so
            # the import carries every committed row, then judge it.
            try:
                conn = sqlite3.connect(str(legacy))
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                conn.close()
            except sqlite3.DatabaseError as exc:
                print(f"neko-sudo: legacy checkpoint failed ({exc!r})",
                      file=sys.stderr)
            usable, _ = _db_generation(legacy)
            if usable:
                _restore_into_state(legacy, state_path)
                aside = legacy.with_name(
                    f"{legacy.name}.imported-{int(time.time())}"
                )
                os.replace(legacy, aside)
                for companion in ("-wal", "-shm"):
                    src = legacy.with_name(legacy.name + companion)
                    if src.exists():
                        os.replace(src, aside.with_name(aside.name + companion))
                return f"legacy:{legacy.name}"

    return "fresh"


class RequestStore:
    def __init__(self, path, clock=time.time, snapshots_dir=None,
                 snapshot_keep=100):
        self._clock = clock
        self._snapshots_dir = snapshots_dir
        self._snapshot_keep = snapshot_keep
        # The live db lives on node-local storage; the parent
        # directory may not exist yet on a node booting for the first time.
        path.parent.mkdir(parents=True, exist_ok=True)
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
            CREATE TABLE IF NOT EXISTS store_meta (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL
            )
            """
        )
        self._conn.execute(
            "INSERT OR IGNORE INTO store_meta (key, value)"
            " VALUES ('generation', 0)"
        )
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
        self._migrate_locked()
        self._conn.commit()

    def _migrate_locked(self):
        """Same-host order columns, added in place when missing (fresh db,
        older db, or an older snapshot restored by reconcile). All are
        nullable:
        the older image names its INSERT columns and reads rows by key, so
        a rollback keeps working, and rows it writes are legacy rows
        (host_seq NULL) that never block and are never held."""
        have = {r["name"] for r in self._conn.execute("PRAGMA table_info(requests)")}
        for name, decl in (("host_seq", "INTEGER"), ("delivered_at", "REAL"),
                           ("uncollected_at", "REAL")):
            if name not in have:
                self._conn.execute(f"ALTER TABLE requests ADD COLUMN {name} {decl}")

    def _bump_locked(self):
        """Increment generation INSIDE the caller's open transaction —
        the data change and its ordering token commit atomically."""
        self._conn.execute(
            "UPDATE store_meta SET value = value + 1 WHERE key = 'generation'"
        )

    def _commit_publish_locked(self):
        """Commit a generation-bumped transaction, then publish a snapshot
        of the committed state into the replicated snapshots dir.
        Snapshotting failures must never take the gate down: the data is
        already durable at that point, and the next commit retries."""
        self._bump_locked()
        self._conn.commit()
        self._publish_locked()

    def _publish_locked(self):
        if self._snapshots_dir is None:
            return
        try:
            self._snapshots_dir.mkdir(parents=True, exist_ok=True)
            gen = self._conn.execute(
                "SELECT value FROM store_meta WHERE key = 'generation'"
            ).fetchone()["value"]
            ts = int(self._clock())
            final = self._snapshots_dir / f"gate-{gen}-{ts}.db"
            # Dotted .tmp name: lives for microseconds before the atomic
            # rename, stays outside the gate-*.db family, and the rename
            # itself is what makes the snapshot visible to replication.
            tmp = self._snapshots_dir / f".gate-{gen}-{ts}.db.tmp"
            escaped = str(tmp).replace("'", "''")
            self._conn.execute(f"VACUUM INTO '{escaped}'")
            os.replace(tmp, final)
            self._prune_locked()
        except Exception as exc:  # noqa: BLE001 — availability over DR
            print(f"neko-sudo: snapshot publish failed ({exc!r}); "
                  "data commit is durable, next commit retries",
                  file=sys.stderr)

    def _prune_locked(self):
        """Keep only the N newest snapshots, ordered by parsed generation
        (never by name: gate-10-* sorts before gate-9-*). Foreign files in
        the snapshots dir are not ours to delete."""
        import re

        if self._snapshots_dir is None:
            return
        entries = []
        for p in self._snapshots_dir.iterdir():
            m = re.match(r"^gate-(\d+)-\d+\.db$", p.name)
            if m:
                entries.append((int(m.group(1)), p))
        entries.sort()
        for _, path in entries[: max(0, len(entries) - self._snapshot_keep)]:
            try:
                path.unlink()
            except OSError as exc:
                print(f"neko-sudo: snapshot prune failed for {path.name} "
                      f"({exc!r})", file=sys.stderr)

    def generation(self):
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM store_meta WHERE key = 'generation'"
            ).fetchone()
            return row["value"]

    def close(self):
        """Release the database connection. The last connection close
        checkpoints WAL into the main file, leaving a self-contained db
        behind (no -wal/-shm companions)."""
        with self._lock:
            self._conn.close()

    def create_request(self, host, user, argv, cwd, ttl_s):
        now = self._clock()
        request_id = secrets.token_urlsafe(12)
        digest = payload_digest(host, user, argv, cwd)
        with self._lock:
            # Per-host submission order. An explicit counter, never
            # rowid (TEXT primary key: VACUUM INTO may renumber) or
            # created_at (clock of whichever node runs the gate).
            host_seq = self._conn.execute(
                "SELECT COALESCE(MAX(host_seq), 0) + 1 FROM requests WHERE host = ?",
                (host,),
            ).fetchone()[0]
            self._conn.execute(
                "INSERT INTO requests (id, host, user, argv, cwd, digest, status,"
                " created_at, expires_at, host_seq)"
                " VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)",
                (
                    request_id,
                    host,
                    user,
                    json.dumps(argv),
                    cwd,
                    digest,
                    now,
                    now + ttl_s,
                    host_seq,
                ),
            )
            self._commit_publish_locked()
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
        cur = self._conn.execute(
            "UPDATE requests SET status = 'expired', decided_at = ?"
            " WHERE id = ? AND status = 'pending'",
            (self._clock(), request_id),
        )
        if cur.rowcount:
            self._commit_publish_locked()

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
            if status == "approved":
                earlier = self._earlier_pending_locked(request, self._clock())
                if earlier:
                    raise EarlierPending([r["id"] for r in earlier])
            self._conn.execute(
                "UPDATE requests SET status = ?, decided_at = ?"
                " WHERE id = ? AND status = 'pending'",
                (status, self._clock(), request_id),
            )
            self._commit_publish_locked()
            return self._get_locked(request_id)

    # ----------------------------------------------------- same-host order

    def _earlier_pending_locked(self, request, now):
        """Earlier same-host requests still awaiting a decision, oldest
        first. Legacy rows (host_seq NULL) never count."""
        if request["host_seq"] is None:
            return []
        rows = self._conn.execute(
            "SELECT * FROM requests WHERE host = ? AND host_seq < ?"
            " AND status = 'pending' AND expires_at > ? ORDER BY host_seq",
            (request["host"], request["host_seq"], now),
        ).fetchall()
        return [self._row_to_request(r) for r in rows]

    def earlier_pending(self, request_id):
        """Public form of the approve guard, so the console can refuse
        before a passkey ceremony is spent on a doomed approve."""
        with self._lock:
            request = self._get_locked(request_id)
            if request is None:
                return []
            return self._earlier_pending_locked(request, self._clock())

    def host_queue(self, request_id):
        """Where a request sits among its host's pending requests:
        {"position", "total", "earlier"} for cards, review and push.
        position counts the same earlier requests the approve guard does."""
        with self._lock:
            request = self._get_locked(request_id)
            if request is None:
                return None
            now = self._clock()
            earlier = self._earlier_pending_locked(request, now)
            total = self._conn.execute(
                "SELECT COUNT(*) FROM requests WHERE host = ?"
                " AND status = 'pending' AND expires_at > ?",
                (request["host"], now),
            ).fetchone()[0]
            return {"position": len(earlier) + 1, "total": total,
                    "earlier": earlier}

    def _mark_uncollected_locked(self, host, now):
        """Durably pass over this host's approvals that nobody collected by
        expires_at + UNCOLLECTED_CUTOFF_S. The clock is consulted exactly
        once per row, here; after that uncollected_at alone decides, so a
        clock stepping back (NTP, failover to a lagging node) can never
        re-arm an approval a later request has already overtaken. The
        caller commits this together with whatever it hands over next."""
        return self._conn.execute(
            "UPDATE requests SET uncollected_at = ? WHERE host = ?"
            " AND status = 'approved' AND delivered_at IS NULL"
            " AND uncollected_at IS NULL AND expires_at + ? <= ?",
            (now, host, UNCOLLECTED_CUTOFF_S, now),
        ).rowcount

    def _holding_locked(self, request, now):
        """Ids of earlier same-host requests that are not settled yet:
        still pending, or approved but neither collected nor passed over.
        Denied, expired, delivered and passed-over requests are settled."""
        if request["host_seq"] is None:
            return []
        rows = self._conn.execute(
            "SELECT id FROM requests WHERE host = ? AND host_seq < ? AND ("
            " (status = 'pending' AND expires_at > ?)"
            " OR (status = 'approved' AND delivered_at IS NULL"
            "     AND uncollected_at IS NULL)"
            ") ORDER BY host_seq",
            (request["host"], request["host_seq"], now),
        ).fetchall()
        return [r["id"] for r in rows]

    def poll_for_host(self, request_id, host):
        """The request as its own host's wrapper may see it.

        Returns None for an unknown id or another host's request, with no
        side effects. An approved request is handed over (status
        "approved", delivered_at recorded once) only when no earlier
        same-host request is unsettled; until then the wrapper sees
        "pending" plus held_behind, which every deployed wrapper keeps
        polling on. An approval nobody collected by expires_at +
        UNCOLLECTED_CUTOFF_S is passed over for good (uncollected_at): it
        stops holding later requests back and reads "expired" from then
        on, so a late poll cannot run it after a request that overtook it.
        """
        with self._lock:
            request = self._get_locked(request_id)
            if request is None or request["host"] != host:
                return None
            request["held_behind"] = []
            if request["status"] != "approved" or request["delivered_at"] is not None:
                return request
            now = self._clock()
            dirty = self._mark_uncollected_locked(host, now) > 0
            request = self._get_locked(request_id)
            assert request is not None  # same row, same lock
            request["held_behind"] = []
            if request["uncollected_at"] is not None:
                request["status"] = "expired"
            else:
                holding = self._holding_locked(request, now)
                if holding:
                    request["status"] = "pending"
                    request["held_behind"] = holding
                else:
                    self._conn.execute(
                        "UPDATE requests SET delivered_at = ?"
                        " WHERE id = ? AND delivered_at IS NULL",
                        (now, request_id),
                    )
                    request["delivered_at"] = now
                    dirty = True
            if dirty:
                # One generation for the hand-over and every pass-over it
                # relied on: no snapshot holds one without the other.
                self._commit_publish_locked()
            return request

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
        cur = self._conn.execute(
            "UPDATE requests SET status = 'expired', decided_at = ?"
            " WHERE status = 'pending' AND expires_at <= ?",
            (now, now),
        )
        if cur.rowcount:
            self._commit_publish_locked()

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
            "host_seq": row["host_seq"],
            "delivered_at": row["delivered_at"],
            "uncollected_at": row["uncollected_at"],
        }
