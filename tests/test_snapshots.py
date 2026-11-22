"""Snapshot publishing + boot reconciliation for node-local state.

The live gate db never lives on the replicated share:
live state is node-local, and after every commit a consistent standalone
snapshot (`VACUUM INTO` + atomic rename) is published to the replicated
snapshots directory. At boot the store reconciles: whichever artifact
(live db or newest snapshot) carries the highest generation wins.
"""

import os
import sqlite3
import time


def make_store(tmp_path, **kwargs):
    from gate.store import RequestStore

    return RequestStore(
        tmp_path / "state" / "gate.sqlite3",
        clock=kwargs.pop("clock", time.time),
        **kwargs,
    )


def open_ro(path):
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------- generation


def test_generation_starts_at_one_and_increments_per_commit(tmp_path):
    """Generation is the ordering token for boot reconciliation: bumped in
    the same transaction as every data change, so live >= newest snapshot
    always holds."""
    store = make_store(tmp_path)
    assert store.generation() == 0  # created, nothing committed yet

    req = store.create_request(
        host="web01", user="agent", argv=["uptime"], cwd="/tmp", ttl_s=60
    )
    assert store.generation() == 1

    store.decide(req["id"], "approve")
    assert store.generation() == 2


def test_generation_survives_reopen(tmp_path):
    store = make_store(tmp_path)
    req = store.create_request(
        host="web01", user="agent", argv=["uptime"], cwd="/tmp", ttl_s=60
    )
    store.decide(req["id"], "deny")

    reopened = make_store(tmp_path)
    assert reopened.generation() == 2


# ------------------------------------------------------------------ publish


def snapshot_names(snap_dir):
    import re

    return sorted(
        p.name for p in snap_dir.iterdir()
        if re.match(r"^gate-\d+-\d+\.db$", p.name)
    )


def snapshot_gens(names):
    import re

    gens = []
    for n in names:
        m = re.match(r"^gate-(\d+)-", n)
        assert m, f"not a snapshot name: {n}"
        gens.append(int(m.group(1)))
    return gens


def test_commit_publishes_standalone_snapshot(tmp_path):
    """After every commit a complete, standalone snapshot appears in the
    replicated snapshots dir: it must open on its own (no -wal needed),
    pass integrity, carry the row, and its generation must match the
    live store's."""
    snaps = tmp_path / "snapshots"
    store = make_store(tmp_path, snapshots_dir=snaps, snapshot_keep=100)
    req = store.create_request(
        host="web01", user="agent", argv=["uptime"], cwd="/tmp", ttl_s=60
    )

    names = snapshot_names(snaps)
    assert len(names) == 1, f"expected exactly one snapshot, got {names}"
    name = names[0]
    assert store.generation() == 1
    assert name.startswith("gate-1-") and name.endswith(".db")

    conn = open_ro(snaps / name)
    assert conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    row = conn.execute(
        "SELECT host, status FROM requests WHERE id = ?", (req["id"],)
    ).fetchone()
    assert row["host"] == "web01" and row["status"] == "pending"
    gen = conn.execute(
        "SELECT value FROM store_meta WHERE key = 'generation'"
    ).fetchone()["value"]
    assert gen == 1
    conn.close()

    store.decide(req["id"], "approve")
    names = snapshot_names(snaps)
    assert len(names) == 2
    first, second = names
    assert first.startswith("gate-1-")
    assert second.startswith("gate-2-")


def test_snapshot_names_never_match_ignore_guards(tmp_path):
    """Ignore guards commonly cover the legacy db path (gate.sqlite3*) —
    snapshot artifacts must stay outside that family forever (this is the
    .db-suffix rule; a regression here silently stops DR replication)."""
    snaps = tmp_path / "snapshots"
    store = make_store(tmp_path, snapshots_dir=snaps)
    store.create_request(
        host="web01", user="agent", argv=["uptime"], cwd="/tmp", ttl_s=60
    )

    for name in snapshot_names(snaps):
        assert ".sqlite3" not in name
        assert ".tmp" not in name
        assert "sync-conflict" not in name
    assert not [p for p in snaps.iterdir() if p.name.endswith(".tmp")], \
        "tmp leftovers in the replicated dir would churn replication"


def test_rapid_commits_same_second_unique_names(tmp_path):
    """Generation guarantees uniqueness/order even when the wall clock
    stands still (lexicographic sort on names must never be the ordering)."""
    snaps = tmp_path / "snapshots"
    frozen = {"t": 1000.0}
    store = make_store(
        tmp_path, clock=lambda: frozen["t"],
        snapshots_dir=snaps, snapshot_keep=100,
    )
    for i in range(12):
        store.create_request(
            host="web01", user="agent", argv=["true", str(i)],
            cwd="/tmp", ttl_s=60,
        )

    names = snapshot_names(snaps)
    assert len(names) == 12
    assert len(set(names)) == 12
    assert "gate-12-" in " ".join(names)


# -------------------------------------------------------------------- prune


def test_prune_keeps_n_newest_by_generation(tmp_path):
    """Keep-N retention prunes oldest-generation snapshots first. Ordering
    must come from the parsed generation, never from lexicographic names
    (gate-10-* sorts before gate-9-*)."""
    import re

    snaps = tmp_path / "snapshots"
    store = make_store(tmp_path, snapshots_dir=snaps, snapshot_keep=3)
    for i in range(12):  # more than keep-N, crossing the 9/10 digit boundary
        store.create_request(
            host="web01", user="agent", argv=["true", str(i)],
            cwd="/tmp", ttl_s=60,
        )

    names = snapshot_names(snaps)
    assert len(names) == 3
    gens = snapshot_gens(names)
    assert gens == [10, 11, 12]

    # foreign artifacts in the snapshots dir are never pruned
    readme = snaps / "README.md"
    readme.write_text("human notes")
    store.create_request(
        host="web02", user="agent", argv=["uptime"], cwd="/tmp", ttl_s=60
    )
    assert readme.exists()
    names = snapshot_names(snaps)
    assert len(names) == 3
    assert snapshot_gens(names) == [11, 12, 13]


# ----------------------------------------------------------- boot reconcile


def fabricate(base, commits, keep=100):
    """Build a real (state, snapshots) pair with `commits` generations,
    fully closed so files can be replaced on Windows."""
    snaps = base / "snaps"
    store = make_store(base, snapshots_dir=snaps, snapshot_keep=keep)
    for i in range(commits):
        store.create_request(
            host="web01", user="agent", argv=["true", str(i)],
            cwd="/tmp", ttl_s=60,
        )
    gen = store.generation()
    store.close()
    return base / "state" / "gate.sqlite3", snaps, gen


def test_reconcile_fresh_when_nothing_exists(tmp_path):
    from gate.store import reconcile_state

    state = tmp_path / "state" / "gate.sqlite3"
    src = reconcile_state(state, tmp_path / "snaps")
    assert src == "fresh"
    assert not state.exists()  # the store creates it on first open


def test_reconcile_restores_newest_good_snapshot_when_state_absent(tmp_path):
    from gate.store import reconcile_state

    _, snaps, gen = fabricate(tmp_path / "a", commits=3)

    state = tmp_path / "b" / "state" / "gate.sqlite3"
    src = reconcile_state(state, snaps)
    assert src.startswith("snapshot:")

    from gate.store import RequestStore

    store = RequestStore(state)
    assert store.generation() == gen
    store.close()


def test_reconcile_prefers_live_on_equal_or_newer_generation(tmp_path):
    from gate.store import reconcile_state

    state, snaps, live_gen = fabricate(tmp_path / "a", commits=5)
    before = state.read_bytes()

    # equal generation: local live wins the tie
    assert reconcile_state(state, snaps) == "live"
    assert state.read_bytes() == before

    # live newer than every snapshot: live wins outright
    _, older_snaps, _ = fabricate(tmp_path / "c", commits=3)
    assert reconcile_state(state, older_snaps) == "live"
    assert state.read_bytes() == before


def test_reconcile_restores_snapshot_when_it_is_newer_than_live(tmp_path):
    from gate.store import reconcile_state

    state, _, _ = fabricate(tmp_path / "a", commits=3)      # live gen 3
    _, newer_snaps, newer_gen = fabricate(tmp_path / "b", commits=7)

    src = reconcile_state(state, newer_snaps)
    assert src.startswith("snapshot:")

    from gate.store import RequestStore

    store = RequestStore(state)
    assert store.generation() == newer_gen
    store.close()


def test_reconcile_quarantines_corrupt_state_and_restores_snapshot(tmp_path):
    from gate.store import reconcile_state

    state, snaps, _ = fabricate(tmp_path / "a", commits=4)
    state.write_bytes(b"definitely not a sqlite database, nya")  # corrupt it

    src = reconcile_state(state, snaps)
    assert src.startswith("snapshot:")

    from gate.store import RequestStore

    store = RequestStore(state)
    assert store.generation() == 4
    store.close()
    quarantined = list(state.parent.glob("gate.sqlite3.corrupt-*"))
    assert len(quarantined) == 1, "corrupt state must be preserved for forensics"


def test_reconcile_corrupt_state_without_snapshots_starts_fresh(tmp_path):
    from gate.store import reconcile_state

    state = tmp_path / "state" / "gate.sqlite3"
    state.parent.mkdir(parents=True)
    state.write_bytes(b"garbage bytes that are not sqlite")

    src = reconcile_state(state, tmp_path / "snaps")
    assert src == "fresh"
    assert not state.exists()
    assert list(state.parent.glob("gate.sqlite3.corrupt-*")), \
        "the corrupt file must not be silently destroyed"


def test_reconcile_skips_corrupt_snapshots(tmp_path):
    from gate.store import reconcile_state

    state, snaps, _ = fabricate(tmp_path / "a", commits=5)
    os.unlink(state)  # force snapshot path

    # newest snapshot corrupted: the older good one must win
    newest = max(snaps.iterdir(), key=lambda p: p.stat().st_mtime)
    newest.write_bytes(b"broken snapshot bytes")
    src = reconcile_state(state, snaps)
    assert src.startswith("snapshot:")

    from gate.store import RequestStore

    store = RequestStore(state)
    assert store.generation() == 4  # gen-5 snapshot was corrupt; gen-4 restores
    store.close()


def test_reconcile_imports_legacy_share_db(tmp_path):
    from gate.store import reconcile_state

    # The pre-Design-A world: a db on the share, and NO snapshots anywhere.
    legacy_dir = tmp_path / "legacy"
    legacy, _, gen = fabricate(legacy_dir, commits=6)  # stand-in for /data/gate.sqlite3

    state = tmp_path / "node" / "state" / "gate.sqlite3"
    src = reconcile_state(state, legacy_dir / "no-such-snapshots",
                          legacy_path=legacy)
    assert src.startswith("legacy:")

    from gate.store import RequestStore

    store = RequestStore(state)
    assert store.generation() == gen
    pending = store.pending_requests()
    assert len(pending) == 6
    store.close()

    renamed = list(legacy.parent.glob("gate.sqlite3.imported-*"))
    assert len(renamed) == 1, "legacy share file must be moved aside after import"
    assert not legacy.exists()


def test_full_loop_restored_node_continues_and_republishes(tmp_path):
    """The actual failover story: node dies, its local state is gone, it
    boots off a replicated snapshot, and the very next decision publishes
    a NEW generation — every node converges on the restored node's line."""
    from gate.store import reconcile_state, RequestStore

    _, snaps, gen = fabricate(tmp_path / "origin", commits=9)

    state = tmp_path / "phoenix" / "state" / "gate.sqlite3"
    src = reconcile_state(state, snaps)
    assert src.startswith("snapshot:")

    store = RequestStore(
        state, snapshots_dir=tmp_path / "phoenix" / "snaps", snapshot_keep=100
    )
    req = store.create_request(
        host="phoenix", user="agent", argv=["uptime"], cwd="/tmp", ttl_s=60
    )
    assert req is not None
    store.decide(req["id"], "approve")
    assert store.generation() == gen + 2

    names = snapshot_names(tmp_path / "phoenix" / "snaps")
    assert snapshot_gens(names)[-2:] == [gen + 1, gen + 2]
    store.close()


# ---------------------------------------------------------- server wiring


def server_env(monkeypatch, tmp_path, *, state=None, snapshots=None, keep=None):
    from gate.tokens import hash_token

    (tmp_path / "tokens.conf").write_text(
        f"web01 {hash_token('raw-server-test-token')}\n", encoding="utf-8"
    )
    monkeypatch.setenv("NEKO_SUDO_DB", str(tmp_path / "share" / "gate.sqlite3"))
    monkeypatch.setenv("NEKO_SUDO_PASSKEYS",
                       str(tmp_path / "console-passkeys.json"))
    monkeypatch.setenv("NEKO_SUDO_SESSIONS", str(tmp_path / "sessions.json"))
    monkeypatch.setenv("NEKO_SUDO_TOKENS_FILE", str(tmp_path / "tokens.conf"))
    monkeypatch.setenv("NEKO_SUDO_ORIGIN", "https://sudo.example.com")
    monkeypatch.setenv("NEKO_SUDO_RP_ID", "sudo.example.com")
    if state:
        monkeypatch.setenv("NEKO_SUDO_STATE", str(state))
    if snapshots:
        monkeypatch.setenv("NEKO_SUDO_SNAPSHOTS", str(snapshots))
    if keep:
        monkeypatch.setenv("NEKO_SUDO_SNAPSHOT_KEEP", str(keep))


def test_build_app_boots_design_a_from_legacy_share_db(tmp_path, monkeypatch):
    """NEKO_SUDO_STATE moves the live db off the replicated share: on boot
    the legacy share db is imported into node-local state, and every
    committed request publishes a snapshot to the replicated dir."""
    from fastapi.testclient import TestClient
    from gate.server import build_app

    legacy, _, gen = fabricate(tmp_path / "legacy-src", commits=4)
    # the legacy db lives exactly at NEKO_SUDO_DB, like the real share db
    (tmp_path / "share").mkdir(parents=True, exist_ok=True)
    os.replace(legacy, tmp_path / "share" / "gate.sqlite3")
    legacy = tmp_path / "share" / "gate.sqlite3"
    state = tmp_path / "node-local" / "gate.sqlite3"
    snaps = tmp_path / "replicated" / "snapshots"
    server_env(monkeypatch, tmp_path, state=state, snapshots=snaps)

    client = TestClient(build_app())
    res = client.post(
        "/v1/requests",
        json={"user": "agent", "argv": ["true"], "cwd": "/tmp"},
        headers={"Authorization": "Bearer raw-server-test-token"},
    )
    assert res.status_code == 201, res.text

    # live db is node-local, generation continues from the imported line
    from gate.store import RequestStore

    store = RequestStore(state)
    assert store.generation() == gen + 1
    store.close()

    # the new commit published a NEW snapshot to the replicated dir
    names = snapshot_names(snaps)
    assert snapshot_gens(names)[-1] == gen + 1

    # the share db was moved aside, never deleted
    assert not legacy.exists()
    assert list((tmp_path / "share").glob("gate.sqlite3.imported-*"))


def test_build_app_without_state_env_is_unchanged_legacy_layout(
        tmp_path, monkeypatch):
    """Deployments that never set NEKO_SUDO_STATE must behave exactly as
    before: the live db is NEKO_SUDO_DB and nothing is ever snapshotted."""
    from fastapi.testclient import TestClient
    from gate.server import build_app

    server_env(monkeypatch, tmp_path)
    client = TestClient(build_app())
    res = client.post(
        "/v1/requests",
        json={"user": "agent", "argv": ["true"], "cwd": "/tmp"},
        headers={"Authorization": "Bearer raw-server-test-token"},
    )
    assert res.status_code == 201, res.text

    assert (tmp_path / "share" / "gate.sqlite3").exists()
    assert not list(tmp_path.rglob("gate-*-*.db")), \
        "no snapshot may appear without NEKO_SUDO_STATE"
