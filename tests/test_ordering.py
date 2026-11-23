"""Same-host request ordering.

Start-order guarantee, enforced by the gate alone:
  * a request cannot be APPROVED while an earlier request from the same
    host is still pending (deny stays allowed);
  * an approved request is not HANDED to its wrapper (host poll answers
    "pending" + held_behind) until every earlier same-host request is
    settled: denied, expired, delivered, or approved-but-uncollected past
    expires_at + 30 s;
  * an approved request nobody collected by expires_at + 30 s can no longer
    be delivered (host poll answers "expired").
Per host only; legacy rows without host_seq never block and are never held.
"""
from __future__ import annotations

import json
import sqlite3

import pytest

from gate.store import EarlierPending, RequestStore, UNCOLLECTED_CUTOFF_S

T0 = 1_760_000_000.0
TTL = 300


class Clock:
    def __init__(self, now: float = T0):
        self.now = now

    def __call__(self) -> float:
        return self.now


def make(tmp_path, clock=None):
    clock = clock or Clock()
    return RequestStore(tmp_path / "gate.sqlite3", clock=clock), clock


def create(store, host="web01", argv=("true",)):
    return store.create_request(host=host, user="agent", argv=list(argv),
                                cwd="/tmp", ttl_s=TTL)


# ----------------------------------------------------------- sequence

def test_host_seq_counts_up_per_host(tmp_path):
    store, _ = make(tmp_path)
    a = create(store, "web01")
    b = create(store, "web01")
    c = create(store, "web02")
    assert (a["host_seq"], b["host_seq"], c["host_seq"]) == (1, 2, 1)


# ------------------------------------------------------------- approve guard

def test_approving_later_request_is_refused_while_earlier_is_pending(tmp_path):
    store, _ = make(tmp_path)
    a = create(store, argv=["systemctl", "stop", "x"])
    b = create(store, argv=["systemctl", "start", "x"])
    with pytest.raises(EarlierPending) as exc:
        store.decide(b["id"], "approve")
    assert exc.value.earlier_ids == [a["id"]]
    assert store.get_request(b["id"])["status"] == "pending"


def test_denying_later_request_is_refused_while_earlier_is_pending(tmp_path):
    """Only the first request of a host's series can be decided at all,
    deny included."""
    store, _ = make(tmp_path)
    a = create(store)
    b = create(store)
    with pytest.raises(EarlierPending) as exc:
        store.decide(b["id"], "deny")
    assert exc.value.earlier_ids == [a["id"]]
    assert store.get_request(b["id"])["status"] == "pending"
    store.decide(a["id"], "deny")
    assert store.decide(b["id"], "deny")["status"] == "denied"


def test_earlier_pending_lists_only_earlier_pending_same_host(tmp_path):
    store, clock = make(tmp_path)
    a = create(store)
    create(store, "web02")
    b = create(store)
    c = create(store)
    assert [r["id"] for r in store.earlier_pending(c["id"])] == [a["id"], b["id"]]
    store.decide(a["id"], "deny")
    assert [r["id"] for r in store.earlier_pending(c["id"])] == [b["id"]]
    assert store.earlier_pending(a["id"]) == []


def test_expired_earlier_request_does_not_block_approval(tmp_path):
    store, clock = make(tmp_path)
    create(store)
    clock.now += 10
    b = create(store)
    clock.now = T0 + TTL  # A's window is over, B still has 10 s
    assert store.decide(b["id"], "approve")["status"] == "approved"


# -------------------------------------------------------- hold on poll

def test_approved_request_is_held_until_earlier_is_delivered(tmp_path):
    store, clock = make(tmp_path)
    a = create(store)
    b = create(store)
    store.decide(a["id"], "approve")
    store.decide(b["id"], "approve")

    held = store.poll_for_host(b["id"], "web01")
    assert held["status"] == "pending"
    assert held["held_behind"] == [a["id"]]
    assert held["digest"] == b["digest"]

    assert store.poll_for_host(a["id"], "web01")["status"] == "approved"
    released = store.poll_for_host(b["id"], "web01")
    assert released["status"] == "approved"
    assert released["held_behind"] == []


def test_denied_earlier_request_releases_the_next(tmp_path):
    store, _ = make(tmp_path)
    a = create(store)
    b = create(store)
    store.decide(a["id"], "deny")
    store.decide(b["id"], "approve")
    assert store.poll_for_host(b["id"], "web01")["status"] == "approved"


def test_expired_earlier_request_releases_the_next(tmp_path):
    store, clock = make(tmp_path)
    create(store)
    clock.now += 10
    b = create(store)
    clock.now = T0 + TTL
    store.decide(b["id"], "approve")
    assert store.poll_for_host(b["id"], "web01")["status"] == "approved"


def test_uncollected_approval_blocks_until_cutoff_then_never_delivers(tmp_path):
    store, clock = make(tmp_path)
    a = create(store)
    clock.now += 10
    b = create(store)
    store.decide(a["id"], "approve")  # A's wrapper died: never polls
    store.decide(b["id"], "approve")

    clock.now = a["expires_at"] + UNCOLLECTED_CUTOFF_S - 1
    assert store.poll_for_host(b["id"], "web01")["status"] == "pending"

    clock.now = a["expires_at"] + UNCOLLECTED_CUTOFF_S
    assert store.poll_for_host(b["id"], "web01")["status"] == "approved"
    # A late poll for A after its cutoff must not run A after B.
    late = store.poll_for_host(a["id"], "web01")
    assert late["status"] == "expired"
    assert store.get_request(a["id"])["delivered_at"] is None


def passed_over_pair(tmp_path):
    """A and B from one host, both approved; A's wrapper is gone. At A's
    cutoff B is handed over: A has been passed over for good."""
    store, clock = make(tmp_path)
    a = create(store, argv=["stop"])
    clock.now += 10
    b = create(store, argv=["start"])
    store.decide(a["id"], "approve")
    store.decide(b["id"], "approve")
    clock.now = a["expires_at"] + UNCOLLECTED_CUTOFF_S
    assert store.poll_for_host(b["id"], "web01")["status"] == "approved"
    return store, clock, a, b


def test_passed_over_approval_stays_dead_when_the_clock_steps_back(tmp_path):
    """The cutoff must not be recomputed from the wall clock on every
    poll: an NTP step back or a failover to a lagging node would re-arm A
    after B had already run. Passing over is durable."""
    store, clock, a, _ = passed_over_pair(tmp_path)
    clock.now = a["expires_at"] + UNCOLLECTED_CUTOFF_S - 20
    late = store.poll_for_host(a["id"], "web01")
    assert late["status"] == "expired"
    assert store.get_request(a["id"])["delivered_at"] is None


def test_passed_over_marker_survives_failover_to_a_lagging_node(tmp_path):
    store, clock, a, b = passed_over_pair(tmp_path)
    store.close()
    lagging = Clock(a["expires_at"] + UNCOLLECTED_CUTOFF_S - 25)
    store = RequestStore(tmp_path / "gate.sqlite3", clock=lagging)
    assert store.poll_for_host(a["id"], "web01")["status"] == "expired"
    assert store.poll_for_host(b["id"], "web01")["status"] == "approved"


def test_passing_over_commits_with_the_hand_over(tmp_path):
    """B's delivery and A's passed-over marker land in ONE generation, so
    no snapshot can hold B delivered while A is still deliverable."""
    store, clock = make(tmp_path)
    a = create(store)
    clock.now += 10
    b = create(store)
    store.decide(a["id"], "approve")
    store.decide(b["id"], "approve")
    gen = store.generation()
    clock.now = a["expires_at"] + UNCOLLECTED_CUTOFF_S
    store.poll_for_host(b["id"], "web01")
    assert store.generation() == gen + 1
    assert store.get_request(a["id"])["uncollected_at"] == clock.now
    assert store.get_request(b["id"])["delivered_at"] == clock.now


def test_uncollected_cutoff_is_thirty_seconds():
    assert UNCOLLECTED_CUTOFF_S == 30


def test_chain_releases_in_order(tmp_path):
    store, _ = make(tmp_path)
    a, b, c = create(store), create(store), create(store)
    for r in (a, b, c):
        store.decide(r["id"], "approve")
    assert store.poll_for_host(c["id"], "web01")["held_behind"] == [a["id"], b["id"]]
    assert store.poll_for_host(b["id"], "web01")["held_behind"] == [a["id"]]
    assert store.poll_for_host(a["id"], "web01")["status"] == "approved"
    assert store.poll_for_host(c["id"], "web01")["held_behind"] == [b["id"]]
    assert store.poll_for_host(b["id"], "web01")["status"] == "approved"
    assert store.poll_for_host(c["id"], "web01")["status"] == "approved"


def test_other_hosts_never_block(tmp_path):
    store, _ = make(tmp_path)
    create(store, "web01")
    other = create(store, "web02")
    assert store.decide(other["id"], "approve")["status"] == "approved"
    assert store.poll_for_host(other["id"], "web02")["status"] == "approved"


def test_pending_and_denied_polls_are_unchanged(tmp_path):
    store, _ = make(tmp_path)
    a = create(store)
    view = store.poll_for_host(a["id"], "web01")
    assert view["status"] == "pending" and view["held_behind"] == []
    store.decide(a["id"], "deny")
    assert store.poll_for_host(a["id"], "web01")["status"] == "denied"


def test_delivery_is_recorded_once_and_bumps_generation(tmp_path):
    store, clock = make(tmp_path)
    a = create(store)
    store.decide(a["id"], "approve")
    gen = store.generation()
    clock.now += 2
    store.poll_for_host(a["id"], "web01")
    assert store.get_request(a["id"])["delivered_at"] == T0 + 2
    assert store.generation() == gen + 1, "delivery must reach the snapshots"
    clock.now += 2
    assert store.poll_for_host(a["id"], "web01")["status"] == "approved"
    assert store.get_request(a["id"])["delivered_at"] == T0 + 2
    assert store.generation() == gen + 1


def test_poll_by_another_host_has_no_side_effects(tmp_path):
    store, _ = make(tmp_path)
    a = create(store)
    b = create(store)
    store.decide(a["id"], "approve")
    store.decide(b["id"], "approve")
    assert store.poll_for_host(a["id"], "web02") is None
    assert store.poll_for_host("no-such-id", "web01") is None
    assert store.get_request(a["id"])["delivered_at"] is None
    assert store.poll_for_host(b["id"], "web01")["status"] == "pending"


# ------------------------------------------------- legacy + migration

OLD_SCHEMA = """
CREATE TABLE requests (
    id TEXT PRIMARY KEY, host TEXT NOT NULL, user TEXT NOT NULL,
    argv TEXT NOT NULL, cwd TEXT NOT NULL, digest TEXT NOT NULL,
    status TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL,
    decided_at REAL)
"""
OLD_INSERT = (
    "INSERT INTO requests (id, host, user, argv, cwd, digest, status,"
    " created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)"
)


def old_image_insert(path, request_id, host="web01", now=T0):
    conn = sqlite3.connect(str(path))
    conn.execute(OLD_INSERT, (request_id, host, "agent", json.dumps(["true"]),
                              "/tmp", "d" * 64, now, now + TTL))
    conn.commit()
    conn.close()


def test_boot_migrates_a_pre_change_db(tmp_path):
    path = tmp_path / "gate.sqlite3"
    conn = sqlite3.connect(str(path))
    conn.execute(OLD_SCHEMA)
    conn.commit()
    conn.close()
    old_image_insert(path, "legacy-a")

    store = RequestStore(path, clock=Clock())
    legacy = store.get_request("legacy-a")
    assert legacy["host_seq"] is None and legacy["delivered_at"] is None
    b = create(store)
    assert b["host_seq"] == 1
    # The legacy pending row neither blocks approval nor holds delivery.
    store.decide(b["id"], "approve")
    assert store.poll_for_host(b["id"], "web01")["status"] == "approved"


def test_old_image_can_still_write_and_read_a_migrated_db(tmp_path):
    """Rollback safety: the previous image names its INSERT columns and
    reads rows by key, so the two nullable columns are invisible to it."""
    store, _ = make(tmp_path)
    a = create(store)
    store.close()
    path = tmp_path / "gate.sqlite3"
    old_image_insert(path, "written-by-old-image")
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM requests WHERE id = ?", (a["id"],)).fetchone()
    assert {k: row[k] for k in ("id", "host", "status")} == {
        "id": a["id"], "host": "web01", "status": "pending"}
    conn.close()

    store = RequestStore(path, clock=Clock())
    # Roll forward again: the old image's row is legacy, numbering continues.
    assert store.get_request("written-by-old-image")["host_seq"] is None
    assert create(store)["host_seq"] == 2


def test_migration_is_idempotent(tmp_path):
    store, _ = make(tmp_path)
    create(store)
    store.close()
    store = RequestStore(tmp_path / "gate.sqlite3", clock=Clock())
    assert create(store)["host_seq"] == 2


# ---------------------------------------------------------- host API

def test_host_api_poll_holds_out_of_order_approval(tmp_path):
    from fastapi.testclient import TestClient

    from gate.app import create_app
    from gate.tokens import hash_token

    clock = Clock()
    store = RequestStore(tmp_path / "gate.sqlite3", clock=clock)
    client = TestClient(create_app(store, tokens={"web01": hash_token("tok")},
                                   clock=clock))
    auth = {"Authorization": "Bearer tok"}
    body = {"user": "agent", "cwd": "/tmp"}
    a = client.post("/v1/requests", json={**body, "argv": ["stop"]}, headers=auth).json()
    b = client.post("/v1/requests", json={**body, "argv": ["start"]}, headers=auth).json()
    store.decide(a["id"], "approve")
    store.decide(b["id"], "approve")

    held = client.get(f"/v1/requests/{b['id']}", headers=auth).json()
    assert held["status"] == "pending"
    assert held["held_behind"] == [a["id"]]
    assert client.get(f"/v1/requests/{a['id']}", headers=auth).json()["status"] == "approved"
    assert client.get(f"/v1/requests/{b['id']}", headers=auth).json()["status"] == "approved"
