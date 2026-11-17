import time

import pytest

def make_store(tmp_path, clock=None):
    from gate.store import RequestStore

    return RequestStore(tmp_path / "gate.sqlite3", clock=clock or time.time)

def test_concurrent_thread_use_does_not_corrupt_reads(tmp_path):
    """The store shares one sqlite connection across threads by design
    (check_same_thread=False). One connection means one shared
    prepared-statement cache: unserialized cross-thread use interleaves
    bind/step on the same sqlite3_stmt and corrupts reads (json.loads(None)
    when one thread decides while another polls; reproduces in <0.1s).
    Every store operation must therefore be atomic under a lock."""
    import threading

    store = make_store(tmp_path)
    errors = []
    stop = threading.Event()
    ids = []

    def creator():
        for i in range(200):
            try:
                r = store.create_request(
                    host="web01", user="agent",
                    argv=["apt", "update", str(i)], cwd="/tmp", ttl_s=60,
                )
                assert r is not None, "create_request lost its own row"
                if r["argv"] != ["apt", "update", str(i)]:
                    errors.append(f"creator iter {i}: bad readback {r['argv']!r}")
                    stop.set()
                    return
                ids.append(r["id"])
                store.decide(r["id"], "approve")
            except Exception as exc:  # noqa: BLE001
                errors.append(f"creator iter {i}: {exc!r}")
                stop.set()
                return
        stop.set()  # success also releases the poller

    def poller():
        while not stop.is_set():
            for rid in tuple(ids)[-5:]:
                try:
                    r = store.get_request(rid)
                    if r is not None and (r["argv"] is None or r["id"] != rid):
                        errors.append(f"poller: corrupt read for {rid}")
                        stop.set()
                        return
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"poller: {exc!r}")
                    stop.set()
                    return

    threads = [threading.Thread(target=creator), threading.Thread(target=poller)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not errors, errors[:3]
    assert len(ids) == 200, "creator stopped early (see errors)"

def test_create_request_persists_pending(tmp_path):
    store = make_store(tmp_path)
    req = store.create_request(
        host="web01",
        user="agent",
        argv=["systemctl", "restart", "nginx"],
        cwd="/home/agent",
        ttl_s=120,
    )
    assert req["status"] == "pending"
    assert req["host"] == "web01"
    assert req["user"] == "agent"

    fetched = store.get_request(req["id"])
    assert fetched is not None
    assert fetched["argv"] == ["systemctl", "restart", "nginx"]
    assert fetched["cwd"] == "/home/agent"
    assert fetched["digest"], "request must carry a digest binding its payload"

def test_request_expires_after_ttl(tmp_path):
    now = {"t": 1000.0}
    store = make_store(tmp_path, clock=lambda: now["t"])
    req = store.create_request(
        host="web01", user="agent", argv=["true"], cwd="/tmp", ttl_s=120
    )
    assert store.get_request(req["id"])["status"] == "pending"

    now["t"] += 121.0
    assert store.get_request(req["id"])["status"] == "expired"

def test_approve_marks_request_approved(tmp_path):
    store = make_store(tmp_path)
    req = store.create_request(
        host="web01", user="agent", argv=["apt", "update"], cwd="/tmp", ttl_s=120
    )
    decided = store.decide(req["id"], "approve")
    assert decided["status"] == "approved"
    assert decided["decided_at"] is not None
    assert store.get_request(req["id"])["status"] == "approved"

def test_decision_is_single_use(tmp_path):
    store = make_store(tmp_path)
    req = store.create_request(
        host="web01", user="agent", argv=["true"], cwd="/tmp", ttl_s=120
    )
    store.decide(req["id"], "deny")

    with pytest.raises(ValueError):
        store.decide(req["id"], "approve")
    assert store.get_request(req["id"])["status"] == "denied"

def test_expired_request_cannot_be_approved(tmp_path):
    now = {"t": 1000.0}
    store = make_store(tmp_path, clock=lambda: now["t"])
    req = store.create_request(
        host="web01", user="agent", argv=["true"], cwd="/tmp", ttl_s=60
    )
    now["t"] += 61.0

    with pytest.raises(ValueError):
        store.decide(req["id"], "approve")
    assert store.get_request(req["id"])["status"] == "expired"

def test_decide_unknown_request_raises(tmp_path):

    store = make_store(tmp_path)
    with pytest.raises(LookupError):
        store.decide("no-such-id", "approve")


def test_pending_requests_lists_only_live_pending(tmp_path):
    now = {"t": 1000.0}
    store = make_store(tmp_path, clock=lambda: now["t"])
    older = store.create_request(
        host="web01", user="agent", argv=["apt", "update"], cwd="/tmp", ttl_s=120
    )
    newer = store.create_request(
        host="db01", user="agent", argv=["systemctl", "restart", "pg"], cwd="/tmp", ttl_s=300
    )
    decided = store.create_request(
        host="web01", user="agent", argv=["true"], cwd="/tmp", ttl_s=120
    )
    store.decide(decided["id"], "deny")

    pending = store.pending_requests()
    assert [r["id"] for r in pending] == [older["id"], newer["id"]]
    assert pending[0]["host"] == "web01" and pending[1]["host"] == "db01"

    now["t"] += 121.0  # older expires; newer (300 s) survives
    pending = store.pending_requests()
    assert [r["id"] for r in pending] == [newer["id"]]
    assert store.get_request(older["id"])["status"] == "expired"


def make_request(store, now, argv, *, decision=None, ttl_s=120):
    request = store.create_request(
        host="web01", user="agent", argv=argv, cwd="/tmp", ttl_s=ttl_s
    )
    now["t"] += 1.0
    if decision:
        store.decide(request["id"], decision)
    return request


def test_finished_requests_newest_first_and_never_pending(tmp_path):
    """Console history: the cards that are done (approved / denied /
    expired), newest first. Pending cards already have their own section."""
    now = {"t": 1000.0}
    store = make_store(tmp_path, clock=lambda: now["t"])
    make_request(store, now, ["apt", "update"], decision="approve")
    make_request(store, now, ["reboot"], decision="deny")
    make_request(store, now, ["true"])  # still pending

    page = store.finished_requests(limit=5, offset=0)

    assert [r["argv"] for r in page["items"]] == [["reboot"], ["apt", "update"]]
    assert [r["status"] for r in page["items"]] == ["denied", "approved"]
    assert page["total"] == 2


def test_finished_requests_page_by_offset(tmp_path):
    now = {"t": 1000.0}
    store = make_store(tmp_path, clock=lambda: now["t"])
    for i in range(7):
        make_request(store, now, ["echo", str(i)], decision="approve")

    first = store.finished_requests(limit=5, offset=0)
    second = store.finished_requests(limit=5, offset=5)

    assert [r["argv"][1] for r in first["items"]] == ["6", "5", "4", "3", "2"]
    assert [r["argv"][1] for r in second["items"]] == ["1", "0"]
    assert first["total"] == second["total"] == 7


def test_finished_requests_show_unanswered_cards_as_expired(tmp_path):
    """A card nobody answered is history too. Expiry is lazy in the store,
    so the history query must expire stale rows itself, not hide them."""
    now = {"t": 1000.0}
    store = make_store(tmp_path, clock=lambda: now["t"])
    make_request(store, now, ["uptime"], ttl_s=60)
    now["t"] += 61.0

    page = store.finished_requests(limit=5, offset=0)

    assert [(r["argv"], r["status"]) for r in page["items"]] == [(["uptime"], "expired")]
    assert page["total"] == 1

