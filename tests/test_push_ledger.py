"""Push send ledger: every delivery attempt leaves one JSON line.

Without a ledger, "never sent", "send failed" and "sent but the browser
held it" are indistinguishable after the fact, so a missed notification
cannot be attributed. The ledger is diagnostics, never a dependency:
it must not break delivery, and it never stores the endpoint URL (a
delivery capability) — only the push-service host and a short tag.
"""

import json

import pytest
from test_webpush import REQUEST, SUB_A, Recorder


def make_sender(store, keys, recorder, ledger, now=lambda: 1900.0):
    from gate.webpush import WebPushPush

    return WebPushPush(
        store,
        keys,
        send_fn=recorder,
        now=now,
        subject="mailto:admin@example.com",
        ledger=ledger,
    )


def lines(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_successful_send_leaves_one_attributable_line(tmp_path):
    from gate.pushledger import PushLedger
    from gate.subscriptions import SubscriptionStore
    from gate.vapid import load_or_generate

    store = SubscriptionStore(tmp_path / "subs.json")
    store.add(SUB_A)
    path = tmp_path / "push-ledger.jsonl"
    make_sender(
        store, load_or_generate(tmp_path / "vapid.json"), Recorder(), PushLedger(path)
    ).request_created(REQUEST)

    [record] = lines(path)
    assert record["request"] == "req-9"
    assert record["host"] == "web01"
    assert record["endpoint"] == "push.example", "push-service host only"
    assert len(record["endpoint_tag"]) == 8
    assert record["ttl"] == 100
    assert record["ok"] is True
    assert record["status"] == 201
    assert record["ts"] and isinstance(record["ms"], int)
    assert "push.example/a" not in path.read_text(), "endpoint URL is a capability"


def make_store_and_keys(tmp_path):
    from gate.subscriptions import SubscriptionStore
    from gate.vapid import load_or_generate

    store = SubscriptionStore(tmp_path / "subs.json")
    store.add(SUB_A)
    return store, load_or_generate(tmp_path / "vapid.json")


@pytest.mark.parametrize(
    "result, expected",
    [
        # Transport blew up (timeout, DNS, TLS): no HTTP status at all.
        (RuntimeError("boom"), {"ok": False, "error": "RuntimeError"}),
        # Push service answered but refused: 429 quota, 5xx outage.
        (503, {"ok": False, "status": 503, "gone": False}),
        (429, {"ok": False, "status": 429, "gone": False}),
        # Subscription is dead: pruned, and the ledger says so.
        (410, {"ok": False, "status": 410, "gone": True}),
    ],
)
def test_failed_sends_are_recorded_not_just_successes(tmp_path, result, expected):
    from gate.pushledger import PushLedger

    store, keys = make_store_and_keys(tmp_path)
    path = tmp_path / "push-ledger.jsonl"
    rec = Recorder(results={SUB_A["endpoint"]: result})
    make_sender(store, keys, rec, PushLedger(path)).request_created(REQUEST)

    [record] = lines(path)
    assert record["request"] == "req-9"
    for key, value in expected.items():
        assert record[key] == value, key


def test_request_with_no_subscriptions_is_recorded_as_never_sent(tmp_path):
    """Zero subscriptions = nothing goes out. That is exactly the case that
    looks like a lost push from the phone, so it must leave a line too."""
    from gate.pushledger import PushLedger
    from gate.subscriptions import SubscriptionStore
    from gate.vapid import load_or_generate

    path = tmp_path / "push-ledger.jsonl"
    rec = Recorder()
    make_sender(
        SubscriptionStore(tmp_path / "subs.json"),
        load_or_generate(tmp_path / "vapid.json"),
        rec,
        PushLedger(path),
    ).request_created(REQUEST)

    assert rec.calls == []
    [record] = lines(path)
    assert record["request"] == "req-9"
    assert record["ok"] is False
    assert record["error"] == "no_subscriptions"


def test_unwritable_ledger_never_breaks_delivery(tmp_path):
    """The ledger is diagnostics. A full disk or a bad path must cost the
    record, never the wake-up."""
    from gate.pushledger import PushLedger

    store, keys = make_store_and_keys(tmp_path)
    blocked = tmp_path / "is-a-directory"
    blocked.mkdir()
    ledger = PushLedger(blocked)
    rec = Recorder()

    make_sender(store, keys, rec, ledger).request_created(REQUEST)  # must not raise

    assert [c[0]["endpoint"] for c in rec.calls] == [SUB_A["endpoint"]]
    assert ledger.append({"x": 1}) is False


def test_unrecordable_attempt_never_stops_delivery_to_the_rest(tmp_path):
    """A hand-corrupted subscriptions file (non-string endpoint) must cost
    that one ledger line, never the wake-ups to the remaining browsers."""
    from gate.pushledger import PushLedger
    from gate.subscriptions import SubscriptionStore
    from gate.vapid import load_or_generate

    subs_path = tmp_path / "subs.json"
    subs_path.write_text(
        json.dumps([{"endpoint": 12345, "keys": {"p256dh": "x", "auth": "y"}}, SUB_A]),
        encoding="utf-8",
    )
    path = tmp_path / "push-ledger.jsonl"
    rec = Recorder()

    make_sender(
        SubscriptionStore(subs_path),
        load_or_generate(tmp_path / "vapid.json"),
        rec,
        PushLedger(path),
    ).request_created(REQUEST)  # must not raise

    assert [c[0]["endpoint"] for c in rec.calls] == [12345, SUB_A["endpoint"]]
    assert lines(path)[-1]["endpoint"] == "push.example"


def test_ledger_is_bounded_by_one_rotation(tmp_path):
    """The gate runs for months: the ledger rotates once to ``.1`` (the old
    ``.1`` is replaced), so disk use stays at roughly twice max_bytes."""
    from gate.pushledger import PushLedger

    path = tmp_path / "push-ledger.jsonl"
    ledger = PushLedger(path, max_bytes=300)
    for i in range(200):
        assert ledger.append({"request": f"req-{i}", "pad": "x" * 40}) is True

    rotated = path.with_name(path.name + ".1")
    assert rotated.exists()
    assert path.stat().st_size <= 300
    assert rotated.stat().st_size <= 300
    assert lines(path)[-1]["request"] == "req-199", "newest record is never lost"
    assert {p.name for p in tmp_path.iterdir()} == {path.name, rotated.name}


def test_concurrent_appends_across_rotation_all_land(tmp_path):
    """Background sends run in a threadpool, so near-simultaneous requests
    append concurrently. Rotation is check-then-act (size, then replace):
    unserialised, one writer's replace races another's append and the line
    is lost (or the error lands in stderr). Every append must succeed."""
    import threading

    from gate.pushledger import PushLedger

    path = tmp_path / "push-ledger.jsonl"
    ledger = PushLedger(path, max_bytes=400)
    results = []
    start = threading.Barrier(8)

    def writer(n):
        start.wait()
        for i in range(150):
            results.append(ledger.append({"w": n, "i": i, "pad": "x" * 30}))

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 8 * 150
    assert all(results), f"{results.count(False)} appends lost to the rotation race"
    for p in tmp_path.iterdir():
        lines(p)  # every surviving line is whole JSON
