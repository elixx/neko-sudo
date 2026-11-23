"""The owner-facing side of same-host ordering.

Only the first pending request of a host's series can be decided: approve
and deny on a later one are refused (before any passkey ceremony is
spent). Cards, the review screen and the push say where a request
sits in its host's queue ("2 of 3 pending on <host>").
"""
from __future__ import annotations

from test_console import (
    ORIGIN,
    auth,
    enroll_owner_passkey,
    login,
    make_assertion_fields,
    make_env,
)


def create(store, host="web01", argv=("true",)):
    return store.create_request(host=host, user="agent", argv=list(argv),
                                cwd="/home/agent", ttl_s=120)


def signed_in(tmp_path):
    client, store, passkeys, _, clock = make_env(tmp_path)
    signer = enroll_owner_passkey(client, passkeys)
    raw = login(client, signer, sign_count=2)
    return client, store, signer, raw


def test_approve_options_refused_while_earlier_same_host_pending(tmp_path):
    client, store, _, raw = signed_in(tmp_path)
    a = create(store, argv=["systemctl", "stop", "x"])
    b = create(store, argv=["systemctl", "start", "x"])

    res = client.post(f"/approvals/{b['id']}/approve/options", headers=auth(raw))
    assert res.status_code == 409, res.text
    detail = res.json()["detail"]
    assert detail["code"] == "earlier_pending"
    assert detail["earlier"] == [{"id": a["id"], "argv": ["systemctl", "stop", "x"]}]
    assert store.get_request(b["id"])["status"] == "pending"

    # The earlier request itself is not blocked.
    ok = client.post(f"/approvals/{a['id']}/approve/options", headers=auth(raw))
    assert ok.status_code == 200, ok.text


def test_approve_raced_past_options_is_refused_not_500(tmp_path):
    """Defense in depth: if the options check is ever bypassed (a race, a
    future refactor), the approve itself answers 409 earlier_pending and
    the store's own guard keeps B pending."""
    client, store, signer, raw = signed_in(tmp_path)
    create(store)
    b = create(store)
    real = store.earlier_pending
    store.earlier_pending = lambda request_id: []  # simulate the race
    try:
        options = client.post(f"/approvals/{b['id']}/approve/options",
                              headers=auth(raw)).json()
        fields = make_assertion_fields(challenge_b64=options["options"]["challenge"],
                                       signer=signer, sign_count=3)
        res = client.post(f"/approvals/{b['id']}/approve",
                          json={"challenge_id": options["challenge_id"], **fields},
                          headers=auth(raw))
    finally:
        store.earlier_pending = real
    assert res.status_code == 409, res.text
    assert res.json()["detail"]["code"] == "earlier_pending"
    assert store.get_request(b["id"])["status"] == "pending"


def test_approve_checks_order_before_spending_the_challenge(tmp_path):
    client, store, signer, raw = signed_in(tmp_path)
    b_first = create(store)
    options = client.post(f"/approvals/{b_first['id']}/approve/options",
                          headers=auth(raw)).json()
    # Not reachable in production (later requests get later seqs), so pin
    # the endpoint's own pre-check directly: it must run before the
    # challenge is consumed.
    real = store.earlier_pending
    store.earlier_pending = lambda request_id: [
        {"id": "earlier-x", "argv": ["true"], "host": "web01"}]
    try:
        fields = make_assertion_fields(challenge_b64=options["options"]["challenge"],
                                       signer=signer, sign_count=3)
        res = client.post(f"/approvals/{b_first['id']}/approve",
                          json={"challenge_id": options["challenge_id"], **fields},
                          headers=auth(raw))
    finally:
        store.earlier_pending = real
    assert res.status_code == 409
    assert res.json()["detail"]["earlier"] == [{"id": "earlier-x", "argv": ["true"]}]
    # The challenge was not consumed: the same ceremony can still finish.
    res = client.post(f"/approvals/{b_first['id']}/approve",
                      json={"challenge_id": options["challenge_id"], **fields},
                      headers=auth(raw))
    assert res.status_code == 200, res.text


def test_deny_refused_while_earlier_same_host_pending(tmp_path):
    """Only a decision on the first card of a series is possible, so
    deny is refused like approve."""
    client, store, _, raw = signed_in(tmp_path)
    a = create(store, argv=["stop"])
    b = create(store, argv=["start"])
    res = client.post(f"/approvals/{b['id']}/deny", headers=auth(raw))
    assert res.status_code == 409, res.text
    assert res.json()["detail"]["code"] == "earlier_pending"
    assert res.json()["detail"]["earlier"] == [{"id": a["id"], "argv": ["stop"]}]
    assert store.get_request(b["id"])["status"] == "pending"
    assert client.post(f"/approvals/{a['id']}/deny", headers=auth(raw)).status_code == 200
    assert client.post(f"/approvals/{b['id']}/deny", headers=auth(raw)).status_code == 200


def test_raced_deny_maps_to_409_not_500(tmp_path):
    client, store, _, raw = signed_in(tmp_path)
    create(store)
    b = create(store)
    real = store.earlier_pending
    store.earlier_pending = lambda request_id: []  # bypass the pre-check
    try:
        res = client.post(f"/approvals/{b['id']}/deny", headers=auth(raw))
    finally:
        store.earlier_pending = real
    assert res.status_code == 409, res.text
    assert res.json()["detail"]["code"] == "earlier_pending"
    assert store.get_request(b["id"])["status"] == "pending"


# ---------------------------------------------------------- stale console

def test_approvals_and_console_js_carry_the_same_build_id(tmp_path):
    import re

    from gate.console import BUILD_ID

    client, _, _, raw = signed_in(tmp_path)
    assert re.fullmatch(r"[0-9a-f]{16}", BUILD_ID)
    assert client.get("/approvals", headers=auth(raw)).json()["build"] == BUILD_ID
    js = client.get("/console.js", headers=auth(raw)).text
    assert js.count(f"const PAGE_BUILD='{BUILD_ID}';") == 1


def test_console_page_and_script_are_never_cached(tmp_path):
    """A cached console.js would make the build-id reload loop forever.
    The sign-in page, its script and the service worker follow suit."""
    client, _, _, raw = signed_in(tmp_path)
    for path in ("/", "/console.js", "/signin.js", "/sw.js"):
        res = client.get(path, headers=auth(raw))
        assert res.status_code == 200
        assert res.headers.get("cache-control") == "no-store", path
    anonymous = client.get("/", headers={"origin": ORIGIN})
    assert "console.js" not in anonymous.text
    assert anonymous.headers.get("cache-control") == "no-store"


def test_served_console_script_keeps_strict_mode(tmp_path):
    """Anything prepended before 'use strict' demotes the directive and
    runs the whole console (agent-controlled rendering included) in
    sloppy mode. The directive must stay the first line."""
    client, _, _, raw = signed_in(tmp_path)
    js = client.get("/console.js", headers=auth(raw)).text
    assert js.split("\n", 1)[0] == "'use strict';"


def test_cards_carry_queue_position_and_earlier_requests(tmp_path):
    client, store, _, raw = signed_in(tmp_path)
    a = create(store, argv=["stop"])
    other = create(store, host="web02", argv=["uptime"])
    b = create(store, argv=["start"])

    cards = {c["id"]: c for c in client.get("/approvals", headers=auth(raw)).json()["pending"]}
    assert cards[a["id"]]["queue"] == {"position": 1, "total": 2}
    assert cards[a["id"]]["earlier"] == []
    assert cards[b["id"]]["queue"] == {"position": 2, "total": 2}
    assert cards[b["id"]]["earlier"] == [{"id": a["id"], "argv": ["stop"]}]
    assert cards[other["id"]]["queue"] == {"position": 1, "total": 1}

    detail = client.get(f"/approvals/{b['id']}", headers=auth(raw)).json()
    assert detail["queue"] == {"position": 2, "total": 2}
    assert detail["earlier"] == [{"id": a["id"], "argv": ["stop"]}]

    store.decide(a["id"], "deny")
    detail = client.get(f"/approvals/{b['id']}", headers=auth(raw)).json()
    assert detail["queue"] == {"position": 1, "total": 1}
    assert detail["earlier"] == []


# ------------------------------------------------------------------- push

def test_create_hands_queue_position_to_push(tmp_path):
    import time

    from fastapi.testclient import TestClient

    from gate.app import create_app
    from gate.store import RequestStore
    from gate.tokens import hash_token

    seen = []

    class Push:
        def request_created(self, request):
            seen.append(request)

    store = RequestStore(tmp_path / "gate.sqlite3", clock=time.time)
    client = TestClient(create_app(store, tokens={"web01": hash_token("tok")},
                                   push=Push()))
    hdr = {"Authorization": "Bearer tok"}
    body = {"user": "agent", "cwd": "/tmp"}
    first = client.post("/v1/requests", json={**body, "argv": ["stop"]}, headers=hdr).json()
    client.post("/v1/requests", json={**body, "argv": ["start"]}, headers=hdr)
    assert [r["queue"] for r in seen] == [
        {"position": 1, "total": 1}, {"position": 2, "total": 2}]
    # The wrapper's create response is unchanged by the push enrichment.
    assert "queue" not in first


def test_push_body_names_queue_position_when_stacked(tmp_path):
    import json

    from gate.subscriptions import SubscriptionStore
    from gate.vapid import load_or_generate
    from gate.webpush import WebPushPush

    subs = SubscriptionStore(tmp_path / "subs.json")
    subs.add({"endpoint": "https://push.example/a",
              "keys": {"p256dh": "p", "auth": "a"}})
    sent = []
    sender = WebPushPush(subs, load_or_generate(tmp_path / "vapid.json"),
                         send_fn=lambda sub, data, ttl: sent.append(json.loads(data)) or 201,
                         now=lambda: 1900.0, subject="mailto:admin@example.com")
    base = {"id": "req-1", "host": "web01", "argv": ["systemctl", "start", "x"],
            "expires_at": 2000.0}
    sender.request_created({**base, "queue": {"position": 2, "total": 3}})
    sender.request_created({**base, "queue": {"position": 1, "total": 1}})
    sender.request_created(base)
    assert sent[0]["body"] == "(2 of 3) web01 \u00b7 systemctl start x"
    assert sent[1]["body"] == "web01 \u00b7 systemctl start x"
    assert sent[2]["body"] == "web01 \u00b7 systemctl start x"
