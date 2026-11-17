"""Console push endpoints: subscribe the owner's browsers, serve the worker."""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from gate.passkeys import ConsolePasskeyStore
from gate.sessions import SessionStore
from gate.store import RequestStore

from test_console import (
    ORIGIN,
    RP_ID,
    FakeClock,
    auth,
    enroll_owner_passkey,
    login,
)
from test_webauthn import SyntheticES256Signer

SUB = {
    "endpoint": "https://push.example/fcm/xyz",
    "keys": {"p256dh": "BPub", "auth": "auth"},
}


def make_env(tmp_path: Path, with_push: bool = True):
    from gate.console import build_console_router
    from gate.subscriptions import SubscriptionStore
    from gate.vapid import VapidIdentity

    clock = FakeClock()
    request_store = RequestStore(tmp_path / "gate.sqlite3", clock=clock)
    passkeys = ConsolePasskeyStore(tmp_path / "console-passkeys.json", clock=clock)
    sessions = SessionStore(clock=clock)
    subs = SubscriptionStore(tmp_path / "subs.json")
    keys = VapidIdentity(tmp_path / "vapid.json") if with_push else None
    router = build_console_router(
        request_store,
        passkeys,
        sessions,
        origin=ORIGIN,
        rp_id=RP_ID,
        clock=clock,
        push_subscriptions=subs if with_push else None,
        push_keys=keys,
    )
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    return client, request_store, passkeys, sessions, clock, subs


@pytest.fixture()
def signed_in(tmp_path):
    client, request_store, passkeys, sessions, clock, subs = make_env(tmp_path)
    signer = enroll_owner_passkey(client, passkeys)
    cookie = login(client, signer)
    assert cookie is not None
    return client, subs, auth(cookie)


def test_sw_js_is_public_and_handles_push_click(tmp_path):
    client, *_ = make_env(tmp_path)
    res = client.get("/sw.js")
    assert res.status_code == 200
    assert "javascript" in res.headers["content-type"]
    body = res.text
    assert "addEventListener('push'" in body
    assert "notificationclick" in body, "tap must focus/open the approvals card"


def test_public_key_requires_session(tmp_path):
    client, *_ = make_env(tmp_path)
    assert client.get("/push/public-key").status_code == 401


def test_subscribe_requires_session(tmp_path):
    client, *_ = make_env(tmp_path)
    res = client.post(
        "/push/subscribe", json=SUB, headers={"origin": ORIGIN}
    )
    assert res.status_code == 401


def test_subscribe_rejects_cross_origin(tmp_path):
    client, *_ = make_env(tmp_path)
    res = client.post(
        "/push/subscribe", json=SUB, headers={"origin": "https://evil.example"}
    )
    assert res.status_code == 403


def test_subscribe_roundtrip_persists(signed_in):
    client, subs, headers = signed_in
    res = client.post("/push/subscribe", json=SUB, headers=headers)
    assert res.status_code == 200, res.text
    assert subs.all() == [SUB]
    assert client.get("/push/public-key", headers=headers).json()["public_key"]


def test_unsubscribe_removes(signed_in):
    client, subs, headers = signed_in
    assert client.post("/push/subscribe", json=SUB, headers=headers).status_code == 200
    res = client.post(
        "/push/unsubscribe", json={"endpoint": SUB["endpoint"]}, headers=headers
    )
    assert res.status_code == 200
    assert subs.all() == []


def test_rotate_requires_session(tmp_path):
    client, *_ = make_env(tmp_path)
    assert client.post("/push/rotate", headers={"origin": ORIGIN}).status_code == 401


def test_rotate_rejects_cross_origin(tmp_path):
    client, *_ = make_env(tmp_path)
    res = client.post("/push/rotate", headers={"origin": "https://evil.example"})
    assert res.status_code == 403


def test_rotate_mints_a_new_key_and_drops_every_subscription(signed_in):
    """Disabling and re-enabling
    notifications rotates the gate's VAPID key. Every stored subscription
    is bound to the retired key, so pushes to them would be refused;
    rotation clears them all. Other browsers re-subscribe themselves on
    their next console load (resync detects the key change)."""
    client, subs, headers = signed_in
    old = client.get("/push/public-key", headers=headers).json()["public_key"]
    assert client.post("/push/subscribe", json=SUB, headers=headers).status_code == 200

    res = client.post("/push/rotate", headers=headers)

    assert res.status_code == 200, res.text
    new = res.json()["public_key"]
    assert new and new != old
    assert client.get("/push/public-key", headers=headers).json()["public_key"] == new
    assert subs.all() == [], "every subscription was bound to the retired key"


def test_malformed_subscription_is_a_400(signed_in):
    client, _, headers = signed_in
    res = client.post(
        "/push/subscribe",
        json={"endpoint": "javascript:alert(1)", "keys": SUB["keys"]},
        headers=headers,
    )
    assert res.status_code == 400


def test_unconfigured_push_fails_closed_per_route(tmp_path):
    client, *_ = make_env(tmp_path, with_push=False)
    assert client.get("/push/public-key").status_code == 503
    assert (
        client.post("/push/subscribe", json=SUB, headers={"origin": ORIGIN}).status_code
        == 503
    )


def test_console_ui_wires_the_bell(signed_in):
    client, _, headers = signed_in
    page = client.get("/", headers=headers).text
    assert "push-btn" in page, "the console page must carry the notifications button"
    js = client.get("/console.js", headers=headers).text
    assert "pushManager.subscribe" in js
    assert "/push/subscribe" in js and "/push/unsubscribe" in js
    assert "sw.js" in js, "the worker must be registered from the console script"


def test_console_resyncs_live_subscription_on_every_signed_in_load(signed_in):
    """Browsers rotate push subscriptions, and the gate only learns the new
    endpoint from the browser. Every signed-in load must post the
    browser's CURRENT subscription (the store upserts by endpoint, so this
    is idempotent); otherwise the gate keeps pushing to a dead endpoint
    after a rotation."""
    client, _, headers = signed_in
    js = client.get("/console.js", headers=headers).text
    start = js.index("async function syncPush(")
    routine = js[start : js.index("\n}\n", start)]
    assert "currentSub()" in routine
    assert "/push/subscribe" in routine
    boot = js[js.index("const me=await api('/whoami')") :]
    assert "syncPush()" in boot, "the signed-in boot path must run the resync"


def js_function(js, signature):
    start = js.index(signature)
    return js[start : js.index("\n}\n", start)]


def test_reenabling_notifications_rotates_the_vapid_key(signed_in):
    """Turning notifications back on from
    the bell rotates the gate's key, and the browser subscribes with the
    NEW key. The enable path must not fetch the current key instead."""
    client, _, headers = signed_in
    js = client.get("/console.js", headers=headers).text
    toggle = js_function(js, "async function togglePush(")
    assert "'/push/rotate'" in toggle
    assert "'/push/public-key'" not in toggle, "enable must rotate, not reuse the key"
    assert "pushManager.subscribe" in toggle


def test_resync_resubscribes_a_browser_bound_to_a_retired_key(signed_in):
    """After a rotation, every OTHER browser still holds a subscription
    bound to the old key; re-posting it as-is would store an endpoint the
    gate can no longer sign for. The page-load resync compares the
    subscription's applicationServerKey with the gate's current key and,
    on mismatch, unsubscribes and subscribes again with the current one."""
    client, _, headers = signed_in
    js = client.get("/console.js", headers=headers).text
    sync = js_function(js, "async function syncPush(")
    assert "'/push/public-key'" in sync
    assert "applicationServerKey" in sync
    assert ".unsubscribe()" in sync
    assert "pushManager.subscribe" in sync
    assert "'/push/subscribe'" in sync


def test_sw_reregisters_a_rotated_subscription(tmp_path):
    """When the browser rotates the subscription it fires
    ``pushsubscriptionchange`` at the worker — possibly with no console tab
    open. The worker must subscribe again (with the same VAPID key) and
    hand the NEW endpoint to the gate, or every later push goes nowhere."""
    client, *_ = make_env(tmp_path)
    sw = client.get("/sw.js").text
    handler = sw[sw.index("addEventListener('pushsubscriptionchange'") :]
    assert "waitUntil" in handler, "the worker must stay alive until re-registered"
    assert "pushManager.subscribe" in handler
    assert "applicationServerKey" in handler
    assert "'/push/subscribe'" in handler


def test_sw_resubscribes_with_the_gates_current_key_first(tmp_path):
    """The old subscription's key may be the RETIRED one after
    a rotation, so the worker asks the gate for its current key first and
    only falls back to the old key when that request fails (signed out)."""
    client, *_ = make_env(tmp_path)
    sw = client.get("/sw.js").text
    handler = sw[sw.index("addEventListener('pushsubscriptionchange'") :]
    assert handler.index("'/push/public-key'") < handler.index("oldSubscription")


def test_sw_opens_only_same_origin_links_from_a_push(tmp_path):
    """A worker that opened data.url from the push payload unvalidated
    would let a forged push (anyone holding the VAPID key) open an
    arbitrary external page on tap. Every URL taken from a payload is
    resolved against the worker's own origin, and anything that lands
    elsewhere (https://x, //x, /\\x, javascript:) collapses to the
    console root."""
    client, *_ = make_env(tmp_path)
    sw = client.get("/sw.js").text
    assert "new URL(" in sw
    assert "self.location.origin" in sw
    push = sw[sw.index("addEventListener('push'") : sw.index("addEventListener('notificationclick'")]
    assert "sameOriginPath(" in push, "payload URL is sanitised before it is stored"
