import time

import pytest
from fastapi.testclient import TestClient

from gate.store import RequestStore


def make_client(tmp_path, clock=None, rate_limit_per_min=10, push=None, store=None):
    from gate.app import create_app
    from gate.tokens import hash_token

    if store is None:
        store = RequestStore(tmp_path / "gate.sqlite3", clock=clock or time.time)
    tokens = {host: hash_token(tok) for host, tok in [("web01", "tok-web01")]}
    app = create_app(
        store,
        tokens=tokens,
        rate_limit_per_min=rate_limit_per_min,
        push=push,
        clock=clock or time.time,
    )
    return TestClient(app)


AUTH = {"Authorization": "Bearer tok-web01"}


def test_create_and_poll_roundtrip(tmp_path):
    client = make_client(tmp_path)
    r = client.post(
        "/v1/requests",
        json={
            "user": "agent",
            "argv": ["systemctl", "restart", "nginx"],
            "cwd": "/home/agent",
        },
        headers=AUTH,
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "pending"
    assert body["host"] == "web01", "host must come from the token, not the body"
    assert body["digest"]

    poll = client.get(f"/v1/requests/{body['id']}", headers=AUTH)
    assert poll.status_code == 200, poll.text
    assert poll.json()["status"] == "pending"
    assert poll.json()["argv"] == ["systemctl", "restart", "nginx"]


def test_missing_token_is_rejected(tmp_path):
    client = make_client(tmp_path)
    r = client.post(
        "/v1/requests",
        json={"user": "agent", "argv": ["true"], "cwd": "/tmp"},
    )
    assert r.status_code == 401


def test_unknown_token_is_rejected(tmp_path):
    client = make_client(tmp_path)
    r = client.post(
        "/v1/requests",
        json={"user": "agent", "argv": ["true"], "cwd": "/tmp"},
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert r.status_code == 401


def test_host_cannot_poll_another_hosts_request(tmp_path):
    store = RequestStore(tmp_path / "gate.sqlite3")
    other = store.create_request(
        host="web02", user="agent", argv=["true"], cwd="/tmp", ttl_s=120
    )
    client = make_client(tmp_path, store=store)
    r = client.get(f"/v1/requests/{other['id']}", headers=AUTH)
    assert r.status_code == 404


class FakePush:
    def __init__(self):
        self.sent = []

    def request_created(self, request):
        self.sent.append(request)


def test_gate_owns_the_approval_ttl_host_value_is_ignored(tmp_path):
    """Central policy: the approval window is managed by
    the gate alone. Whatever ttl_s a host still sends must not change it."""
    client = make_client(tmp_path, clock=lambda: 1000.0)
    r = client.post(
        "/v1/requests",
        json={"user": "agent", "argv": ["true"], "cwd": "/tmp", "ttl_s": 60},
        headers=AUTH,
    )
    assert r.status_code == 201, r.text
    assert r.json()["expires_at"] == 1300.0, "gate TTL (300s) must win"


def test_gate_default_approval_ttl_is_300s(tmp_path):
    client = make_client(tmp_path, clock=lambda: 1000.0)
    r = client.post(
        "/v1/requests",
        json={"user": "agent", "argv": ["true"], "cwd": "/tmp"},
        headers=AUTH,
    )
    assert r.status_code == 201, r.text
    assert r.json()["expires_at"] == 1300.0


def test_approval_ttl_env_override_parses_and_fails_closed():
    from gate.app import approval_ttl_from_environ

    assert approval_ttl_from_environ({}) == 300
    assert approval_ttl_from_environ({"NEKO_SUDO_APPROVAL_TTL_S": "60"}) == 60
    for bad in ("0", "-5", "junk", ""):
        with pytest.raises(ValueError):
            approval_ttl_from_environ({"NEKO_SUDO_APPROVAL_TTL_S": bad})


def test_rate_limit_returns_429_then_recovers_after_window(tmp_path):
    now = {"t": 1000.0}
    client = make_client(
        tmp_path, rate_limit_per_min=3, clock=lambda: now["t"]
    )
    payload = {"user": "agent", "argv": ["true"], "cwd": "/tmp"}
    for _ in range(3):
        assert client.post("/v1/requests", json=payload, headers=AUTH).status_code == 201
    assert client.post("/v1/requests", json=payload, headers=AUTH).status_code == 429

    now["t"] += 61.0
    assert client.post("/v1/requests", json=payload, headers=AUTH).status_code == 201


def test_push_receives_full_request_as_wakeup(tmp_path):
    push = FakePush()
    client = make_client(tmp_path, push=push)
    r = client.post(
        "/v1/requests",
        json={"user": "agent", "argv": ["apt", "update"], "cwd": "/tmp"},
        headers=AUTH,
    )
    assert r.status_code == 201
    assert len(push.sent) == 1
    sent = push.sent[0]
    assert sent["id"] == r.json()["id"]
    assert sent["host"] == "web01"
    assert sent["argv"] == ["apt", "update"], "sender needs argv for the lock screen"
    assert "expires_at" in sent, "sender needs expiry to set push TTL"
    # It is still a wake-up, never authority: no token material rides along.
    assert "token" not in str(sent).lower()


def test_push_runs_only_after_the_response_is_sent(tmp_path):
    """The response must be on the wire before the push runs: a slow push
    service must never delay the wrapper's 201 (and its "expires in Ns"
    notice) by the whole send. Driven at the ASGI level because
    TestClient cannot observe ordering."""
    import json

    import anyio

    from gate.app import create_app
    from gate.tokens import hash_token

    events = []

    class OrderPush:
        def request_created(self, request):
            events.append("push")

    app = create_app(
        RequestStore(tmp_path / "gate.sqlite3"),
        tokens={"web01": hash_token("tok-web01")},
        push=OrderPush(),
    )
    body = json.dumps({"user": "agent", "argv": ["true"], "cwd": "/tmp"}).encode()
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/v1/requests",
        "raw_path": b"/v1/requests",
        "query_string": b"",
        "root_path": "",
        "headers": [
            (b"host", b"testserver"),
            (b"content-type", b"application/json"),
            (b"authorization", b"Bearer tok-web01"),
            (b"content-length", str(len(body)).encode()),
        ],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
    }
    inbound = [{"type": "http.request", "body": body, "more_body": False}]

    async def receive():
        return inbound.pop(0) if inbound else {"type": "http.disconnect"}

    async def send(message):
        events.append(message["type"])
        if message["type"] == "http.response.start":
            assert message["status"] == 201

    anyio.run(app, scope, receive, send)
    assert events == ["http.response.start", "http.response.body", "push"]


def test_body_host_field_is_rejected(tmp_path):
    client = make_client(tmp_path)
    r = client.post(
        "/v1/requests",
        json={
            "host": "web02",
            "user": "agent",
            "argv": ["true"],
            "cwd": "/tmp",
        },
        headers=AUTH,
    )
    assert r.status_code == 422, "host must never be accepted from the body"
    assert client.get("/v1/requests", headers=AUTH).status_code == 405
