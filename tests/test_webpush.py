"""The real push sender: wake the owner's lock screen, never break the gate."""

import json

import pytest

SUB_A = {
    "endpoint": "https://push.example/a",
    "keys": {"p256dh": "pubA", "auth": "authA"},
}
SUB_B = {
    "endpoint": "https://push.example/b",
    "keys": {"p256dh": "pubB", "auth": "authB"},
}

REQUEST = {
    "id": "req-9",
    "host": "web01",
    "user": "agent",
    "argv": ["apt", "update"],
    "expires_at": 2000.0,
}


class Recorder:
    """Fake push transport: records (subscription, payload, ttl); scripted results."""

    def __init__(self, results=None):
        self.calls = []
        self.results = results or {}

    def __call__(self, subscription, data, ttl):
        self.calls.append((subscription, json.loads(data), ttl))
        result = self.results.get(subscription["endpoint"], 201)
        if isinstance(result, Exception):
            raise result
        return result


@pytest.fixture()
def store(tmp_path):
    from gate.subscriptions import SubscriptionStore

    s = SubscriptionStore(tmp_path / "subs.json")
    return s


@pytest.fixture()
def keys(tmp_path):
    from gate.vapid import load_or_generate

    return load_or_generate(tmp_path / "vapid.json")


def make_sender(store, keys, recorder, now=lambda: 1900.0):
    from gate.webpush import WebPushPush

    return WebPushPush(
        store, keys, send_fn=recorder, now=now, subject="mailto:admin@example.com"
    )


def test_notifies_every_subscription_with_actionable_payload(store, keys):
    store.add(SUB_A)
    store.add(SUB_B)
    rec = Recorder()
    make_sender(store, keys, rec).request_created(REQUEST)
    assert [c[0]["endpoint"] for c in rec.calls] == [
        "https://push.example/a",
        "https://push.example/b",
    ]
    sub_a, payload, ttl = rec.calls[0]
    assert payload["title"] == "neko-sudo: approval needed"
    assert "web01" in payload["body"] and "apt update" in payload["body"]
    # A tap selects the exact pending request in the login-aware console,
    # never the JSON route or a different pending request.
    assert payload["url"] == "/#review=req-9"
    assert ttl == 100, "expires_at 2000 with now=1900"


def test_push_ttl_is_never_more_than_remaining_life(store, keys):
    store.add(SUB_A)
    rec = Recorder()
    make_sender(store, keys, rec, now=lambda: 1995.0).request_created(REQUEST)
    assert rec.calls[0][2] == 5


def test_expired_request_still_sends_short_ttl(store, keys):
    store.add(SUB_A)
    rec = Recorder()
    make_sender(store, keys, rec, now=lambda: 2100.0).request_created(REQUEST)
    assert rec.calls[0][2] >= 1, "ttl floors at 1s; the service drops late pushes"


def test_no_subscriptions_is_a_quiet_noop(store, keys):
    rec = Recorder()
    make_sender(store, keys, rec).request_created(REQUEST)
    assert rec.calls == []


def test_transport_failure_never_propagates(store, keys):
    store.add(SUB_A)
    rec = Recorder(results={"https://push.example/a": RuntimeError("boom")})
    make_sender(store, keys, rec).request_created(REQUEST), "must not raise"


def test_gone_subscriptions_are_pruned_404_410(store, keys):
    store.add(SUB_A)
    store.add(SUB_B)
    rec = Recorder(
        results={
            "https://push.example/a": 410,
            "https://push.example/b": 201,
        }
    )
    make_sender(store, keys, rec).request_created(REQUEST)
    endpoints = [s["endpoint"] for s in store.all()]
    assert endpoints == ["https://push.example/b"], "410/404 = browser unsubscribed"


def test_server_errors_keep_the_subscription(store, keys):
    store.add(SUB_A)
    rec = Recorder(results={"https://push.example/a": 503})
    make_sender(store, keys, rec).request_created(REQUEST)
    assert store.all() == [SUB_A], "5xx is transient; do not prune"


def test_default_transport_uses_pywebpush(tmp_path, store, keys):
    from gate import webpush

    assert hasattr(webpush, "pywebpush"), "runtime dependency for the real transport"


def test_real_transport_consumes_gate_vapid_keys(tmp_path, monkeypatch):
    """The default transport must actually work with VapidKeys' PEM.

    pywebpush accepts a ``Vapid`` instance, a file PATH, or a base64url
    raw scalar — but NOT a PEM string: strings fall into
    ``Vapid.from_string`` and die with "ASN.1 parsing error: invalid
    length". That silently disables every push while fake-transport tests
    stay green. HTTP here is faked; key parsing, ECDH encryption and JWT
    signing all run for real.
    """
    transport, subscription, _ = real_transport(tmp_path, monkeypatch)
    assert transport(subscription, '{"title":"t"}', ttl=60) == 201


def real_transport(tmp_path, monkeypatch, status=201):
    """The REAL pywebpush transport with only the HTTP POST faked.

    Returns (transport, subscription, posts): ``posts`` collects the
    kwargs of every faked requests.post so tests can inspect exactly what
    would have hit the wire (headers, timeout, ...).
    """
    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from gate import webpush
    from gate.vapid import load_or_generate

    class FakeResponse:
        status_code = status
        reason = "Scripted"
        content = b""
        text = ""
        headers = {}

    posts = []

    def fake_post(url, **kw):
        posts.append(kw)
        return FakeResponse()

    requests_mod = webpush.pywebpush.__globals__["requests"]
    monkeypatch.setattr(requests_mod, "post", fake_post)

    keys = load_or_generate(tmp_path / "vapid.json")
    sub_key = ec.generate_private_key(ec.SECP256R1())
    subscription = {
        "endpoint": "https://push.example/send/test",
        "keys": {
            "p256dh": base64.urlsafe_b64encode(
                sub_key.public_key().public_bytes(
                    serialization.Encoding.X962,
                    serialization.PublicFormat.UncompressedPoint,
                )
            ).decode(),
            "auth": base64.urlsafe_b64encode(b"a" * 16).decode(),
        },
    }
    transport = webpush._pywebpush_transport(keys, "mailto:admin@example.com")
    return transport, subscription, posts


@pytest.mark.parametrize("status", [404, 410])
def test_real_transport_reports_gone_status_instead_of_raising(
    tmp_path, monkeypatch, status
):
    """pywebpush RAISES WebPushException on any status > 202, so a sender
    that only inspects return codes never sees 404/410, and gone
    subscriptions are never pruned (a fake transport hides this). The
    transport must hand the push service's status back so the sender can
    act on it."""
    transport, subscription, _ = real_transport(tmp_path, monkeypatch, status)
    assert transport(subscription, '{"title":"t"}', ttl=60) == status


def test_real_transport_bounds_the_push_post_with_a_timeout(tmp_path, monkeypatch):
    """pywebpush's webpush() defaults to timeout=None — a push service that
    stalls holds the send forever. One bounded POST keeps a slow push
    service from eating the approval window."""
    from gate.webpush import PUSH_TIMEOUT_S

    transport, subscription, posts = real_transport(tmp_path, monkeypatch)
    transport(subscription, '{"title":"t"}', ttl=60)
    assert posts[0]["timeout"] == PUSH_TIMEOUT_S
    assert 0 < PUSH_TIMEOUT_S <= 10


def test_real_transport_sends_no_topic_header(tmp_path, monkeypatch):
    """RFC 8030 §5.4: a queued message is REPLACED by a newer one with the
    same Topic. One fixed Topic for every approval means a second request
    silently discards the first's undelivered push while the browser is
    background-throttled, so approval pushes carry no Topic.
    Urgency stays high so the push service still wakes the device."""
    transport, subscription, posts = real_transport(tmp_path, monkeypatch)
    transport(subscription, '{"title":"t"}', ttl=60)
    headers = {k.lower(): v for k, v in posts[0]["headers"].items()}
    assert "topic" not in headers
    assert headers["urgency"] == "high"


def test_real_transport_signs_with_the_current_key_after_rotation(tmp_path, monkeypatch):
    """A VAPID rotation must take effect on the very next send. A transport
    that parsed the key once at startup would keep signing with the
    retired key after a rotation, and every fresh subscription (bound to
    the new key) would be refused. The VAPID Authorization header carries
    the signer's public key as k=."""
    import re

    from gate import webpush
    from gate.vapid import VapidIdentity

    _, subscription, posts = real_transport(tmp_path, monkeypatch)
    identity = VapidIdentity(tmp_path / "identity.json")
    transport = webpush._pywebpush_transport(identity, "mailto:admin@example.com")

    old_key = identity.public_key
    transport(subscription, '{"title":"t"}', ttl=60)
    new_key = identity.rotate()
    transport(subscription, '{"title":"t"}', ttl=60)

    def signer(post):
        auth = {k.lower(): v for k, v in post["headers"].items()}["authorization"]
        return re.search(r"k=([A-Za-z0-9_-]+)", auth).group(1).rstrip("=")

    assert [signer(p) for p in posts] == [old_key, new_key]


def test_payload_carries_no_secrets(store, keys):
    store.add(SUB_A)
    rec = Recorder()
    poisoned = dict(REQUEST, token="tok-secret-value")
    make_sender(store, keys, rec).request_created(poisoned)
    blob = json.dumps(rec.calls[0][1])
    assert "tok-secret-value" not in blob
