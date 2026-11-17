import pytest

from hostside.client import GateClient, GateError


class FakeTransport:
    def __init__(self, create_response=None, poll_response=None, exc=None):
        self.create_response = create_response
        self.poll_response = poll_response
        self.exc = exc
        self.calls = []

    def post_json(self, path, payload, headers, timeout):
        self.calls.append(("POST", path, payload, headers))
        if self.exc:
            raise self.exc
        return self.create_response

    def get_json(self, path, headers, timeout):
        self.calls.append(("GET", path, None, headers))
        if self.exc:
            raise self.exc
        return self.poll_response


GOOD_CREATE = {
    "id": "abc123",
    "status": "pending",
    "digest": "0f" * 32,
    "expires_at": 2000.0,
}


def make_client(transport):
    return GateClient("https://gate.example", token="tok-web01", transport=transport)


def test_create_sends_token_and_payload():
    transport = FakeTransport(create_response=GOOD_CREATE)
    client = make_client(transport)
    request = client.create(
        user="agent", argv=["apt", "update"], cwd="/home/agent", ttl_s=120
    )
    assert request["id"] == "abc123"
    method, path, payload, headers = transport.calls[0]
    assert method == "POST" and path.endswith("/v1/requests")
    assert headers["Authorization"] == "Bearer tok-web01"
    assert payload["argv"] == ["apt", "update"]
    assert "host" not in payload, "host is derived from the token, never sent"


def test_create_sends_neko_sudo_user_agent():
    # Cloudflare Bot Fight Mode bans the default "Python-urllib/x" browser
    # signature outright (error 1010); the wrapper must identify itself.
    transport = FakeTransport(create_response=GOOD_CREATE)
    client = make_client(transport)
    client.create(user="agent", argv=["true"], cwd="/home/agent", ttl_s=120)
    _method, _path, _payload, headers = transport.calls[0]
    assert headers["User-Agent"].startswith("neko-sudo/")
    assert "Python-urllib" not in headers["User-Agent"]


def test_create_fail_closed_on_transport_error():
    client = make_client(FakeTransport(exc=OSError("network down")))
    with pytest.raises(GateError):
        client.create(user="agent", argv=["true"], cwd="/tmp", ttl_s=120)


def test_create_fail_closed_on_malformed_response():
    client = make_client(FakeTransport(create_response={"nope": 1}))
    with pytest.raises(GateError):
        client.create(user="agent", argv=["true"], cwd="/tmp", ttl_s=120)


def test_poll_returns_request_status():
    transport = FakeTransport(
        poll_response={"id": "abc123", "status": "approved", "digest": "0f" * 32}
    )
    client = make_client(transport)
    assert client.poll("abc123")["status"] == "approved"


def test_poll_fail_closed_on_transport_error():
    client = make_client(FakeTransport(exc=TimeoutError("too slow")))
    with pytest.raises(GateError):
        client.poll("abc123")


def test_poll_fail_closed_on_malformed_response():
    client = make_client(FakeTransport(poll_response={"unexpected": True}))
    with pytest.raises(GateError):
        client.poll("abc123")
