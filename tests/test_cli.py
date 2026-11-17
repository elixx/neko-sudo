import pytest

from hostside.cli import ConfigError, load_config, main


def write_config(tmp_path, body):
    path = tmp_path / "neko-sudo.conf"
    path.write_text(body)
    return str(path)


MINIMAL = """\
[gate]
url = https://sudo.example.com
token = tok-web01
host = web01
user = agent
"""


class ApprovingClient:
    def __init__(self):
        self.created_with = None

    def create(self, user, argv, cwd, ttl_s):
        self.created_with = (user, argv, cwd, ttl_s)
        from hostside.digest import payload_digest

        digest = payload_digest("web01", user, argv, cwd)
        # Gate-owned window: create response fixes the deadline (main tests
        # run with clock=1000.0, so 300s remain).
        return {"id": "req-9", "status": "pending", "digest": digest,
                "expires_at": 1300.0}

    def poll(self, request_id):
        return {"id": "req-9", "status": "approved",
                "digest": self._digest}

    _digest = None


def test_missing_config_fails_closed(tmp_path):
    with pytest.raises(ConfigError):
        load_config(str(tmp_path / "nope.conf"))


def test_config_requires_every_field(tmp_path):
    body = "[gate]\nurl = https://gate.example\ntoken = t\nhost = web01\n"  # no user
    with pytest.raises(ConfigError):
        load_config(write_config(tmp_path, body))


def test_minimal_config_parses_with_default_ttl(tmp_path):
    config = load_config(write_config(tmp_path, MINIMAL))
    assert config.url == "https://sudo.example.com"
    assert config.host == "web01"
    assert config.user == "agent"
    assert config.ttl_s == 300


def test_main_refuses_shell_without_contacting_gate(tmp_path):
    client = ApprovingClient()
    code = main(
        ["bash"],
        config_path=write_config(tmp_path, MINIMAL),
        client_factory=lambda config: client,
        clock=lambda: 1000.0,
        sleep=lambda s: None,
        exec_fn=lambda argv: None,
        which=lambda name: None,   # refused locally before resolution matters
    )
    assert code == 1
    assert client.created_with is None


def test_main_strips_leading_double_dash(tmp_path):
    """`run -- true` (habit from sudo) must gate and exec `true`, not `--`."""
    client = ApprovingClient()
    original_create = client.create

    def create(user, argv, cwd, ttl_s):
        request = original_create(user, argv, cwd, ttl_s)
        client._digest = request["digest"]
        return request

    client.create = create
    executed = []
    code = main(
        ["--", "true"],
        config_path=write_config(tmp_path, MINIMAL),
        client_factory=lambda config: client,
        clock=lambda: 1000.0,
        sleep=lambda s: None,
        exec_fn=executed.append,
        which=lambda name: f"/usr/bin/{name}",
    )
    assert code == 0
    assert client.created_with is not None
    assert client.created_with[1] == ["true"]
    assert executed == [["/usr/bin/true"]]


def test_main_end_to_end_with_injected_client(tmp_path):
    client = ApprovingClient()
    original_create = client.create

    def create(user, argv, cwd, ttl_s):
        request = original_create(user, argv, cwd, ttl_s)
        client._digest = request["digest"]
        return request

    client.create = create
    executed = []
    code = main(
        ["systemctl", "restart", "nginx"],
        config_path=write_config(tmp_path, MINIMAL),
        client_factory=lambda config: client,
        clock=lambda: 1000.0,
        sleep=lambda s: None,
        exec_fn=executed.append,
        which=lambda name: f"/usr/bin/{name}",
    )
    assert code == 0
    assert executed == [["/usr/bin/systemctl", "restart", "nginx"]]
    assert client.created_with[3] == 300


def test_main_prints_awaiting_approval_with_time_remaining(tmp_path, capsys):
    client = ApprovingClient()
    original_create = client.create

    def create(user, argv, cwd, ttl_s):
        request = original_create(user, argv, cwd, ttl_s)
        client._digest = request["digest"]
        return request

    client.create = create
    code = main(
        ["true"],
        config_path=write_config(tmp_path, MINIMAL),
        client_factory=lambda config: client,
        clock=lambda: 1000.0,
        sleep=lambda s: None,
        exec_fn=lambda argv: None,
        which=lambda name: f"/usr/bin/{name}",
    )
    assert code == 0
    err = capsys.readouterr().err
    assert "awaiting approval" in err
    assert "expires in 300s" in err
    # No request URL or id: the agent needs the hold-up, not the surface.
    assert "http" not in err
    assert "/approvals/" not in err
