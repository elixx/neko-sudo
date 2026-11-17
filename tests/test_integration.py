"""End-to-end over real HTTP: wrapper client against the actual gate app.

Proves wire compatibility (paths, auth, digest binding) using the
default stdlib transport — the same code the host will run.
"""

import socket
import sqlite3
import tempfile
import threading
import time
from pathlib import Path

import pytest
import uvicorn

from gate.app import create_app
from gate.store import RequestStore
from gate.tokens import hash_token
from hostside.client import GateClient
from hostside.runner import run

pytestmark = pytest.mark.integration


class EventPush:
    """Captures the request_id the gate hands to the push hook."""

    def __init__(self):
        self.event = threading.Event()
        self.request_id = None

    def request_created(self, request):
        self.request_id = request["id"]
        self.event.set()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def gate(tmp_path):
    store = RequestStore(tmp_path / "gate.sqlite3")
    push = EventPush()
    tokens = {"web01": hash_token("tok-web01")}
    app = create_app(store=store, tokens=tokens, push=push)
    config = uvicorn.Config(app, host="127.0.0.1", port=free_port(), log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 5
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started, "gate did not start"
    yield {
        "url": f"http://127.0.0.1:{config.port}",
        "store": store,
        "push": push,
    }
    server.should_exit = True
    thread.join(timeout=5)


def run_wrapper(gate, argv, token="tok-web01", decide=None):
    client = GateClient(gate["url"], token=token, timeout_s=5)
    executed = []
    result = {}

    def worker():
        result["value"] = run(
            argv,
            host="web01",
            user="agent",
            cwd="/home/agent",
            client=client,
            clock=time.time,
            sleep=time.sleep,
            ttl_s=60,
            poll_interval_s=0.05,
            exec_fn=executed.append,
            which=lambda name: f"/usr/bin/{name}",
        )

    thread = threading.Thread(target=worker)
    thread.start()
    if decide:
        assert gate["push"].event.wait(timeout=5), "gate never created the request"
        gate["store"].decide(gate["push"].request_id, decide)
    thread.join(timeout=10)
    assert not thread.is_alive(), "wrapper did not terminate"
    return result["value"], executed


def test_approved_over_real_http(gate):
    (code, message), executed = run_wrapper(
        gate, ["systemctl", "restart", "nginx"], decide="approve"
    )
    assert code == 0
    assert executed == [["/usr/bin/systemctl", "restart", "nginx"]]


def test_denied_over_real_http(gate):
    (code, message), executed = run_wrapper(gate, ["apt", "update"], decide="deny")
    assert code == 1
    assert executed == []


def test_wrong_token_fails_closed(gate):
    (code, message), executed = run_wrapper(gate, ["apt", "update"], token="tok-imposter")
    assert code == 1
    assert executed == []
    assert not gate["push"].event.is_set(), "no request may be created for an unknown token"
