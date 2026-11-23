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


def test_same_host_requests_start_in_submission_order(gate):
    """Same-host order end to end: real wrappers over real HTTP. A's wrapper polls at
    the production 2 s interval, B's every 50 ms. The owner decides A,
    then B straight away. Without the gate's hold, B's wrapper sees its
    approval first and runs before A (a stop/start pair inverted)."""
    from gate.store import EarlierPending

    store = gate["store"]
    started = []
    results = {}

    def wrapper(key, argv, poll_interval_s):
        client = GateClient(gate["url"], token="tok-web01", timeout_s=5)
        results[key] = run(
            argv,
            host="web01",
            user="agent",
            cwd="/home/agent",
            client=client,
            clock=time.time,
            sleep=time.sleep,
            ttl_s=60,
            poll_interval_s=poll_interval_s,
            exec_fn=lambda resolved: started.append(resolved[1:]),
            which=lambda name: f"/usr/bin/{name}",
        )

    def wait_pending(n):
        deadline = time.time() + 5
        while len(store.pending_requests()) < n:
            assert time.time() < deadline, f"never saw {n} pending requests"
            time.sleep(0.02)

    first = threading.Thread(target=wrapper, args=("a", ["systemctl", "stop", "x"], 2.0))
    first.start()
    wait_pending(1)
    second = threading.Thread(target=wrapper, args=("b", ["systemctl", "start", "x"], 0.05))
    second.start()
    wait_pending(2)
    a, b = sorted(store.pending_requests(), key=lambda r: r["host_seq"])

    with pytest.raises(EarlierPending):
        store.decide(b["id"], "approve")
    store.decide(a["id"], "approve")
    store.decide(b["id"], "approve")
    for thread in (first, second):
        thread.join(timeout=10)
        assert not thread.is_alive(), "wrapper did not terminate"

    assert started == [["stop", "x"], ["start", "x"]]
    assert results == {"a": (0, "approved"), "b": (0, "approved")}
