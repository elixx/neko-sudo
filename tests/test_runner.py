import pytest

from hostside.client import GateError
from hostside.digest import payload_digest
from hostside.runner import run


DIGEST = payload_digest("web01", "agent", ["apt", "update"], "/home/agent")


class StubClient:
    def __init__(self, create_response=None, create_error=None, poll_sequence=None,
                 poll_error=None):
        self.create_response = create_response
        self.create_error = create_error
        self.poll_sequence = list(poll_sequence or [])
        self.poll_error = poll_error
        self.created_with = None
        self.polled = 0

    def create(self, user, argv, cwd, ttl_s):
        self.created_with = (user, argv, cwd, ttl_s)
        if self.create_error:
            raise self.create_error
        return self.create_response

    def poll(self, request_id):
        self.polled += 1
        if self.poll_error:
            raise self.poll_error
        return self.poll_sequence.pop(0)


class Recorder:
    def __init__(self):
        self.executed = []

    def __call__(self, argv):
        self.executed.append(argv)


class FakeClock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def create_response(digest=DIGEST):
    # The gate owns the approval window: the response's expires_at is the
    # wrapper's only deadline (here: a 300s window created at t=1000).
    return {
        "id": "req-1",
        "status": "pending",
        "digest": digest,
        "expires_at": 1000.0 + 300,
    }


def poll_response(status, digest=DIGEST):
    return {"id": "req-1", "status": status, "digest": digest}


def run_with(client, argv=None, ttl_s=120, which=None, notice=None):
    argv = argv if argv is not None else ["apt", "update"]
    clock = FakeClock()
    recorder = Recorder()
    code, message = run(
        argv,
        host="web01",
        user="agent",
        cwd="/home/agent",
        client=client,
        clock=clock,
        sleep=clock.sleep,
        ttl_s=ttl_s,
        poll_interval_s=2.0,
        exec_fn=recorder,
        which=which if which is not None else (lambda name: f"/usr/bin/{name}"),
        notice=notice,
    )
    return code, message, recorder, clock


def test_policy_refusal_never_contacts_the_gate():
    client = StubClient(create_error=AssertionError("must not be called"))
    code, message, recorder, _ = run_with(client, argv=["bash"])
    assert code == 1
    assert "shell" in message
    assert client.created_with is None
    assert recorder.executed == []


def test_create_gate_error_denies():
    client = StubClient(create_error=GateError("network down"))
    code, message, recorder, _ = run_with(client)
    assert code == 1
    assert recorder.executed == []


def test_create_digest_mismatch_denies_without_polling():
    client = StubClient(
        create_response=create_response(digest="00" * 32),
        poll_sequence=[poll_response("approved")],
    )
    client_expected_digest = DIGEST  # local argv digest is computed by run()
    code, message, recorder, _ = run_with(client)
    assert code == 1
    assert client.polled == 0
    assert recorder.executed == []


def test_approved_executes_resolved_argv_but_gates_typed_argv():
    """The card binds exactly what the agent typed; exec uses argv[0]
    resolved against the wrapper's sanitized PATH (sudo semantics)."""
    client = StubClient(
        create_response=create_response(),
        poll_sequence=[poll_response("pending"), poll_response("approved")],
    )
    code, message, recorder, _ = run_with(client)
    assert code == 0
    assert recorder.executed == [["/usr/bin/apt", "update"]]
    assert client.created_with is not None
    assert client.created_with[1] == ["apt", "update"]


def test_unknown_command_fails_closed_before_contacting_gate():
    """No card for a command that cannot run — resolve before create."""
    client = StubClient(create_error=AssertionError("must not be called"))
    code, message, recorder, _ = run_with(client, which=lambda name: None)
    assert code == 1
    assert "command not found" in message
    assert client.created_with is None
    assert recorder.executed == []


def test_resolve_leaves_pathlike_argv0_untouched():
    from hostside.runner import _resolve_command

    def boom(name):
        raise AssertionError("must not consult PATH for pathlike argv[0]")

    assert _resolve_command(["/usr/bin/apt", "update"], boom) == ["/usr/bin/apt", "update"]
    assert _resolve_command(["./run.sh", "x"], boom) == ["./run.sh", "x"]


def test_notice_announces_the_wait_once_with_time_remaining():
    """After create succeeds (and only then), the wrapper tells the
    terminal how long an approval can still land — derived from the gate's
    expires_at, never from a local ttl setting."""
    notices = []
    client = StubClient(
        create_response=create_response(),
        poll_sequence=[poll_response("pending"), poll_response("approved")],
    )
    code, _, recorder, _ = run_with(client, ttl_s=90, notice=notices.append)
    assert code == 0
    assert notices == [300], "display follows the gate's window"


def test_notice_silent_when_gate_unreachable():
    notices = []
    client = StubClient(create_error=GateError("network down"))
    code, _, recorder, _ = run_with(client, notice=notices.append)
    assert code == 1
    assert notices == []


def test_denied_never_executes():
    client = StubClient(
        create_response=create_response(),
        poll_sequence=[poll_response("denied")],
    )
    code, message, recorder, _ = run_with(client)
    assert code == 1
    assert recorder.executed == []


def test_expired_never_executes():
    client = StubClient(
        create_response=create_response(),
        poll_sequence=[poll_response("expired")],
    )
    code, message, recorder, _ = run_with(client)
    assert code == 1
    assert recorder.executed == []


def test_poll_response_digest_mismatch_denies():
    client = StubClient(
        create_response=create_response(),
        poll_sequence=[poll_response("approved", digest="00" * 32)],
    )
    code, message, recorder, _ = run_with(client)
    assert code == 1
    assert recorder.executed == []


def test_poll_gate_error_denies_immediately():
    client = StubClient(
        create_response=create_response(),
        poll_error=GateError("connection reset"),
    )
    code, message, recorder, _ = run_with(client)
    assert code == 1
    assert recorder.executed == []


def test_wrapper_times_out_at_gate_deadline_plus_grace():
    """The only local deadline is the gate's own expires_at plus a small
    grace for in-flight polls — no local cap may cut the wait short."""
    client = StubClient(
        create_response=create_response(),
        poll_sequence=[poll_response("pending")] * 1000,
    )
    code, message, recorder, clock = run_with(client)
    assert code == 1
    assert "timed out" in message
    assert recorder.executed == []
    assert clock.now < 1000.0 + 300.0 + 5.0 + 2.0, "stop at gate deadline + grace"


def test_approval_landing_late_in_the_window_still_executes():
    """The gate owns the window and the wrapper adds no local cap: an
    approval landing 290s into a 300s window must still execute."""
    clock = FakeClock()

    class LateApprovalClient(StubClient):
        def poll(self, request_id):
            self.polled += 1
            return poll_response(
                "approved" if clock.now >= 1290.0 else "pending"
            )

    client = LateApprovalClient(create_response=create_response())
    recorder = Recorder()
    code, message = run(
        ["apt", "update"],
        host="web01",
        user="agent",
        cwd="/home/agent",
        client=client,
        clock=clock,
        sleep=clock.sleep,
        ttl_s=120,
        poll_interval_s=2.0,
        exec_fn=recorder,
        which=lambda name: f"/usr/bin/{name}",
    )
    assert code == 0, message
    assert recorder.executed == [["/usr/bin/apt", "update"]]
    assert clock.now >= 1290.0


def test_create_sends_user_argv_cwd_and_ttl():
    client = StubClient(
        create_response=create_response(),
        poll_sequence=[poll_response("approved")],
    )
    run_with(client, argv=["systemctl", "restart", "nginx"], ttl_s=90)
    assert client.created_with == (
        "agent", ["systemctl", "restart", "nginx"], "/home/agent", 90
    )
