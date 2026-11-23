"""Wrapper orchestration: policy -> create -> poll -> verify -> exec.

Every path except "owner approved the exact argv we submitted" returns
exit code 1. Fail closed, always.
"""

from __future__ import annotations

import os
import shutil

from .client import GateError
from .digest import payload_digest
from .policy import check

ALLOWED_STATUSES = {"approved", "denied", "expired"}

# Slack past the gate's expires_at before giving up locally: one poll
# round-trip may already be in flight when the window closes.
WAIT_GRACE_S = 5.0


def _resolve_command(argv: list[str], which) -> list[str] | None:
    """sudo-style argv[0] resolution for exec.

    os.execve does no PATH lookup, so a bare name like "true" dies with
    FileNotFoundError. Resolve the way sudo itself would: against the
    wrapper process's PATH — which under sudo is the sanitized
    secure_path, NOT the invoking user's PATH, so an agent-controlled
    shadowing binary can never be picked. Pathlike argv[0] (absolute or
    containing a separator) passes through untouched.
    """
    if "/" in argv[0] or "\\" in argv[0]:
        return argv
    resolved = which(argv[0])
    if resolved is None:
        return None
    return [resolved, *argv[1:]]


def _posix_exec(argv: list[str]):
    """Replace the process with the approved command, root, clean env.

    POSIX-only (os.execve). Not exercised by the test suite (the tests
    inject exec_fn), so it is kept as small as possible.
    """
    env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"}
    os.execve(argv[0], argv, env)


def run(
    argv: list[str],
    *,
    host: str,
    user: str,
    cwd: str,
    client,
    clock,
    sleep,
    ttl_s: int,
    poll_interval_s: float,
    exec_fn=_posix_exec,
    which=None,
    notice=None,
) -> tuple[int, str]:
    reason = check(argv)
    if reason:
        return 1, f"refused locally: {reason}"

    # Resolve before creating the request: an unrunnable command must not
    # cost the owner an approval card, and execve needs an absolute path.
    resolved = _resolve_command(argv, which if which is not None else shutil.which)
    if resolved is None:
        return 1, f"command not found in PATH: {argv[0]}"

    local_digest = payload_digest(host, user, argv, cwd)

    try:
        request = client.create(user=user, argv=argv, cwd=cwd, ttl_s=ttl_s)
    except GateError as exc:
        return 1, f"gate unreachable: {exc}"

    if request["digest"] != local_digest:
        return 1, "digest mismatch on create: gate response does not bind our payload"

    # The gate owns the approval window: expires_at from the create
    # response is our only deadline (plus WAIT_GRACE_S for an in-flight
    # poll). No local cap: a cap shorter than the gate's window would
    # silently deny approvals that arrive late but still in time.
    expires_at = request["expires_at"]
    if notice is not None:
        notice(expires_at - clock())

    deadline = expires_at + WAIT_GRACE_S
    while True:
        try:
            current = client.poll(request["id"])
        except GateError as exc:
            return 1, f"poll failed: {exc}"
        if current["digest"] != local_digest:
            return 1, "digest mismatch on poll: refusing to act on this response"
        status = current["status"]
        if status == "approved":
            exec_fn(resolved)
            return 0, "approved"
        if status in ("denied", "expired"):
            return 1, f"request {status}"
        if clock() >= deadline:
            return 1, "timed out waiting for approval"
        sleep(poll_interval_s)
