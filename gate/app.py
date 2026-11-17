"""FastAPI application factory for the neko-sudo gate.

Host-facing API (bearer-token auth, one token per host):
    POST /v1/requests        create an approval request (201) or 429 if rate-limited
    GET  /v1/requests/{id}   poll a request this host created

The host is derived from the token, never from the request body.
Owner-facing decision endpoints (passkey console) are intentionally not
exposed here yet; decisions are made in-process via store.decide().
"""

import os
import time
from collections import defaultdict, deque

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException
from pydantic import BaseModel

from gate.tokens import hash_token

# The approval window is gate-owned and centrally configured. Hosts do not
# get a say, so per-host values cannot drift from the central policy.
DEFAULT_TTL_S = 300


def approval_ttl_from_environ(environ=os.environ) -> int:
    """Resolve the gate-owned TTL: NEKO_SUDO_APPROVAL_TTL_S wins, unset
    means the 300s default. Bad values raise at boot, not per request —
    a silent fallback would hide a typo behind the wrong window length."""
    raw = environ.get("NEKO_SUDO_APPROVAL_TTL_S")
    if raw is None:
        return DEFAULT_TTL_S
    ttl = int(raw)  # ValueError on junk/empty — intended
    if ttl <= 0:
        raise ValueError(
            f"NEKO_SUDO_APPROVAL_TTL_S must be a positive int, got {ttl}"
        )
    return ttl


class NullPush:
    """Push sender that does nothing; the real web-push sender plugs in here."""

    def request_created(self, request: dict) -> None:
        pass


class CreateRequestBody(BaseModel):
    user: str
    argv: list[str]
    cwd: str
    # Optional hint from the wrapper; the gate owns the approval window and
    # ignores it. Declared so such payloads still parse (extra=forbid).
    ttl_s: int | None = None

    model_config = {"extra": "forbid"}


def create_app(
    store,
    tokens: dict[str, str],
    rate_limit_per_min: int = 30,
    push=None,
    clock=time.time,
    default_ttl_s: int = DEFAULT_TTL_S,
) -> FastAPI:
    app = FastAPI(title="neko-sudo gate")
    push = push or NullPush()
    tokens_by_hash = {h: host for host, h in tokens.items()}
    hits: dict[str, deque] = defaultdict(deque)

    def host_for(authorization: str | None) -> str:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        token_hash = hash_token(authorization[len("Bearer ") :])
        host = tokens_by_hash.get(token_hash)
        if host is None:
            raise HTTPException(status_code=401, detail="unknown token")
        return host

    def check_rate_limit(host: str) -> None:
        window = hits[host]
        now = clock()
        while window and now - window[0] >= 60:
            window.popleft()
        if len(window) >= rate_limit_per_min:
            raise HTTPException(status_code=429, detail="rate limit exceeded")
        window.append(now)

    @app.post("/v1/requests", status_code=201)
    def create_request(
        body: CreateRequestBody,
        background_tasks: BackgroundTasks,
        authorization: str | None = Header(default=None),
    ):
        host = host_for(authorization)
        check_rate_limit(host)
        request = store.create_request(
            host=host,
            user=body.user,
            argv=body.argv,
            cwd=body.cwd,
            ttl_s=default_ttl_s,  # gate owns the window; body.ttl_s is ignored
        )
        # The wake-up goes out AFTER the 201 is on the wire: a slow
        # push service must never delay the wrapper or its expiry notice.
        background_tasks.add_task(push.request_created, request)
        return request

    @app.get("/v1/requests/{request_id}")
    def poll_request(request_id: str, authorization: str | None = Header(default=None)):
        host = host_for(authorization)
        request = store.get_request(request_id)
        if request is None or request["host"] != host:
            raise HTTPException(status_code=404, detail="not found")
        return request

    return app
