"""Web-push sender: the gate's own VAPID identity, browsers' subscriptions.

Plugs into the ``push`` seam of :mod:`gate.app`. The request handed over is
a wake-up, never authority — the payload only says *what* wants approving
and *where to look*. Delivery failures are logged and swallowed: a broken
push service must never fail request creation. Endpoints the push service
reports gone (404/410) are pruned; server errors are not. Every attempt —
and every request that found no subscription — leaves one line in the
push ledger, so a missed notification can be attributed afterwards.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from datetime import UTC, datetime
from urllib.parse import urlsplit

from py_vapid import Vapid
from pywebpush import WebPushException
from pywebpush import webpush as pywebpush

from .subscriptions import SubscriptionStore
from .vapid import VapidIdentity, VapidKeys

GONE_STATUSES = (404, 410)
# One push POST may take at most this long. pywebpush's default is
# no timeout at all.
PUSH_TIMEOUT_S = 10.0


def _pywebpush_transport(keys, subject: str):
    """Build the default transport closure over the gate's VAPID identity.

    ``keys`` is anything with a ``private_pem`` attribute: a fixed
    :class:`VapidKeys`, or the live :class:`~gate.vapid.VapidIdentity`
    whose key can rotate. The PEM is read on every send, so a
    rotation takes effect on the next push.
    """

    # pywebpush takes a Vapid instance, a file PATH, or a base64url raw
    # scalar — a PEM *string* falls into Vapid.from_string (DER expected)
    # and dies with "ASN.1 parsing error: invalid length". Parse eagerly
    # so a bad key surfaces at startup (fail-open → NullPush), not on
    # every request; re-parse only when the PEM changes. One tuple holds
    # (pem, parsed) so a concurrent send never pairs a new PEM with an
    # old parse.
    parsed = [(keys.private_pem, Vapid.from_pem(keys.private_pem.encode("ascii")))]

    def current_vapid():
        pem = keys.private_pem
        entry = parsed[0]
        if entry[0] != pem:
            entry = (pem, Vapid.from_pem(pem.encode("ascii")))
            parsed[0] = entry
        return entry[1]

    def send(subscription: dict, data: str, ttl: int) -> int:
        vapid = current_vapid()
        try:
            response = pywebpush(
                subscription_info=subscription,
                data=data,
                ttl=ttl,
                vapid_private_key=vapid,
                vapid_claims={"sub": subject},
                timeout=PUSH_TIMEOUT_S,
                # No Topic header: same-Topic pushes REPLACE each other at
                # the push service, so a second request silently dropped
                # the first's undelivered wake-up.
                headers={"Urgency": "high"},
            )
        except WebPushException as exc:
            # pywebpush raises on every status > 202; hand an HTTP answer
            # back as a status so the sender can prune 404/410.
            # No response at all (connection error) stays an exception.
            if exc.response is None:
                raise
            return exc.response.status_code
        return getattr(response, "status_code", 200)

    return send


class WebPushPush:
    def __init__(
        self,
        subscriptions: SubscriptionStore,
        keys: VapidKeys | VapidIdentity,
        send_fn=None,
        now=time.time,
        subject: str = "mailto:admin@example.com",
        ledger=None,
    ):
        self._subscriptions = subscriptions
        self._keys = keys
        self._send = send_fn or _pywebpush_transport(keys, subject)
        self._now = now
        self._subject = subject
        self._ledger = ledger

    def _payload(self, request: dict) -> str:
        argv = " ".join(request.get("argv", []))
        if len(argv) > 120:
            argv = argv[:117] + "..."
        payload = {
            "title": "neko-sudo: approval needed",
            "body": f"{request.get('host', '?')} \u00b7 {argv}",
            # Tap target is the console PAGE, not the JSON API: the page
            # renders a login flow for cold sessions and polls pending
            # cards every 5s, so a tap always lands somewhere actionable.
            "url": "/",
        }
        return json.dumps(payload)

    def _ttl(self, request: dict) -> int:
        remaining = int(request.get("expires_at", 0) - self._now())
        return max(1, remaining)

    def request_created(self, request: dict) -> None:
        data = self._payload(request)
        ttl = self._ttl(request)
        subscriptions = self._subscriptions.all()
        if not subscriptions:
            self._record(request, None, ttl, time.monotonic(), error="no_subscriptions")
        for subscription in subscriptions:
            endpoint = subscription.get("endpoint", "?")
            started = time.monotonic()
            try:
                status = self._send(subscription, data, ttl)
            except Exception as exc:  # noqa: BLE001 — push must never break the gate
                print(
                    f"neko-sudo push: delivery to {endpoint} failed: {exc!r}",
                    file=sys.stderr,
                )
                self._record(
                    request, endpoint, ttl, started, error=type(exc).__name__
                )
                continue
            self._record(request, endpoint, ttl, started, status=status)
            if status in GONE_STATUSES:
                self._subscriptions.remove(endpoint)

    def _record(self, request, endpoint, ttl, started, *, status=None, error=None):
        if self._ledger is None:
            return
        try:
            record = {
                "ts": datetime.now(UTC).isoformat(timespec="seconds"),
                "request": request.get("id"),
                "host": request.get("host"),
                "ttl": ttl,
                "ok": status is not None and 200 <= status < 300,
                "status": status,
                "gone": status in GONE_STATUSES,
                "error": error,
                "ms": int((time.monotonic() - started) * 1000),
            }
            if endpoint is not None:
                # Host + short tag only: the endpoint URL is a delivery capability.
                record["endpoint"] = urlsplit(endpoint).hostname or "?"
                record["endpoint_tag"] = hashlib.sha256(endpoint.encode()).hexdigest()[:8]
        except Exception as exc:  # noqa: BLE001 — diagnostics never break delivery
            print(f"neko-sudo push: ledger record skipped: {exc!r}", file=sys.stderr)
            return
        self._ledger.append(record)
