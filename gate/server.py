"""Env-driven assembly for container deployment (Docker Swarm).

Builds one FastAPI app containing the host-facing /v1 API
(``gate.app.create_app``) and the owner console
(``gate.console.build_console_router``). Configuration is environment-only:

    NEKO_SUDO_ORIGIN       https://sudo.example.com   (required)
    NEKO_SUDO_RP_ID        sudo.example.com          (default: ORIGIN host)
    NEKO_SUDO_DB           /data/gate.sqlite3           requests DB
    NEKO_SUDO_PASSKEYS     /data/console-passkeys.json  passkey store
    NEKO_SUDO_SESSIONS     /data/sessions.json          session persist (hashes)
    NEKO_SUDO_TOKENS_FILE  /data/tokens.conf            "host sha256hex" lines
    NEKO_SUDO_VAPID        /data/vapid.json             web-push VAPID keypair
    NEKO_SUDO_PUSH_SUBSCRIPTIONS  /data/push-subscriptions.json
    NEKO_SUDO_PUSH_SUBJECT  mailto:admin@example.com  VAPID contact
    NEKO_SUDO_PUSH_LEDGER  /data/push-ledger.jsonl     one line per push attempt

The tokens file only ever contains SHA-256 hashes of host bearer tokens —
mint a token with e.g. ``openssl rand -hex 32`` and store
``sha256sum`` of it, never the token itself.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

from gate.app import NullPush, approval_ttl_from_environ
from gate.app import create_app as create_host_api
from gate.console import build_console_router
from gate.passkeys import ConsolePasskeyStore
from gate.sessions import SessionStore
from gate.store import RequestStore

DEFAULT_DATA_DIR = Path("/data")


def load_token_hashes(path: Path) -> dict[str, str]:
    """Parse ``host sha256hex`` lines; malformed lines fail closed at boot."""
    tokens: dict[str, str] = {}
    if not path.exists():
        print(f"neko-sudo: no tokens file at {path}; no hosts can create "
              "requests until one is provided", file=sys.stderr)
        return tokens
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2 or len(parts[1]) != 64:
            raise RuntimeError(
                f"{path}:{line_no}: expected 'host <64-hex sha256>'"
            )
        host, digest = parts
        tokens[host] = digest.lower()
    return tokens


def build_app(*, env: dict[str, str] | None = None) -> "object":
    from fastapi import FastAPI  # local import keeps module import cheap

    config = dict(os.environ) if env is None else dict(env)
    origin = config.get("NEKO_SUDO_ORIGIN", "").strip()
    if not origin or not origin.startswith("https://"):
        raise RuntimeError(
            "NEKO_SUDO_ORIGIN must be the public HTTPS origin "
            "(e.g. https://sudo.example.com)"
        )
    rp_id = config.get("NEKO_SUDO_RP_ID", "").strip() or urlsplit(origin).hostname

    data_dir = DEFAULT_DATA_DIR
    db_path = Path(config.get("NEKO_SUDO_DB", data_dir / "gate.sqlite3"))
    passkeys_path = Path(config.get(
        "NEKO_SUDO_PASSKEYS", data_dir / "console-passkeys.json"))
    sessions_path = Path(config.get(
        "NEKO_SUDO_SESSIONS", data_dir / "sessions.json"))
    tokens_file = Path(config.get(
        "NEKO_SUDO_TOKENS_FILE", data_dir / "tokens.conf"))
    vapid_path = Path(config.get("NEKO_SUDO_VAPID", data_dir / "vapid.json"))
    subs_path = Path(config.get(
        "NEKO_SUDO_PUSH_SUBSCRIPTIONS",
        data_dir / "push-subscriptions.json",
    ))
    push_subject = config.get(
        "NEKO_SUDO_PUSH_SUBJECT", "mailto:admin@example.com")
    push_ledger_path = Path(config.get(
        "NEKO_SUDO_PUSH_LEDGER", data_dir / "push-ledger.jsonl"))

    for parent in (db_path, passkeys_path, sessions_path):
        parent.parent.mkdir(parents=True, exist_ok=True)

    request_store = RequestStore(db_path)
    passkeys = ConsolePasskeyStore(passkeys_path)
    sessions = SessionStore(path=sessions_path)
    tokens = load_token_hashes(tokens_file)

    # Web push is a convenience, never a dependency: any failure here
    # disables notifications but leaves the gate fully functional.
    push = NullPush()
    push_keys = None
    push_subs = None
    try:
        from .pushledger import PushLedger
        from .subscriptions import SubscriptionStore
        from .vapid import VapidIdentity
        from .webpush import WebPushPush

        # Live identity shared by sender + console: /push/rotate
        # swaps the keypair for both at once.
        push_keys = VapidIdentity(vapid_path)
        push_subs = SubscriptionStore(subs_path)
        push = WebPushPush(
            push_subs,
            push_keys,
            subject=push_subject,
            ledger=PushLedger(push_ledger_path),
        )
    except Exception as exc:  # noqa: BLE001 — fail-open by design
        print(f"neko-sudo: push notifications disabled ({exc!r})",
              file=sys.stderr)

    # Approval TTL is gate-owned: NEKO_SUDO_APPROVAL_TTL_S here is the
    # single source of truth for every host.
    app: FastAPI = create_host_api(
        store=request_store,
        tokens=tokens,
        push=push,
        default_ttl_s=approval_ttl_from_environ(config),
    )
    app.include_router(build_console_router(
        request_store,
        passkeys,
        sessions,
        origin=origin,
        rp_id=rp_id,
        push_subscriptions=push_subs,
        push_keys=push_keys,
    ))
    return app


def create_app() -> "object":
    """Uvicorn factory target: ``uvicorn gate.server:create_app --factory``."""
    # /data may be shared or replicated (e.g. a Syncthing share) to hosts
    # where the gated agent has a shell. Owner-only before ANY state file is
    # created or rewritten (the stores replace files via tmp+rename, so a
    # chmod after the fact does not stick).
    os.umask(0o077)
    return build_app()
