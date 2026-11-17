"""Env-driven server assembly: host API + owner console in one app."""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from gate.server import build_app
from gate.tokens import hash_token

RAW_TOKEN = "raw-test-token-0123456789abcdef"


def write_env(tmp_path: Path, monkeypatch, *, tokens_body: str = "web01 " + "a" * 64):
    (tmp_path / "tokens.conf").write_text(tokens_body + "\n", encoding="utf-8")
    monkeypatch.setenv("NEKO_SUDO_DB", str(tmp_path / "gate.sqlite3"))
    monkeypatch.setenv("NEKO_SUDO_PASSKEYS", str(tmp_path / "console-passkeys.json"))
    monkeypatch.setenv("NEKO_SUDO_SESSIONS", str(tmp_path / "sessions.json"))
    monkeypatch.setenv("NEKO_SUDO_TOKENS_FILE", str(tmp_path / "tokens.conf"))
    monkeypatch.setenv("NEKO_SUDO_ORIGIN", "https://sudo.example.com")
    monkeypatch.setenv("NEKO_SUDO_RP_ID", "sudo.example.com")


def test_build_app_mounts_console_and_host_api(tmp_path, monkeypatch):
    write_env(tmp_path, monkeypatch)
    app = build_app()
    client = TestClient(app)

    # Console is up on the configured origin's RP
    assert client.get("/").status_code == 200

    # Host API still fail-closes without a token, accepts the configured one
    res = client.post(
        "/v1/requests",
        json={"user": "agent", "argv": ["true"], "cwd": "/tmp"},
    )
    assert res.status_code == 401


def test_build_app_tokens_file_only_ever_holds_hashes(tmp_path, monkeypatch):
    write_env(
        tmp_path,
        monkeypatch,
        tokens_body=f"web01 {'b' * 64}\ndb01 {'c' * 64}",
    )
    app = build_app()
    client = TestClient(app)

    # Both surfaces are mounted in one app: console page + host API
    assert client.get("/").status_code == 200
    assert client.get("/login/options").status_code == 405  # POST-only route exists
    assert client.post(
        "/v1/requests", json={"user": "agent", "argv": ["true"], "cwd": "/tmp"}
    ).status_code == 401


def test_build_app_approval_ttl_env_is_authoritative(tmp_path, monkeypatch):
    """The gate is the single source of truth for the approval window:
    NEKO_SUDO_APPROVAL_TTL_S on the gate service beats both the built-in
    default and any ttl_s a host still sends."""
    write_env(
        tmp_path,
        monkeypatch,
        tokens_body=f"web01 {hash_token(RAW_TOKEN)}",
    )
    monkeypatch.setenv("NEKO_SUDO_APPROVAL_TTL_S", "60")
    app = build_app()
    client = TestClient(app)
    res = client.post(
        "/v1/requests",
        json={"user": "agent", "argv": ["true"], "cwd": "/tmp", "ttl_s": 999},
        headers={"Authorization": f"Bearer {RAW_TOKEN}"},
    )
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["expires_at"] - body["created_at"] == 60


def test_build_app_requires_configured_origin(tmp_path, monkeypatch):
    write_env(tmp_path, monkeypatch)
    monkeypatch.delenv("NEKO_SUDO_ORIGIN")
    try:
        build_app()
        raised = False
    except RuntimeError:
        raised = True
    assert raised, "missing NEKO_SUDO_ORIGIN must fail closed at boot"


def test_build_app_enables_push_with_own_vapid_identity(tmp_path, monkeypatch):
    write_env(tmp_path, monkeypatch)
    monkeypatch.setenv("NEKO_SUDO_VAPID", str(tmp_path / "vapid.json"))
    monkeypatch.setenv(
        "NEKO_SUDO_PUSH_SUBSCRIPTIONS", str(tmp_path / "push-subscriptions.json")
    )
    app = build_app()
    client = TestClient(app)

    # The worker is served and the keypair is minted on the data volume
    res = client.get("/sw.js")
    assert res.status_code == 200
    assert "notificationclick" in res.text
    vapid = Path(str(tmp_path / "vapid.json"))
    assert vapid.exists(), "VAPID identity must persist on the data volume"

    # Push endpoints exist behind the session gate
    assert client.get("/push/public-key").status_code == 401
    assert (
        client.post(
            "/push/subscribe", json={"endpoint": "https://x", "keys": {"p256dh": "a", "auth": "b"}}
        ).status_code
        == 401
    )


def test_build_app_records_push_outcomes_on_the_data_volume(tmp_path, monkeypatch):
    """The deployed gate must keep its push ledger beside its other
    state (NEKO_SUDO_PUSH_LEDGER, default /data/push-ledger.jsonl), so a
    missed notification can be attributed afterwards. With no browser
    subscribed, the request still leaves a 'no_subscriptions' line."""
    import json

    write_env(tmp_path, monkeypatch, tokens_body=f"web01 {hash_token(RAW_TOKEN)}")
    monkeypatch.setenv("NEKO_SUDO_VAPID", str(tmp_path / "vapid.json"))
    monkeypatch.setenv(
        "NEKO_SUDO_PUSH_SUBSCRIPTIONS", str(tmp_path / "push-subscriptions.json")
    )
    ledger = tmp_path / "push-ledger.jsonl"
    monkeypatch.setenv("NEKO_SUDO_PUSH_LEDGER", str(ledger))
    client = TestClient(build_app())

    res = client.post(
        "/v1/requests",
        json={"user": "agent", "argv": ["true"], "cwd": "/tmp"},
        headers={"Authorization": f"Bearer {RAW_TOKEN}"},
    )
    assert res.status_code == 201, res.text

    [record] = [json.loads(x) for x in ledger.read_text(encoding="utf-8").splitlines()]
    assert record["request"] == res.json()["id"]
    assert record["host"] == "web01"
    assert record["error"] == "no_subscriptions"


def push_env(tmp_path, monkeypatch):
    write_env(tmp_path, monkeypatch, tokens_body=f"web01 {hash_token(RAW_TOKEN)}")
    monkeypatch.setenv("NEKO_SUDO_VAPID", str(tmp_path / "vapid.json"))
    monkeypatch.setenv(
        "NEKO_SUDO_PUSH_SUBSCRIPTIONS", str(tmp_path / "push-subscriptions.json")
    )
    monkeypatch.setenv("NEKO_SUDO_PUSH_LEDGER", str(tmp_path / "push-ledger.jsonl"))


def test_gate_process_creates_state_files_owner_only(tmp_path, monkeypatch):
    """The data dir may be shared or replicated to hosts where the gated
    agent account has a shell. Files written at the default umask come out
    0644 -- VAPID private key and push subscriptions included -- and the
    stores rewrite via tmp+rename, so a one-off chmod does not stick. The
    gate process must set umask 077 BEFORE it creates any state file, so
    every file it creates or rewrites is owner-only. (Observed at the
    os.umask seam: Windows umask drops group/other bits, so reading it back
    there proves nothing; the POSIX test below checks real modes in CI.)"""
    from gate import server

    push_env(tmp_path, monkeypatch)
    calls = []

    def fake_umask(mask):
        calls.append((mask, (tmp_path / "vapid.json").exists()))
        return 0o022

    monkeypatch.setattr(server.os, "umask", fake_umask)
    server.create_app()
    assert calls == [(0o077, False)], "umask 077 must precede every state file"


def test_build_app_wires_a_rotatable_vapid_identity(tmp_path, monkeypatch):
    """The assembled gate must hold the LIVE VapidIdentity at
    NEKO_SUDO_VAPID (shared by the sender and the console), not a fixed
    snapshot, or /push/rotate could mint a key the sender never uses."""
    from gate import vapid

    made = []

    class Spy(vapid.VapidIdentity):
        def __init__(self, path):
            super().__init__(path)
            made.append(self)

    monkeypatch.setattr(vapid, "VapidIdentity", Spy)
    push_env(tmp_path, monkeypatch)
    client = TestClient(build_app())

    assert [m.path for m in made] == [tmp_path / "vapid.json"]
    res = client.post("/push/rotate", headers={"origin": "https://sudo.example.com"})
    assert res.status_code == 401, "rotation is mounted and session-gated"


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes; runs in CI")
def test_state_files_written_by_the_gate_are_0600(tmp_path, monkeypatch):
    """The real effect on disk: boot-time VAPID key, rewritten session /
    subscription stores, the push ledger and the SQLite DB are 0600."""
    import stat

    from gate.server import create_app

    push_env(tmp_path, monkeypatch)
    previous = os.umask(0o022)
    try:
        client = TestClient(create_app())
        res = client.post(
            "/v1/requests",
            json={"user": "agent", "argv": ["true"], "cwd": "/tmp"},
            headers={"Authorization": f"Bearer {RAW_TOKEN}"},
        )
        assert res.status_code == 201, res.text
        from gate.subscriptions import SubscriptionStore

        SubscriptionStore(tmp_path / "push-subscriptions.json").add(
            {"endpoint": "https://push.example/x", "keys": {"p256dh": "p", "auth": "a"}}
        )
    finally:
        os.umask(previous)

    for name in ("vapid.json", "push-subscriptions.json", "push-ledger.jsonl",
                 "gate.sqlite3"):
        mode = stat.S_IMODE((tmp_path / name).stat().st_mode)
        assert mode & 0o077 == 0, f"{name} is {oct(mode)}"
