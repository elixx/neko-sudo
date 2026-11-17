"""Operator CLI for console passkeys: enroll codes, list, revoke."""
from __future__ import annotations

from pathlib import Path

import pytest

from gate.enroll import main
from gate.passkeys import ConsolePasskeyStore


def test_cli_enroll_mints_code(tmp_path, capsys):
    path = tmp_path / "console-passkeys.json"
    rc = main(["enroll", "--ttl", "300"], store_path=path)
    assert rc == 0
    out = capsys.readouterr().out
    assert "Enrollment code" in out
    assert "single use" in out
    store = ConsolePasskeyStore(path)
    assert store.enrollment_pending() is True
    # The code itself is printed for the operator and never stored in clear
    minted = [line for line in out.splitlines() if line.startswith("Enrollment code")][0]
    code = minted.split()[-1]
    assert store.check_enrollment(code, consume=False) is True


def test_cli_list_empty_then_enrolled(tmp_path, capsys):
    path = tmp_path / "console-passkeys.json"
    store = ConsolePasskeyStore(path)
    assert main(["list"], store_path=path) == 0
    assert "No console passkeys enrolled" in capsys.readouterr().out

    verified = {
        "id": "cli_key_000000000001",
        "alg": -7,
        "public_key": {"kty": "EC2", "crv": "P-256", "x": "x", "y": "y"},
        "sign_count": 1,
        "rp_id": "sudo.example.com",
    }
    store.save_credential(verified, label="Laptop")
    assert main(["list"], store_path=path) == 0
    out = capsys.readouterr().out
    assert "Laptop" in out and "cli_key_000" in out


def test_cli_honors_server_store_env(tmp_path, monkeypatch, capsys):
    """In the container the CLI must land codes where the server reads them."""
    env_path = tmp_path / "data" / "console-passkeys.json"
    monkeypatch.setenv("NEKO_SUDO_PASSKEYS", str(env_path))
    assert main(["enroll"], store_path=None) == 0
    code = [l for l in capsys.readouterr().out.splitlines()
            if l.startswith("Enrollment code")][0].split()[-1]
    from gate.passkeys import ConsolePasskeyStore
    assert env_path.exists()
    assert ConsolePasskeyStore(env_path).check_enrollment(code, consume=False)


def test_cli_revoke_ambiguous_fails_clean(tmp_path, capsys):
    path = tmp_path / "console-passkeys.json"
    store = ConsolePasskeyStore(path)
    for suffix in ("aaa111", "bbb222"):
        store.save_credential(
            {
                "id": f"dup_{suffix}",
                "alg": -7,
                "public_key": {"kty": "EC2", "crv": "P-256", "x": "x", "y": "y"},
                "sign_count": 1,
                "rp_id": "sudo.example.com",
            },
            label=f"Key {suffix}",
        )
    assert main(["revoke", "dup_"], store_path=path) == 1
    assert "ambiguous_prefix" in capsys.readouterr().err
    assert main(["revoke", "dup_aaa"], store_path=path) == 0
    assert "Key aaa111" in capsys.readouterr().out
    assert [c["label"] for c in ConsolePasskeyStore(path).list()] == ["Key bbb222"]
