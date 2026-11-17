"""Console routes: passkey enrollment, sign-in, and approve/deny (TDD)."""
from __future__ import annotations

import hashlib
import json
import struct
import time
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from gate.passkeys import ConsolePasskeyStore
from gate.sessions import COOKIE_NAME, SessionStore
from gate.store import RequestStore
from gate.webauthn import (
    COSE_ALG_ES256,
    FLAG_AT,
    FLAG_UP,
    FLAG_UV,
    b64url_encode,
)

from test_webauthn import SyntheticES256Signer, cbor_encode

ORIGIN = "https://sudo.example.com"
RP_ID = "sudo.example.com"


class FakeClock:
    def __init__(self, now: float = 1_760_000_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make_env(tmp_path: Path):
    from gate.console import build_console_router

    clock = FakeClock()
    request_store = RequestStore(tmp_path / "gate.sqlite3", clock=clock)
    passkeys = ConsolePasskeyStore(tmp_path / "console-passkeys.json", clock=clock)
    sessions = SessionStore(clock=clock)
    router = build_console_router(
        request_store,
        passkeys,
        sessions,
        origin=ORIGIN,
        rp_id=RP_ID,
        clock=clock,
    )
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    return client, request_store, passkeys, sessions, clock


def make_registration_fields(
    *,
    challenge_b64: str,
    signer: SyntheticES256Signer,
    cred_id: bytes = b"owner-key-01",
    origin: str = ORIGIN,
    rp_id: str = RP_ID,
    sign_count: int = 1,
) -> dict[str, str]:
    client_data = json.dumps(
        {
            "type": "webauthn.create",
            "challenge": challenge_b64,
            "origin": origin,
            "crossOrigin": False,
        }
    ).encode("utf-8")
    flags = bytes([FLAG_UP | FLAG_UV | FLAG_AT])
    header = hashlib.sha256(rp_id.encode()).digest() + flags + struct.pack(">I", sign_count)
    attested = b"\x00" * 16 + struct.pack(">H", len(cred_id)) + cred_id + cbor_encode(signer.cose_map())
    att_obj = cbor_encode({"fmt": "none", "attStmt": {}, "authData": header + attested})
    return {
        "credential_id": b64url_encode(cred_id),
        "client_data_json": b64url_encode(client_data),
        "attestation_object": b64url_encode(att_obj),
    }


def make_assertion_fields(
    *,
    challenge_b64: str,
    signer: SyntheticES256Signer,
    cred_id: bytes = b"owner-key-01",
    origin: str = ORIGIN,
    rp_id: str = RP_ID,
    sign_count: int = 2,
    corrupt_sig: bool = False,
) -> dict[str, str]:
    client_data = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": challenge_b64,
            "origin": origin,
            "crossOrigin": False,
        }
    ).encode("utf-8")
    auth_data = (
        hashlib.sha256(rp_id.encode()).digest()
        + bytes([FLAG_UP | FLAG_UV])
        + struct.pack(">I", sign_count)
    )
    sig = bytearray(signer.sign(auth_data + hashlib.sha256(client_data).digest()))
    if corrupt_sig:
        sig[-1] ^= 0x01
    return {
        "credential_id": b64url_encode(cred_id),
        "client_data_json": b64url_encode(client_data),
        "authenticator_data": b64url_encode(auth_data),
        "signature": b64url_encode(bytes(sig)),
    }


def enroll_owner_passkey(
    client: TestClient,
    passkeys: ConsolePasskeyStore,
    *,
    signer: SyntheticES256Signer | None = None,
    cred_id: bytes = b"owner-key-01",
    label: str = "Owner Hello",
) -> SyntheticES256Signer:
    signer = signer or SyntheticES256Signer()
    code = passkeys.new_enrollment(ttl_s=600)
    res = client.post(
        "/enroll/options",
        json={"enroll_code": code, "label": label},
        headers={"origin": ORIGIN},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    fields = make_registration_fields(
        challenge_b64=body["options"]["challenge"], signer=signer, cred_id=cred_id
    )
    res = client.post(
        "/enroll",
        json={"challenge_id": body["challenge_id"], "enroll_code": code,
              "label": label, **fields},
        headers={"origin": ORIGIN},
    )
    assert res.status_code == 201, res.text
    return signer


def login(
    client: TestClient,
    signer: SyntheticES256Signer,
    *,
    cred_id: bytes = b"owner-key-01",
    sign_count: int = 2,
    corrupt_sig: bool = False,
    origin: str = ORIGIN,
) -> str | None:
    """Complete a passkey sign-in; returns the raw session cookie (or None)."""
    res = client.post("/login/options", json={}, headers={"origin": origin})
    assert res.status_code == 200, res.text
    body = res.json()
    fields = make_assertion_fields(
        challenge_b64=body["options"]["challenge"],
        signer=signer,
        cred_id=cred_id,
        sign_count=sign_count,
        corrupt_sig=corrupt_sig,
        origin=origin,
    )
    res = client.post(
        "/login", json={"challenge_id": body["challenge_id"], **fields},
        headers={"origin": origin},
    )
    if res.status_code != 200:
        return None
    set_cookie = res.headers["set-cookie"]
    for part in set_cookie.split(";"):
        key, _, value = part.strip().partition("=")
        if key == COOKIE_NAME and value:
            return value
    return None


def auth(raw_session: str) -> dict[str, str]:
    return {"cookie": f"{COOKIE_NAME}={raw_session}", "origin": ORIGIN}


def pending_request(request_store: RequestStore, *, argv=("apt", "update")) -> dict:
    return request_store.create_request(
        host="web01", user="agent", argv=list(argv), cwd="/home/agent", ttl_s=120
    )


# ---------------------------------------------------------------- enrollment

def test_enroll_happy_path_stores_credential_and_consumes_code(tmp_path):
    client, _, passkeys, _, _ = make_env(tmp_path)
    signer = SyntheticES256Signer()
    code = passkeys.new_enrollment(ttl_s=600)

    res = client.post(
        "/enroll/options",
        json={"enroll_code": code, "label": "Owner Hello"},
        headers={"origin": ORIGIN},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["options"]["rp"]["id"] == RP_ID
    assert body["options"]["user"]["id"] == passkeys.user_id()
    assert {p["alg"] for p in body["options"]["pubKeyCredParams"]} >= {
        COSE_ALG_ES256,
    }

    fields = make_registration_fields(
        challenge_b64=body["options"]["challenge"], signer=signer
    )
    res = client.post(
        "/enroll",
        json={"challenge_id": body["challenge_id"], "enroll_code": code,
              "label": "Owner Hello", **fields},
        headers={"origin": ORIGIN},
    )
    assert res.status_code == 201, res.text
    assert res.json()["credential"]["label"] == "Owner Hello"
    assert passkeys.enrollment_pending() is False, "code must be burned on use"
    assert [c["label"] for c in passkeys.list()] == ["Owner Hello"]


def test_enroll_rejects_wrong_code(tmp_path):
    client, _, passkeys, _, _ = make_env(tmp_path)
    passkeys.new_enrollment(ttl_s=600)
    res = client.post(
        "/enroll/options",
        json={"enroll_code": "WRNG-WRNG-WRNG-WRNG", "label": "Evil"},
        headers={"origin": ORIGIN},
    )
    assert res.status_code == 403
    assert res.json()["detail"]["code"] == "invalid_enroll_code"


def test_enroll_rejects_bad_label(tmp_path):
    client, _, passkeys, _, _ = make_env(tmp_path)
    code = passkeys.new_enrollment(ttl_s=600)
    res = client.post(
        "/enroll/options",
        json={"enroll_code": code, "label": "   "},
        headers={"origin": ORIGIN},
    )
    assert res.status_code == 400
    assert res.json()["detail"]["code"] == "invalid_label"


def test_enroll_duplicate_credential_conflicts(tmp_path):
    client, _, passkeys, _, _ = make_env(tmp_path)
    enroll_owner_passkey(client, passkeys, cred_id=b"owner-key-01")
    code = passkeys.new_enrollment(ttl_s=600)
    signer = SyntheticES256Signer()
    res = client.post(
        "/enroll/options",
        json={"enroll_code": code, "label": "Second"},
        headers={"origin": ORIGIN},
    )
    assert res.status_code == 200
    body = res.json()
    fields = make_registration_fields(
        challenge_b64=body["options"]["challenge"], signer=signer, cred_id=b"owner-key-01"
    )
    res = client.post(
        "/enroll",
        json={"challenge_id": body["challenge_id"], "enroll_code": code,
              "label": "Second", **fields},
        headers={"origin": ORIGIN},
    )
    assert res.status_code == 409
    assert res.json()["detail"]["code"] == "duplicate_credential"


# -------------------------------------------------------------------- login

def test_login_options_without_passkeys_conflicts(tmp_path):
    client, _, _, _, _ = make_env(tmp_path)
    res = client.post("/login/options", json={}, headers={"origin": ORIGIN})
    assert res.status_code == 409
    assert res.json()["detail"]["code"] == "no_passkeys"


def test_login_happy_path_sets_session_cookie(tmp_path):
    client, _, passkeys, _, _ = make_env(tmp_path)
    signer = enroll_owner_passkey(client, passkeys)

    raw = login(client, signer, sign_count=2)
    assert raw, "sign-in must set the session cookie"
    res = client.get("/whoami", headers=auth(raw))
    assert res.status_code == 200
    assert res.json() == {"signed_in": True, "label": "Owner Hello"}


def test_login_rejects_unenrolled_credential(tmp_path):
    client, _, passkeys, _, _ = make_env(tmp_path)
    enroll_owner_passkey(client, passkeys)
    stranger = SyntheticES256Signer(private_scalar=0x42424242)

    assert login(client, stranger, cred_id=b"stranger-key", sign_count=1) is None


def test_login_rejects_corrupted_signature(tmp_path):
    client, _, passkeys, _, _ = make_env(tmp_path)
    signer = enroll_owner_passkey(client, passkeys)

    assert login(client, signer, sign_count=2, corrupt_sig=True) is None


def test_login_challenge_is_single_use(tmp_path):
    client, _, passkeys, _, _ = make_env(tmp_path)
    signer = enroll_owner_passkey(client, passkeys)

    res = client.post("/login/options", json={}, headers={"origin": ORIGIN})
    body = res.json()
    fields = make_assertion_fields(
        challenge_b64=body["options"]["challenge"], signer=signer, sign_count=2
    )
    first = client.post(
        "/login", json={"challenge_id": body["challenge_id"], **fields},
        headers={"origin": ORIGIN},
    )
    assert first.status_code == 200
    replay = client.post(
        "/login", json={"challenge_id": body["challenge_id"], **fields},
        headers={"origin": ORIGIN},
    )
    assert replay.status_code == 401
    assert replay.json()["detail"]["code"] == "challenge_unknown"


def test_logout_revokes_session(tmp_path):
    client, _, passkeys, sessions, _ = make_env(tmp_path)
    signer = enroll_owner_passkey(client, passkeys)
    raw = login(client, signer, sign_count=2)

    res = client.post("/logout", headers=auth(raw))
    assert res.status_code == 200
    assert client.get("/whoami", headers=auth(raw)).status_code == 401


# ---------------------------------------------------------------- approvals

def test_history_requires_session(tmp_path):
    client, _, _, _, _ = make_env(tmp_path)
    assert client.get("/history").status_code == 401


def test_history_pages_finished_cards_five_at_a_time(tmp_path):
    """Console history table: finished cards newest first, 5 per page,
    with the total so the page can offer older/newer."""
    client, request_store, passkeys, _, clock = make_env(tmp_path)
    signer = enroll_owner_passkey(client, passkeys)
    raw = login(client, signer)
    for i in range(7):
        r = request_store.create_request(
            host="web01", user="agent", argv=["echo", str(i)], cwd="/tmp", ttl_s=120
        )
        clock.advance(1)
        request_store.decide(r["id"], "approve" if i % 2 else "deny")
    pending_request(request_store)  # live card: not history

    first = client.get("/history", headers=auth(raw))
    assert first.status_code == 200, first.text
    body = first.json()
    assert (body["page"], body["page_size"], body["total"]) == (0, 5, 7)
    assert [c["argv"][1] for c in body["items"]] == ["6", "5", "4", "3", "2"]
    top = body["items"][0]
    assert (top["host"], top["status"]) == ("web01", "denied")  # i=6: even -> deny
    assert {"created_at", "decided_at", "user", "cwd"} <= set(top)

    older = client.get("/history?page=1", headers=auth(raw)).json()
    assert [c["argv"][1] for c in older["items"]] == ["1", "0"]


def test_history_rejects_a_negative_page(tmp_path):
    client, _, passkeys, _, _ = make_env(tmp_path)
    raw = login(client, enroll_owner_passkey(client, passkeys))
    assert client.get("/history?page=-1", headers=auth(raw)).status_code == 422


def test_approvals_require_session(tmp_path):
    client, _, _, _, _ = make_env(tmp_path)
    assert client.get("/approvals").status_code == 401


def test_approvals_card_shows_exact_payload_and_countdown(tmp_path):
    client, request_store, passkeys, _, clock = make_env(tmp_path)
    signer = enroll_owner_passkey(client, passkeys)
    raw = login(client, signer, sign_count=2)
    req = pending_request(request_store)

    res = client.get("/approvals", headers=auth(raw))
    assert res.status_code == 200
    cards = res.json()["pending"]
    assert len(cards) == 1
    card = cards[0]
    assert card["id"] == req["id"]
    assert card["host"] == "web01"
    assert card["user"] == "agent"
    assert card["argv"] == ["apt", "update"]
    assert card["cwd"] == "/home/agent"
    assert card["digest"] == req["digest"]
    assert card["seconds_left"] == pytest.approx(120, abs=5)

    detail = client.get(f"/approvals/{req['id']}", headers=auth(raw))
    assert detail.status_code == 200
    assert detail.json()["id"] == req["id"]


def test_approval_detail_unknown_404_and_decided_410(tmp_path):
    client, request_store, passkeys, _, _ = make_env(tmp_path)
    signer = enroll_owner_passkey(client, passkeys)
    raw = login(client, signer, sign_count=2)

    assert client.get("/approvals/nope", headers=auth(raw)).status_code == 404

    req = pending_request(request_store)
    request_store.decide(req["id"], "deny")
    res = client.get(f"/approvals/{req['id']}", headers=auth(raw))
    assert res.status_code == 410
    assert res.json()["detail"]["status"] == "denied"


def test_deny_requires_session_only(tmp_path):
    client, request_store, passkeys, _, _ = make_env(tmp_path)
    signer = enroll_owner_passkey(client, passkeys)
    raw = login(client, signer, sign_count=2)
    req = pending_request(request_store)

    unauth = client.post(f"/approvals/{req['id']}/deny", headers={"origin": ORIGIN})
    assert unauth.status_code == 401

    res = client.post(f"/approvals/{req['id']}/deny", headers=auth(raw))
    assert res.status_code == 200
    assert res.json()["status"] == "denied"
    assert request_store.get_request(req["id"])["status"] == "denied"


def test_approve_requires_passkey_bound_to_request(tmp_path):
    client, request_store, passkeys, _, clock = make_env(tmp_path)
    signer = enroll_owner_passkey(client, passkeys)
    raw = login(client, signer, sign_count=2)
    req = pending_request(request_store)

    # 1. begin the approve ceremony
    res = client.post(f"/approvals/{req['id']}/approve/options", headers=auth(raw))
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["options"]["rpId"] == RP_ID
    assert body["options"]["challenge"]

    # 2. complete it with a fresh assertion (sign_count moves past login)
    fields = make_assertion_fields(
        challenge_b64=body["options"]["challenge"], signer=signer, sign_count=3
    )
    res = client.post(
        f"/approvals/{req['id']}/approve",
        json={"challenge_id": body["challenge_id"], **fields},
        headers=auth(raw),
    )
    assert res.status_code == 200, res.text
    assert res.json()["status"] == "approved"
    assert request_store.get_request(req["id"])["status"] == "approved"

    # sign counter advanced and persisted
    stored = passkeys.get_credential(fields["credential_id"], rp_id=RP_ID)
    assert stored["sign_count"] == 3


def test_approve_rejects_login_challenge_purpose_mismatch(tmp_path):
    client, request_store, passkeys, _, _ = make_env(tmp_path)
    signer = enroll_owner_passkey(client, passkeys)
    raw = login(client, signer, sign_count=2)
    req = pending_request(request_store)

    login_options = client.post("/login/options", json={}, headers={"origin": ORIGIN}).json()
    fields = make_assertion_fields(
        challenge_b64=login_options["options"]["challenge"], signer=signer, sign_count=3
    )
    res = client.post(
        f"/approvals/{req['id']}/approve",
        json={"challenge_id": login_options["challenge_id"], **fields},
        headers=auth(raw),
    )
    assert res.status_code == 400
    assert res.json()["detail"]["code"] == "challenge_mismatch"
    assert request_store.get_request(req["id"])["status"] == "pending"


def test_approve_challenge_bound_to_session(tmp_path):
    client, request_store, passkeys, sessions, _ = make_env(tmp_path)
    signer = enroll_owner_passkey(client, passkeys)
    first = login(client, signer, sign_count=2)
    second = login(client, signer, sign_count=3)
    req = pending_request(request_store)

    options = client.post(
        f"/approvals/{req['id']}/approve/options", headers=auth(first)
    ).json()
    fields = make_assertion_fields(
        challenge_b64=options["options"]["challenge"], signer=signer, sign_count=4
    )
    res = client.post(
        f"/approvals/{req['id']}/approve",
        json={"challenge_id": options["challenge_id"], **fields},
        headers=auth(second),
    )
    assert res.status_code == 403
    assert res.json()["detail"]["code"] == "session_mismatch"
    assert request_store.get_request(req["id"])["status"] == "pending"


def test_approve_already_decided_conflicts(tmp_path):
    client, request_store, passkeys, _, _ = make_env(tmp_path)
    signer = enroll_owner_passkey(client, passkeys)
    raw = login(client, signer, sign_count=2)
    req = pending_request(request_store)
    request_store.decide(req["id"], "deny")

    options = client.post(
        f"/approvals/{req['id']}/approve/options", headers=auth(raw)
    )
    assert options.status_code == 410
    res = client.post(
        f"/approvals/{req['id']}/approve",
        json={
            "challenge_id": "whatever",
            "credential_id": "x",
            "client_data_json": "x",
            "authenticator_data": "x",
            "signature": "x",
        },
        headers=auth(raw),
    )
    assert res.status_code == 409
    assert res.json()["detail"]["code"] == "not_pending"


# ------------------------------------------------------------- cross-site

def test_cross_origin_post_rejected(tmp_path):
    client, _, _, _, _ = make_env(tmp_path)
    res = client.post(
        "/login/options", json={}, headers={"origin": "https://evil.example"}
    )
    assert res.status_code == 403
    assert res.json()["detail"]["code"] == "cross_site"


# ------------------------------------------------------------------- page

def test_index_plain_when_unauthenticated(tmp_path):
    """Anonymous visitors learn nothing: no names, no purpose, no internals."""
    client, _, _, _, _ = make_env(tmp_path)
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    body = res.text.lower()
    for leak in ("neko", "sudo", "approval", "passkey", "pending",
                 "console.js", "privileged"):
        assert leak not in body, leak


def test_index_serves_console_when_signed_in(tmp_path):
    client, _, passkeys, _, _ = make_env(tmp_path)
    signer = enroll_owner_passkey(client, passkeys)
    raw = login(client, signer)
    assert raw, "sign-in must yield a session cookie"
    res = client.get("/", headers=auth(raw))
    assert res.status_code == 200
    assert "neko-sudo" in res.text
    assert "Pending requests" in res.text


def test_signed_in_console_heads_neko_sudo_with_history_below_pending(tmp_path):
    """Once signed in, the sign-in block's header
    reads "Neko Sudo" (not "Sign in"), and a paginated table of the most
    recent finished cards sits below the pending section. The anonymous
    page is a different document and keeps leaking nothing."""
    client, _, passkeys, _, _ = make_env(tmp_path)
    raw = login(client, enroll_owner_passkey(client, passkeys))
    page = client.get("/", headers=auth(raw)).text

    assert ">Neko Sudo</h2>" in page
    assert "<h2>Sign in</h2>" not in page
    pending_at = page.index("Pending requests")
    history_at = page.index("Recent requests")
    assert pending_at < history_at, "history goes below the pending section"
    for element in ('id="history"', 'id="hist-newer"', 'id="hist-older"', 'id="hist-page"'):
        assert element in page[history_at:], element


def test_console_js_renders_history_as_text_with_pager(tmp_path):
    """The history table shows agent-controlled strings (argv, host, cwd):
    they must reach the DOM as text, never as HTML, or a crafted command
    could restyle or spoof the console. The pager walks /history pages,
    and the 5s poll reloads the current page so a decided card moves
    from pending into history without a reload."""
    client, _, passkeys, _, _ = make_env(tmp_path)
    raw = login(client, enroll_owner_passkey(client, passkeys))
    js = client.get("/console.js", headers=auth(raw)).text

    start = js.index("async function loadHistory(")
    loader = js[start : js.index("\n}\n", start)]
    assert "/history?page=" in loader
    assert "textContent" in loader
    assert "innerHTML" not in loader, "history cells must be text, not markup"
    assert "$('hist-older').onclick" in js and "$('hist-newer').onclick" in js
    start = js.index("async function refresh(")
    assert "loadHistory(" in js[start : js.index("\n}\n", start)]


def test_pending_card_renders_agent_fields_as_text(tmp_path):
    """The approval card is what the owner decides on. host/user/cwd/argv
    come from the gated side (cwd is just a directory name the agent can
    pick), so interpolating them into innerHTML let the agent inject
    markup and restyle or overlay the very card being approved (CSP stops
    scripts, not inline styles). Every field must reach the DOM as text."""
    client, _, passkeys, _, _ = make_env(tmp_path)
    raw = login(client, enroll_owner_passkey(client, passkeys))
    js = client.get("/console.js", headers=auth(raw)).text

    start = js.index("function card(")
    renderer = js[start : js.index("\n}\n", start)]
    assert "innerHTML" not in renderer, "card fields must be text nodes"
    assert "textContent" in renderer


def test_console_js_hidden_without_session(tmp_path):
    """The full console script must not be readable by anonymous visitors."""
    client, _, passkeys, _, _ = make_env(tmp_path)
    res = client.get("/console.js")
    assert res.status_code == 404
    assert "credentials" not in res.text

    signer = enroll_owner_passkey(client, passkeys)
    raw = login(client, signer)
    assert raw, "sign-in must yield a session cookie"
    res = client.get("/console.js", headers=auth(raw))
    assert res.status_code == 200
    assert "javascript" in res.headers["content-type"]
    assert "navigator.credentials.get" in res.text


def test_signin_js_served_to_anonymous(tmp_path):
    """The plain page's login script loads without a session and carries
    no console internals."""
    client, _, _, _, _ = make_env(tmp_path)
    res = client.get("/signin.js")
    assert res.status_code == 200
    assert "javascript" in res.headers["content-type"]
    assert "navigator.credentials.get" in res.text
    assert "approvals" not in res.text
