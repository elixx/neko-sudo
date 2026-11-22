"""Owner console for the neko-sudo gate: passkey sign-in, enrollment, approve/deny.

The console is served from the same FastAPI app as the host-facing /v1 API
(``gate.app.create_app``) and mounts these owner-facing routes:

    GET  /                                plain sign-in page; full console only with a session
    POST /login/options                   begin passkey sign-in ceremony
    POST /login                           complete sign-in -> session cookie
    POST /logout                          revoke the session
    GET  /whoami                          session probe for the page JS
    POST /enroll/options                  begin enrollment (needs enroll code)
    POST /enroll                          complete enrollment, burn the code
    GET  /approvals                       pending request cards (session)
    GET  /approvals/{id}                  one card (session)
    POST /approvals/{id}/approve/options  begin approve ceremony (session)
    POST /approvals/{id}/approve          complete approve w/ passkey (session)
    POST /approvals/{id}/deny             deny (session only, no passkey)

Fail-closed rules baked in:

* Every ceremony challenge is single-use, expires, and is bound to its
  purpose; an approve challenge is additionally bound to the session digest
  that started it, so another browser cannot finish it.
* Approval completion requires a fresh user-verified passkey assertion —
  a signed-in cookie alone can only deny.
* Cross-site POSTs (Origin / Sec-Fetch-Site) are rejected outright.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from gate.passkeys import ConsolePasskeyStore, PasskeyStoreError, validate_label
from gate.sessions import (
    SessionStore,
    clear_cookie_header,
    cookie_value,
    set_cookie_header,
)
from gate.webauthn import (
    COSE_ALG_ES256,
    COSE_ALG_RS256,
    WebAuthnError,
    b64url_encode,
    verify_assertion,
    verify_registration,
)

CHALLENGE_TTL_S = 300
CHALLENGE_CAP = 64
CEREMONY_TIMEOUT_MS = 120_000
# Console history table: finished cards per page.
HISTORY_PAGE_SIZE = 5


class _Body(BaseModel):
    model_config = {"extra": "forbid"}


class LoginBody(_Body):
    challenge_id: str
    credential_id: str
    client_data_json: str
    authenticator_data: str
    signature: str


class EnrollOptionsBody(_Body):
    enroll_code: str
    label: str


class EnrollBody(_Body):
    challenge_id: str
    enroll_code: str
    label: str
    credential_id: str
    client_data_json: str
    attestation_object: str


class ApproveBody(_Body):
    challenge_id: str
    credential_id: str
    client_data_json: str
    authenticator_data: str
    signature: str


class PushKeysBody(_Body):
    p256dh: str
    auth: str


class PushSubBody(_Body):
    endpoint: str
    keys: PushKeysBody


class PushUnsubBody(_Body):
    endpoint: str


def build_console_router(
    request_store,
    passkeys: ConsolePasskeyStore,
    sessions: SessionStore,
    *,
    origin: str,
    rp_id: str,
    clock=time.time,
    push_subscriptions=None,
    push_keys=None,
) -> APIRouter:
    router = APIRouter()
    challenges: dict[str, dict] = {}

    def err(http_status: int, code: str, **extra) -> None:
        detail = {"code": code}
        detail.update(extra)
        raise HTTPException(status_code=http_status, detail=detail)

    def require_same_origin(request: Request) -> None:
        site = request.headers.get("sec-fetch-site")
        if site and site not in ("same-origin", "none"):
            err(403, "cross_site")
        origin_header = request.headers.get("origin")
        if origin_header and origin_header.lower() != origin.lower():
            err(403, "cross_site")

    def session_of(request: Request) -> tuple[str, dict]:
        raw = cookie_value(request.headers.get("cookie", ""))
        record = sessions.check(raw) if raw else None
        if record is None:
            err(401, "not_signed_in")
        return raw, record

    def new_challenge(purpose: dict | None = None,
                      session_digest: str | None = None) -> tuple[str, dict]:
        now = clock()
        for stale in [c for c, rec in challenges.items() if now >= rec["expires_at"]]:
            challenges.pop(stale, None)
        while len(challenges) >= CHALLENGE_CAP:
            challenges.pop(next(iter(challenges)))
        challenge_id = secrets.token_urlsafe(16)
        rec = {
            "challenge": b64url_encode(secrets.token_bytes(32)),
            "purpose": purpose,
            "session_digest": session_digest,
            "expires_at": now + CHALLENGE_TTL_S,
        }
        challenges[challenge_id] = rec
        return challenge_id, rec

    def pop_challenge(challenge_id: str, *, purpose: dict | None,
                      session_digest: str | None = None) -> str:
        rec = challenges.pop(challenge_id, None)  # single-use: consumed either way
        if rec is None or clock() >= rec["expires_at"]:
            err(401, "challenge_unknown")
        if purpose is None:
            if rec["purpose"] is not None:
                err(400, "challenge_mismatch")
        elif rec["purpose"] != purpose:
            err(400, "challenge_mismatch")
        elif rec["session_digest"] != session_digest:
            err(403, "session_mismatch")
        return rec["challenge"]

    def card(request: dict) -> dict:
        return {
            **{k: request[k] for k in
               ("id", "host", "user", "argv", "cwd", "digest", "status",
                "created_at", "expires_at")},
            "seconds_left": max(0, int(request["expires_at"] - clock())),
        }

    def pending_or_4xx(request_id: str, *, decided_status: int) -> dict:
        request = request_store.get_request(request_id)
        if request is None:
            err(404, "unknown_request")
        if request["status"] != "pending":
            err(decided_status, "not_pending", status=request["status"])
        return request

    def decide(request_id: str, decision: str) -> dict:
        try:
            return request_store.decide(request_id, decision)
        except LookupError:
            err(404, "unknown_request")
        except ValueError as exc:
            err(409, "not_pending", reason=str(exc))

    # ------------------------------------------------------------- sign-in

    @router.post("/login/options")
    def login_options(request: Request):
        require_same_origin(request)
        creds = passkeys.list(rp_id=rp_id)
        if not creds:
            err(409, "no_passkeys")
        challenge_id, rec = new_challenge()
        return {
            "challenge_id": challenge_id,
            "options": {
                "challenge": rec["challenge"],
                "rpId": rp_id,
                "timeout": CEREMONY_TIMEOUT_MS,
                "userVerification": "required",
                "allowCredentials": [
                    {"type": "public-key", "id": c["id"]} for c in creds
                ],
            },
        }

    @router.post("/login")
    def login(body: LoginBody, request: Request, response: Response):
        require_same_origin(request)
        challenge = pop_challenge(body.challenge_id, purpose=None)
        credential = passkeys.get_credential(body.credential_id, rp_id=rp_id)
        if credential is None:
            err(401, "unknown_credential")
        try:
            new_count = verify_assertion(
                credential=credential,
                client_data_json=body.client_data_json,
                authenticator_data=body.authenticator_data,
                signature=body.signature,
                expected_challenge=challenge,
                expected_origin=origin,
                expected_rp_id=rp_id,
            )
        except WebAuthnError as exc:
            err(401, "webauthn_failed", reason=exc.code)
        passkeys.update_sign_count(body.credential_id, new_count)
        raw = sessions.create(method="passkey", detail=credential["label"])
        response.headers["set-cookie"] = set_cookie_header(
            raw, max_age_s=sessions.absolute_s
        )
        return {"ok": True, "label": credential["label"]}

    @router.post("/logout")
    def logout(request: Request, response: Response):
        require_same_origin(request)
        raw = cookie_value(request.headers.get("cookie", ""))
        if raw:
            sessions.revoke(raw)
        response.headers["set-cookie"] = clear_cookie_header()
        return {"ok": True}

    @router.get("/whoami")
    def whoami(request: Request):
        _, record = session_of(request)
        return {"signed_in": True, "label": record.get("detail", "")}

    # ---------------------------------------------------------- enrollment

    @router.post("/enroll/options")
    def enroll_options(body: EnrollOptionsBody, request: Request):
        require_same_origin(request)
        try:
            label = validate_label(body.label)
        except PasskeyStoreError:
            err(400, "invalid_label")
        if not passkeys.check_enrollment(body.enroll_code, consume=False):
            err(403, "invalid_enroll_code")
        challenge_id, rec = new_challenge(purpose={"type": "enroll"})
        return {
            "challenge_id": challenge_id,
            "user_id": passkeys.user_id(),
            "options": {
                "challenge": rec["challenge"],
                "rp": {"id": rp_id, "name": rp_id},
                "user": {
                    "id": passkeys.user_id(),
                    "name": "neko-sudo owner",
                    "displayName": "Owner",
                },
                "pubKeyCredParams": [
                    {"type": "public-key", "alg": COSE_ALG_ES256},
                    {"type": "public-key", "alg": COSE_ALG_RS256},
                ],
                "timeout": CEREMONY_TIMEOUT_MS,
                "excludeCredentials": [
                    {"type": "public-key", "id": c["id"]}
                    for c in passkeys.list(rp_id=rp_id)
                ],
                "authenticatorSelection": {"userVerification": "required"},
                "attestation": "none",
                "label": label,
            },
        }

    @router.post("/enroll", status_code=201)
    def enroll(body: EnrollBody, request: Request):
        require_same_origin(request)
        try:
            validate_label(body.label)
        except PasskeyStoreError:
            err(400, "invalid_label")
        if not passkeys.check_enrollment(body.enroll_code, consume=False):
            err(403, "invalid_enroll_code")
        challenge = pop_challenge(
            body.challenge_id, purpose={"type": "enroll"}
        )
        try:
            verified = verify_registration(
                client_data_json=body.client_data_json,
                attestation_object=body.attestation_object,
                expected_challenge=challenge,
                expected_origin=origin,
                expected_rp_id=rp_id,
                credential_id=body.credential_id,
            )
            saved = passkeys.save_credential(
                verified, label=body.label, consume_enrollment=True
            )
        except WebAuthnError as exc:
            err(400, "webauthn_failed", reason=exc.code)
        except PasskeyStoreError as exc:
            if exc.code == "duplicate_credential":
                err(409, "duplicate_credential")
            err(400, exc.code)
        return {"credential": saved}

    # ------------------------------------------------------------ approvals

    @router.get("/approvals")
    def list_approvals(request: Request):
        _, _ = session_of(request)
        return {"pending": [card(r) for r in request_store.pending_requests()]}

    @router.get("/history")
    def history(request: Request, page: int = Query(0, ge=0)):
        """Finished cards (approved / denied / expired), newest first."""
        session_of(request)
        found = request_store.finished_requests(
            limit=HISTORY_PAGE_SIZE, offset=page * HISTORY_PAGE_SIZE
        )
        return {
            "items": [
                {k: r[k] for k in ("id", "host", "user", "argv", "cwd", "status",
                                   "created_at", "decided_at")}
                for r in found["items"]
            ],
            "page": page,
            "page_size": HISTORY_PAGE_SIZE,
            "total": found["total"],
        }

    @router.get("/approvals/{request_id}")
    def approval_detail(request_id: str, request: Request):
        session_of(request)
        req = request_store.get_request(request_id)
        if req is None:
            err(404, "unknown_request")
        if req["status"] != "pending":
            err(410, "not_pending", status=req["status"])
        return card(req)

    @router.post("/approvals/{request_id}/deny")
    def deny_approval(request_id: str, request: Request):
        require_same_origin(request)
        session_of(request)
        pending_or_4xx(request_id, decided_status=409)
        return {"status": decide(request_id, "deny")["status"]}

    @router.post("/approvals/{request_id}/approve/options")
    def approve_options(request_id: str, request: Request):
        require_same_origin(request)
        raw, _ = session_of(request)
        pending_or_4xx(request_id, decided_status=410)
        session_digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        challenge_id, rec = new_challenge(
            purpose={"type": "decide", "request_id": request_id,
                     "action": "approve"},
            session_digest=session_digest,
        )
        creds = passkeys.list(rp_id=rp_id)
        return {
            "challenge_id": challenge_id,
            "options": {
                "challenge": rec["challenge"],
                "rpId": rp_id,
                "timeout": CEREMONY_TIMEOUT_MS,
                "userVerification": "required",
                "allowCredentials": [
                    {"type": "public-key", "id": c["id"]} for c in creds
                ],
            },
        }

    @router.post("/approvals/{request_id}/approve")
    def approve(request_id: str, body: ApproveBody, request: Request):
        require_same_origin(request)
        raw, _ = session_of(request)
        pending_or_4xx(request_id, decided_status=409)
        session_digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        challenge = pop_challenge(
            body.challenge_id,
            purpose={"type": "decide", "request_id": request_id,
                     "action": "approve"},
            session_digest=session_digest,
        )
        credential = passkeys.get_credential(body.credential_id, rp_id=rp_id)
        if credential is None:
            err(401, "unknown_credential")
        try:
            new_count = verify_assertion(
                credential=credential,
                client_data_json=body.client_data_json,
                authenticator_data=body.authenticator_data,
                signature=body.signature,
                expected_challenge=challenge,
                expected_origin=origin,
                expected_rp_id=rp_id,
            )
        except WebAuthnError as exc:
            err(401, "webauthn_failed", reason=exc.code)
        passkeys.update_sign_count(body.credential_id, new_count)
        return {"status": decide(request_id, "approve")["status"]}

    @router.get("/", response_class=HTMLResponse, include_in_schema=False)
    def index(request: Request) -> HTMLResponse:
        raw = cookie_value(request.headers.get("cookie", ""))
        record = sessions.check(raw) if raw else None
        if record is None:
            # Anonymous visitors: plain page, zero service details.
            return HTMLResponse(_SIGNIN_HTML)
        return HTMLResponse(_INDEX_HTML)

    @router.get("/console.js", include_in_schema=False)
    def console_js(request: Request) -> Response:
        raw = cookie_value(request.headers.get("cookie", ""))
        if not raw or sessions.check(raw) is None:
            return Response(status_code=404, content="Not Found",
                            media_type="text/plain")
        return Response(content=_REVIEW_JS + "\n" + _CONSOLE_JS,
                        media_type="application/javascript")

    @router.get("/signin.js", include_in_schema=False)
    def signin_js() -> Response:
        return Response(content=_SIGNIN_JS, media_type="application/javascript")

    # ------------------------------------------------------- push notify

    @router.get("/sw.js", include_in_schema=False)
    def service_worker() -> Response:
        return Response(content=_SW_JS, media_type="application/javascript")

    def push_or_503():
        if push_subscriptions is None or push_keys is None:
            err(503, "push_disabled")
        return push_subscriptions, push_keys

    @router.get("/push/public-key")
    def push_public_key(request: Request):
        _, keys = push_or_503()
        session_of(request)
        return {"public_key": keys.public_key}

    @router.post("/push/subscribe")
    def push_subscribe(body: PushSubBody, request: Request):
        subs, _ = push_or_503()
        require_same_origin(request)
        session_of(request)
        try:
            subs.add(
                {
                    "endpoint": body.endpoint,
                    "keys": {
                        "p256dh": body.keys.p256dh,
                        "auth": body.keys.auth,
                    },
                }
            )
        except ValueError as exc:
            err(400, "bad_subscription", reason=str(exc))
        return {"ok": True}

    @router.post("/push/unsubscribe")
    def push_unsubscribe(body: PushUnsubBody, request: Request):
        subs, _ = push_or_503()
        require_same_origin(request)
        session_of(request)
        subs.remove(body.endpoint)
        return {"ok": True}

    @router.post("/push/rotate")
    def push_rotate(request: Request):
        """Mint a new VAPID keypair.

        The console calls this when notifications are switched back on.
        Every stored subscription is bound to the retired key, so all of
        them are dropped; browsers still holding one re-subscribe on their
        next console load (the page-load resync detects the key change).
        """
        subs, keys = push_or_503()
        require_same_origin(request)
        session_of(request)
        public_key = keys.rotate()
        subs.clear()
        return {"public_key": public_key}

    return router


_SIGNIN_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'">
<style>
 body{font-family:system-ui,sans-serif;max-width:28rem;margin:3rem auto;padding:0 1rem;background:#111;color:#eee}
 .muted{color:#999}
 button{cursor:pointer;padding:.5rem 1rem;border-radius:6px;border:1px solid #666;background:#222;color:#eee}
 #enroll input{width:14rem;padding:.4rem;margin:.2rem .5rem .2rem 0;background:#222;color:#eee;border:1px solid #555;border-radius:4px}
</style>
</head>
<body>
<div id="signin">
 <button id="signin-btn">Sign in</button>
 <span id="who" class="muted"></span>
</div>
<div id="enroll" hidden>
 <form id="enroll-form">
  <input id="enroll-code" placeholder="Enrollment code" autocomplete="off">
  <input id="enroll-label" placeholder="Label" autocomplete="off">
  <button type="submit">Submit</button>
 </form>
</div>
<script src="/signin.js"></script>
</body>
</html>
"""

_SIGNIN_JS = """'use strict';
// Sign-in only. The full console script is served after authentication.
function b64uToBuf(s){const b=atob(s.replace(/-/g,'+').replace(/_/g,'/'));const a=new Uint8Array(b.length);for(let i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a.buffer}
function bufToB64u(buf){const a=new Uint8Array(buf);let s='';for(const b of a)s+=String.fromCharCode(b);return btoa(s).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'')}

async function api(path,opts={}){
  const res=await fetch(path,{credentials:'same-origin',headers:{'Content-Type':'application/json'},...opts});
  const body=await res.json().catch(()=>({}));
  if(!res.ok){const e=new Error(body.detail&&body.detail.code||res.status);e.code=body.detail&&body.detail.code;throw e}
  return body;
}

const $=(id)=>document.getElementById(id);

async function signIn(){
  try{
    const {challenge_id,options}=await api('/login/options',{method:'POST',body:'{}'});
    const cred=await navigator.credentials.get({publicKey:{
      challenge:b64uToBuf(options.challenge),
      rpId:options.rpId,timeout:options.timeout,userVerification:options.userVerification,
      allowCredentials:(options.allowCredentials||[]).map(c=>({type:c.type,id:b64uToBuf(c.id)})),
    }});
    await api('/login',{method:'POST',body:JSON.stringify({
      challenge_id,
      credential_id:cred.id,
      client_data_json:bufToB64u(cred.response.clientDataJSON),
      authenticator_data:bufToB64u(cred.response.authenticatorData),
      signature:bufToB64u(cred.response.signature),
    })});
    location.reload();  // session cookie set -> the full page loads
  }catch(e){alert('Sign-in failed: '+(e.code||e.message))}
}

$('signin-btn').onclick=signIn;
$('enroll-form').onsubmit=async(ev)=>{
  ev.preventDefault();
  try{
    const enroll_code=$('enroll-code').value.trim(),label=$('enroll-label').value.trim();
    const {challenge_id,user_id,options}=await api('/enroll/options',{method:'POST',body:JSON.stringify({enroll_code,label})});
    const cred=await navigator.credentials.create({publicKey:{
      challenge:b64uToBuf(options.challenge),
      rp:{id:options.rp.id,name:options.rp.name},
      user:{id:b64uToBuf(user_id),name:options.user.name,displayName:options.user.displayName},
      pubKeyCredParams:options.pubKeyCredParams,timeout:options.timeout,
      excludeCredentials:(options.excludeCredentials||[]).map(c=>({type:c.type,id:b64uToBuf(c.id)})),
      authenticatorSelection:options.authenticatorSelection,attestation:options.attestation,
    }});
    await api('/enroll',{method:'POST',body:JSON.stringify({
      challenge_id,enroll_code,label,
      credential_id:cred.id,
      client_data_json:bufToB64u(cred.response.clientDataJSON),
      attestation_object:bufToB64u(cred.response.attestationObject),
    })});
    location.reload();
  }catch(e){alert('Failed: '+(e.code||e.message))}
};

(async()=>{
  try{
    await api('/whoami');
    location.reload();  // already signed in here -> load the full page
  }catch(e){
    // Bootstrap only: if nothing is enrolled yet, offer first-key setup.
    try{await api('/login/options',{method:'POST',body:'{}'})}catch(err){
      if(err.code==='no_passkeys')$('enroll').hidden=false;
    }
  }
})();
"""

_INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'">
<title>neko-sudo gate</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:44rem;margin:2rem auto;padding:0 1rem;background:#111;color:#eee}
 h1{font-size:1.3rem} .muted{color:#999} .card{border:1px solid #444;border-radius:8px;padding:1rem;margin:1rem 0}
 code{background:#222;padding:2px 6px;border-radius:4px;word-break:break-all}
 button{cursor:pointer;padding:.5rem 1rem;border-radius:6px;border:1px solid #666;background:#222;color:#eee;margin-right:.5rem}
 .ok{border-color:#2c5}.deny{border-color:#c33}
 #enroll input{width:14rem;padding:.4rem;margin:.2rem .5rem .2rem 0;background:#222;color:#eee;border:1px solid #555;border-radius:4px}
 #history{width:100%;border-collapse:collapse;font-size:.9rem}
 #history th,#history td{text-align:left;padding:.35rem .5rem;border-bottom:1px solid #333;vertical-align:top}
 #history td.cmd{font-family:ui-monospace,monospace;word-break:break-all}
 .s-approved{color:#4d8}.s-denied{color:#e66}.s-expired{color:#999}
 [hidden]{display:none!important}
 .history-command{font:inherit;color:#bcd3f8;margin:0;padding:.25rem .4rem;text-align:left;max-width:100%;overflow-wrap:anywhere;word-break:normal}
 #command-review{box-sizing:border-box;width:100%;max-width:none;height:100vh;height:100dvh;max-height:none;
   margin:0;inset:0;border:0;padding:0;background:#10141d;color:#edf1f8;overflow:hidden;color-scheme:dark}
 #command-review[open]{display:grid;grid-template-rows:auto minmax(0,1fr) auto}
 #command-review header,#command-review footer{background:#191f2c;padding:.75rem max(1rem,calc((100% - 48rem) / 2));}
 #command-review header{border-bottom:1px solid #374055;display:flex;gap:.8rem;align-items:center;justify-content:space-between}
 #command-review h2,#command-review h3{margin:.15rem 0 .35rem}
 #command-review #review-close{flex:none;margin:0}
 #review-body{overflow:auto;overscroll-behavior:contain;padding:1rem max(1rem,calc((100% - 48rem) / 2));min-width:0}
 #review-meta{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:.45rem .8rem;margin:0 0 1.1rem}
 #review-meta dt{color:#b3bfd3} #review-meta dd{margin:0;overflow-wrap:anywhere}
 #command-review pre{background:#0a0e16;border:1px solid #364157;border-radius:.5rem;padding:.8rem;
   font: .94rem/1.55 ui-monospace,monospace;white-space:pre-wrap;overflow-wrap:anywhere;direction:ltr;unicode-bidi:isolate}
 #review-script-text span{display:block}
 #command-review details{margin:1rem 0} #command-review summary{cursor:pointer;color:#c4dcff}
 #command-review footer{border-top:1px solid #374055;padding-bottom:max(.75rem,env(safe-area-inset-bottom));}
 #review-actions{display:flex;gap:.65rem;flex-wrap:wrap} #review-actions button{margin:0;min-height:44px}
 #review-approve:not(:disabled){background:#15452f;border-color:#52c082}
 #review-deny:not(:disabled){background:#4e2128;border-color:#e47580}
 #review-result:empty{display:none} #review-result{margin:.5rem 0 0;overflow-wrap:anywhere}
 :focus-visible{outline:2px solid #a7ccff;outline-offset:3px}
</style>
</head>
<body>
<h1>neko-sudo gate</h1>
<p class="muted">Privileged command approvals &mdash; every approve needs your passkey.</p>
<div id="enroll" hidden>
 <h2>Enroll a passkey</h2>
 <form id="enroll-form">
  <input id="enroll-code" placeholder="ENROLL-CODE (XXXX-XXXX-XXXX-XXXX)" autocomplete="off">
  <input id="enroll-label" placeholder="Label (e.g. Laptop)" autocomplete="off">
  <button type="submit">Enroll</button>
 </form>
</div>
<div id="signin">
 <h2 id="signin-title">Neko Sudo</h2>
 <button id="signin-btn">Sign in with passkey</button>
 <span id="who" class="muted"></span>
 <button id="push-btn" hidden>Notifications</button>
</div>
<h2>Pending requests <span id="count" class="muted"></span></h2>
<div id="empty" class="muted">No pending requests.</div>
<div id="review-link-status" class="muted" role="status"></div>
<div id="approvals"></div>
<h2>Recent requests</h2>
<table id="history">
 <thead><tr><th>When</th><th>Host</th><th>Command</th><th>Outcome</th></tr></thead>
 <tbody id="history-rows"></tbody>
</table>
<div id="hist-empty" class="muted" hidden>No finished requests yet.</div>
<div style="margin-top:.6rem">
 <button id="hist-newer" disabled>&larr; Newer</button>
 <button id="hist-older" disabled>Older &rarr;</button>
 <span id="hist-page" class="muted"></span>
</div>
<dialog id="command-review" aria-labelledby="review-title">
 <header>
  <div><h2 id="review-title">Command review</h2><div id="review-timing" class="muted"></div></div>
  <button type="button" id="review-close" autofocus>Close</button>
 </header>
 <div id="review-body">
  <dl id="review-meta">
   <dt>Host</dt><dd id="review-host"></dd>
   <dt>Requested by</dt><dd id="review-user"></dd>
   <dt>Working directory</dt><dd id="review-cwd"></dd>
   <dt id="review-digest-label">Digest</dt><dd id="review-digest" dir="ltr"></dd>
  </dl>
  <section id="review-script" aria-labelledby="review-script-title" hidden>
   <h3 id="review-script-title">Shell script preview</h3>
   <div id="review-script-note" class="muted"></div>
   <pre id="review-script-text"></pre>
  </section>
  <details id="review-decoded" hidden>
   <summary>Decoded Base64 literal (preview only)</summary>
   <pre id="review-decoded-text"></pre>
  </details>
  <details id="review-exact-toggle">
   <summary>Exact arguments (argv)</summary>
   <p class="muted">One JSON string per argument. Escapes expose invisible characters.</p>
   <pre id="review-exact"></pre>
  </details>
 </div>
 <footer>
  <div id="review-actions" hidden>
   <button type="button" id="review-approve" class="ok">Approve with passkey</button>
   <button type="button" id="review-deny" class="deny">Deny</button>
  </div>
  <p id="review-result" role="status"></p>
 </footer>
</dialog>
<script src="/console.js"></script>
</body>
</html>
"""

_REVIEW_JS = Path(__file__).with_name("command_review.js").read_text(encoding="utf-8")

_CONSOLE_JS = """'use strict';
// base64url <-> ArrayBuffer helpers (WebAuthn speaks ArrayBuffers)
function b64uToBuf(s){const b=atob(s.replace(/-/g,'+').replace(/_/g,'/'));const a=new Uint8Array(b.length);for(let i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a.buffer}
function bufToB64u(buf){const a=new Uint8Array(buf);let s='';for(const b of a)s+=String.fromCharCode(b);return btoa(s).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'')}

async function api(path,opts={}){
  const res=await fetch(path,{credentials:'same-origin',headers:{'Content-Type':'application/json'},...opts});
  const body=await res.json().catch(()=>({}));
  if(!res.ok){const e=new Error(body.detail&&body.detail.code||res.status);e.code=body.detail&&body.detail.code;e.body=body;throw e}
  return body;
}

const $=(id)=>document.getElementById(id);
let histPage=0, historySeq=0, historyKey='', pendingKey='';
let refreshing=false;

async function refresh(){
  if(refreshing)return;
  refreshing=true;
  try{
    const {pending}=await api('/approvals');
    $('empty').hidden=pending.length>0;
    $('count').textContent=pending.length?`(${pending.length})`:'';
    pendingReadAt=performance.now();
    pendingReviews=pending;
    const key=JSON.stringify(pending.map(r=>r.id));
    if(key!==pendingKey){
      $('approvals').replaceChildren(...pending.map(card));
      pendingKey=key;
    }
    if(activeReview?.pending && !pending.some(r=>r.id===activeReview.request.id)){
      activeReview.ended=true;
      updateReviewButtons();
    }
    syncLinkedReview();
    loadHistory(histPage);
  }catch(e){
    if(e.code==='not_signed_in'){
      $('who').textContent='';
      if(activeReview?.pending){activeReview.ended=true;updateReviewButtons()}
    }
  }finally{refreshing=false}
}

// History cells carry agent-controlled strings (argv, host, cwd): build
// them as text nodes only, never markup.
function cell(text,cls){const td=document.createElement('td');td.textContent=text;if(cls)td.className=cls;return td}

async function loadHistory(page){
  histPage=page;
  const seq=++historySeq;
  try{
    const h=await api(`/history?page=${page}`);
    if(seq!==historySeq)return;
    const pages=Math.max(1,Math.ceil(h.total/h.page_size));
    if(h.page>0&&h.page>=pages)return loadHistory(pages-1);
    const key=JSON.stringify(h.items.map(r=>r.id));
    if(key!==historyKey){
      const rows=$('history-rows');
      rows.replaceChildren(...h.items.map(r=>{
        const tr=document.createElement('tr');
        const cmd=cell('', 'cmd');
        const show=document.createElement('button');
        show.type='button';show.className='history-command';
        show.textContent=commandSummary(r.argv);
        show.onclick=()=>openReview(r,false);
        cmd.append(show);
        tr.append(cell(new Date(r.created_at*1000).toLocaleString()),cell(visibleText(r.host)),
          cmd,cell(r.status,'s-'+r.status));
        return tr;
      }));
      historyKey=key;
    }
    $('history').hidden=h.total===0;
    $('hist-empty').hidden=h.total>0;
    $('hist-page').textContent=h.total?`page ${histPage+1} of ${pages}`:'';
    $('hist-newer').disabled=histPage===0;
    $('hist-older').disabled=histPage+1>=pages;
  }catch(e){}
}

$('hist-newer').onclick=()=>loadHistory(histPage-1);
$('hist-older').onclick=()=>loadHistory(histPage+1);

function card(r){
  // Every field comes from the gated side (cwd is a directory name the
  // agent picks): text nodes only, never markup, so the card you approve
  // shows exactly what was asked.
  const el=(tag,text,cls)=>{const e=document.createElement(tag);if(text!=null)e.textContent=text;if(cls)e.className=cls;return e};
  const d=el('div',null,'card');
  const head=el('div');
  head.append(el('b',visibleText(r.host)),' · user ',el('code',visibleText(r.user)));
  const cmd=el('p');cmd.append(el('code',commandSummary(r.argv)));
  const review=el('button','Review command');
  review.type='button';
  review.onclick=()=>{
    const current=pendingReviews.find(item=>item.id===r.id);
    if(current)openReview(current,true);
  };
  d.append(head,cmd,review);
  return d;
}

async function approve(id){
  const {challenge_id,options}=await api(`/approvals/${id}/approve/options`,{method:'POST'});
  const cred=await navigator.credentials.get({publicKey:{
    challenge:b64uToBuf(options.challenge),
    rpId:options.rpId,timeout:options.timeout,userVerification:options.userVerification,
    allowCredentials:(options.allowCredentials||[]).map(c=>({type:c.type,id:b64uToBuf(c.id)})),
  }});
  await api(`/approvals/${id}/approve`,{method:'POST',body:JSON.stringify({
    challenge_id,
    credential_id:cred.id,
    client_data_json:bufToB64u(cred.response.clientDataJSON),
    authenticator_data:bufToB64u(cred.response.authenticatorData),
    signature:bufToB64u(cred.response.signature),
  })});
}

async function signIn(){
  try{
    const {challenge_id,options}=await api('/login/options',{method:'POST',body:'{}'});
    const cred=await navigator.credentials.get({publicKey:{
      challenge:b64uToBuf(options.challenge),
      rpId:options.rpId,timeout:options.timeout,userVerification:options.userVerification,
      allowCredentials:(options.allowCredentials||[]).map(c=>({type:c.type,id:b64uToBuf(c.id)})),
    }});
    const {label}=await api('/login',{method:'POST',body:JSON.stringify({
      challenge_id,
      credential_id:cred.id,
      client_data_json:bufToB64u(cred.response.clientDataJSON),
      authenticator_data:bufToB64u(cred.response.authenticatorData),
      signature:bufToB64u(cred.response.signature),
    })});
    $('who').textContent='signed in: '+label;
    refresh();
  }catch(e){alert('Sign-in failed: '+(e.code||e.message))}
}

$('signin-btn').onclick=signIn;
$('enroll-form').onsubmit=async(ev)=>{
  ev.preventDefault();
  try{
    const enroll_code=$('enroll-code').value.trim(),label=$('enroll-label').value.trim();
    const {challenge_id,user_id,options}=await api('/enroll/options',{method:'POST',body:JSON.stringify({enroll_code,label})});
    const cred=await navigator.credentials.create({publicKey:{
      challenge:b64uToBuf(options.challenge),
      rp:{id:options.rp.id,name:options.rp.name},
      user:{id:b64uToBuf(user_id),name:options.user.name,displayName:options.user.displayName},
      pubKeyCredParams:options.pubKeyCredParams,timeout:options.timeout,
      excludeCredentials:(options.excludeCredentials||[]).map(c=>({type:c.type,id:b64uToBuf(c.id)})),
      authenticatorSelection:options.authenticatorSelection,attestation:options.attestation,
    }});
    await api('/enroll',{method:'POST',body:JSON.stringify({
      challenge_id,enroll_code,label,
      credential_id:cred.id,
      client_data_json:bufToB64u(cred.response.clientDataJSON),
      attestation_object:bufToB64u(cred.response.attestationObject),
    })});
    alert('Passkey enrolled — sign in with it now.');
    $('enroll').hidden=true;
  }catch(e){alert('Enroll failed: '+(e.code||e.message))}
};

const PUSH_ON='Notifications: on';
const PUSH_OFF='Notifications';

async function currentSub(){
  if(!('serviceWorker' in navigator))return null;
  const reg=await navigator.serviceWorker.getRegistration();
  return reg?reg.pushManager.getSubscription():null;
}

async function togglePush(){
  try{
    const sub=await currentSub();
    if(sub){
      await api('/push/unsubscribe',{method:'POST',body:JSON.stringify({endpoint:sub.endpoint})});
      await sub.unsubscribe();
      $('push-btn').textContent=PUSH_OFF;
      return;
    }
    if(Notification.permission==='denied'){alert('Notifications are blocked for this site (browser settings).');return}
    const perm=await Notification.requestPermission();
    if(perm!=='granted')return;
    // Re-enabling rotates the gate's VAPID key;
    // subscribe with the fresh key it hands back.
    const {public_key}=await api('/push/rotate',{method:'POST'});
    const sw=await navigator.serviceWorker.register('/sw.js');
    const fresh=await sw.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:b64uToBuf(public_key)});
    const info=fresh.toJSON();
    await api('/push/subscribe',{method:'POST',body:JSON.stringify({endpoint:info.endpoint,keys:info.keys})});
    $('push-btn').textContent=PUSH_ON;
  }catch(e){alert('Push: '+(e.code||e.message))}
}

$('push-btn').onclick=togglePush;

// Re-post the browser's live subscription on every signed-in load:
// browsers rotate push endpoints, and the gate only learns the new one
// here. The server upserts by endpoint, so repeating it is harmless.
// After a gate VAPID rotation a subscription bound to the retired
// key is replaced, not re-posted: the gate can no longer push to it.
function sameKey(a,b){const x=new Uint8Array(a),y=new Uint8Array(b);return x.length===y.length&&x.every((v,i)=>v===y[i])}

async function syncPush(){
  let sub=await currentSub();
  if(!sub)return;
  $('push-btn').textContent=PUSH_ON;
  const {public_key}=await api('/push/public-key');
  const current=b64uToBuf(public_key);
  const bound=sub.options&&sub.options.applicationServerKey;
  if(bound&&!sameKey(bound,current)){
    await sub.unsubscribe();
    const reg=await navigator.serviceWorker.getRegistration();
    sub=await reg.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:current});
  }
  const info=sub.toJSON();
  await api('/push/subscribe',{method:'POST',body:JSON.stringify({endpoint:info.endpoint,keys:info.keys})});
}

(async()=>{
  try{
    const me=await api('/whoami');
    $('who').textContent='signed in: '+me.label;
    if('serviceWorker' in navigator){
      $('push-btn').hidden=false;
      syncPush().catch(()=>{});
    }
  }catch(e){
    $('who').textContent='not signed in';
    // No passkeys yet? Show the enroll panel so the first key can be added.
    try{await api('/login/options',{method:'POST',body:'{}'})}catch(err){
      if(err.code==='no_passkeys')$('enroll').hidden=false;
    }
  }
  initReview();
  refresh();setInterval(refresh,5000);
})();
"""


_SW_JS = """'use strict';
// neko-sudo service worker: show approval pushes; tap opens the card.

// Only ever open a page on this origin: a URL from a push payload is
// resolved against our own origin, and anything that lands elsewhere
// (https://x, //x, /\\x, javascript:) collapses to the console root.
function sameOriginPath(raw) {
  try {
    const u = new URL(typeof raw === 'string' ? raw : '/', self.location.origin);
    if (u.origin !== self.location.origin) return '/';
    return u.pathname + u.search + u.hash;
  } catch (e) {
    return '/';
  }
}

self.addEventListener('push', (event) => {
  let data = {};
  try { data = event.data.json(); } catch (e) { /* keep {} */ }
  event.waitUntil(self.registration.showNotification(
    data.title || 'neko-sudo',
    {
      body: data.body || 'approval requested',
      tag: 'neko-sudo-approval',
      renotify: true,
      data: { url: sameOriginPath(data.url) },
    },
  ));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = sameOriginPath(event.notification.data && event.notification.data.url);
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((wins) => {
      for (const w of wins) {
        if ('focus' in w) { w.navigate(url); return w.focus(); }
      }
      return self.clients.openWindow(url);
    }),
  );
});

// The browser rotated the push subscription: subscribe again with
// the same VAPID key and hand the NEW endpoint to the gate, even with no
// console tab open. Anything that fails here is repaired by the console's
// resync on the next signed-in load.
self.addEventListener('pushsubscriptionchange', (event) => {
  event.waitUntil((async () => {
    let sub = event.newSubscription;
    if (!sub) {
      // The gate's current key wins: after a VAPID rotation the old
      // subscription's key is the retired one. Fall back to it only when
      // the gate can't be asked (signed out).
      let applicationServerKey = null;
      try {
        const res = await fetch('/push/public-key', { credentials: 'same-origin' });
        if (res.ok) applicationServerKey = (await res.json()).public_key;
      } catch (e) { /* offline: fall back to the old key below */ }
      if (!applicationServerKey) {
        const old = event.oldSubscription;
        applicationServerKey = old && old.options && old.options.applicationServerKey;
      }
      if (!applicationServerKey) return;
      sub = await self.registration.pushManager.subscribe(
        { userVisibleOnly: true, applicationServerKey });
    }
    const info = sub.toJSON();
    await fetch('/push/subscribe', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ endpoint: info.endpoint, keys: info.keys }),
    });
  })());
});
"""
