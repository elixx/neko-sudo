"""Console WebAuthn passkey and enrollment store.

Persists enrolled console passkeys and the single active enrollment code in
``runtime/console-passkeys.json`` (by default; path injectable for tests).
The enrollment CLI (``python -m gate.enroll``) and the gate server cooperate
through this file without IPC: every operation re-reads the file under an
in-process lock and writes updates atomically in UTF-8 text mode.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

from .webauthn import b64url_encode

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PASSKEYS_PATH = ROOT / 'runtime' / 'console-passkeys.json'

SCHEMA_VERSION = 1
DEFAULT_ENROLL_TTL_S = 600
MAX_ENROLL_TTL_S = 86400
MAX_ENROLL_FAILURES = 5
ID_PREFIX_LEN = 12
LABEL_MAX_LEN = 80

# 32 unambiguous uppercase + digit characters (no 0/O/1/I): 5 bits/char.
# 4 groups of 4 = 16 chars = 80 bits of entropy.
ENROLL_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
ENROLL_GROUPS = 4
ENROLL_GROUP_LEN = 4


class PasskeyStoreError(ValueError):
    """Passkey store or enrollment error; ``code`` is a machine reason."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def normalize_enroll_code(raw: Any) -> str:
    """Normalize a human-typed enrollment code to ``XXXX-XXXX-XXXX-XXXX``."""
    if not isinstance(raw, str):
        return ''
    compact = re.sub(r'[\s-]+', '', raw).upper()
    total_len = ENROLL_GROUPS * ENROLL_GROUP_LEN
    if len(compact) == total_len:
        return '-'.join(compact[i:i + ENROLL_GROUP_LEN]
                        for i in range(0, total_len, ENROLL_GROUP_LEN))
    return raw.strip().upper()


def hash_enroll_code(code: Any) -> str:
    """SHA-256 hex digest of the normalized enrollment code."""
    normalized = normalize_enroll_code(code)
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()


def _generate_enroll_code() -> str:
    groups = [
        ''.join(secrets.choice(ENROLL_ALPHABET) for _ in range(ENROLL_GROUP_LEN))
        for _ in range(ENROLL_GROUPS)
    ]
    return '-'.join(groups)


def validate_label(label: Any) -> str:
    if not isinstance(label, str):
        raise PasskeyStoreError('invalid_label', 'label must be a string')
    cleaned = label.strip()
    if not 1 <= len(cleaned) <= LABEL_MAX_LEN:
        raise PasskeyStoreError('invalid_label',
                                f'label must be 1-{LABEL_MAX_LEN} characters')
    return cleaned


class ConsolePasskeyStore:
    """Thread-safe, file-backed store for console WebAuthn passkeys."""

    def __init__(self, path: Optional[Path | str] = None, *,
                 clock: Callable[[], float] = time.time):
        self._path = Path(path) if path is not None else DEFAULT_PASSKEYS_PATH
        self._clock = clock
        self._lock = threading.RLock()

    @property
    def path(self) -> Path:
        return self._path

    # --------------------------------------------------------- disk I/O
    def _default_state(self) -> dict:
        return {
            'version': SCHEMA_VERSION,
            'user_id': b64url_encode(secrets.token_bytes(16)),
            'credentials': [],
            'enrollment': None,
        }

    def _load_locked(self) -> dict:
        try:
            raw = self._path.read_text(encoding='utf-8')
        except FileNotFoundError:
            return self._default_state()
        except OSError as exc:
            raise PasskeyStoreError('store_unavailable',
                                    f'cannot read passkey store: {exc}') from exc
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise PasskeyStoreError('store_corrupt',
                                    f'passkey store is not valid JSON: {exc}') from exc
        if not isinstance(data, dict) or data.get('version') != SCHEMA_VERSION:
            raise PasskeyStoreError('store_corrupt',
                                    'unsupported passkey store schema version')
        user_id = data.get('user_id')
        credentials = data.get('credentials')
        enrollment = data.get('enrollment')
        if not isinstance(user_id, str) or not user_id or not isinstance(credentials, list):
            raise PasskeyStoreError('store_corrupt', 'passkey store fields are malformed')
        if enrollment is not None and not isinstance(enrollment, dict):
            raise PasskeyStoreError('store_corrupt', 'passkey store enrollment is malformed')
        return {
            'version': SCHEMA_VERSION,
            'user_id': user_id,
            'credentials': [dict(c) for c in credentials if isinstance(c, dict)],
            'enrollment': dict(enrollment) if isinstance(enrollment, dict) else None,
        }

    def _save_locked(self, state: dict) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            dir=str(self._path.parent),
            prefix=self._path.name + '.',
            suffix='.tmp',
        )
        try:
            with open(fd, 'w', encoding='utf-8', newline='\n') as handle:
                handle.write(json.dumps(state, indent=2, ensure_ascii=False) + '\n')
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self._path)
        finally:
            tmp = Path(tmp_name)
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass

    def _prune_expired_enrollment_locked(self, state: dict, now: float) -> bool:
        """Clear expired or burned enrollment in ``state``; return True if active."""
        enrollment = state.get('enrollment')
        if not isinstance(enrollment, dict):
            state['enrollment'] = None
            return False
        expires_at = enrollment.get('expires_at')
        failures = enrollment.get('failures', 0)
        if (not isinstance(expires_at, (int, float))
                or isinstance(expires_at, bool)
                or now >= float(expires_at)
                or not isinstance(failures, int)
                or isinstance(failures, bool)
                or failures >= MAX_ENROLL_FAILURES):
            state['enrollment'] = None
            return False
        return True

    # --------------------------------------------------------- user_id
    def user_id(self) -> str:
        """Return the store's persistent random 16-byte base64url user_id."""
        with self._lock:
            exists = self._path.exists()
            state = self._load_locked()
            if not exists:
                self._save_locked(state)
            return state['user_id']

    # --------------------------------------------------------- enrollment
    def new_enrollment(self, ttl_s: float = DEFAULT_ENROLL_TTL_S) -> str:
        """Create a new enrollment code, persist only its SHA-256 + expiry, and return the code."""
        if isinstance(ttl_s, bool) or not isinstance(ttl_s, (int, float)) or not 1 <= ttl_s <= MAX_ENROLL_TTL_S:
            raise PasskeyStoreError('invalid_ttl',
                                    f'enrollment ttl_s must be between 1 and {MAX_ENROLL_TTL_S} seconds')
        code = _generate_enroll_code()
        code_sha256 = hash_enroll_code(code)
        now = float(self._clock())
        with self._lock:
            state = self._load_locked()
            state['enrollment'] = {
                'code_sha256': code_sha256,
                'expires_at': now + float(ttl_s),
                'failures': 0,
            }
            self._save_locked(state)
        return code

    def enrollment_pending(self) -> bool:
        """True if an unburned, unexpired enrollment code is currently pending."""
        with self._lock:
            if not self._path.exists():
                return False
            state = self._load_locked()
            now = float(self._clock())
            had = state.get('enrollment') is not None
            active = self._prune_expired_enrollment_locked(state, now)
            if had and not active:
                self._save_locked(state)
            return active

    def check_enrollment(self, code: Any, *, consume: bool = False) -> bool:
        """Constant-time enrollment code verification.

        Increments ``failures`` on mismatch and burns the enrollment after
        5 wrong attempts. When ``consume=True``, burns the enrollment on a
        matching check as well.
        """
        candidate_sha256 = hash_enroll_code(code)
        with self._lock:
            state = self._load_locked()
            now = float(self._clock())
            had = state.get('enrollment') is not None
            if not self._prune_expired_enrollment_locked(state, now):
                if had:
                    self._save_locked(state)
                hmac.compare_digest(candidate_sha256, '0' * 64)
                return False
            enrollment = state['enrollment']
            expected_sha256 = str(enrollment.get('code_sha256', ''))
            valid_input = isinstance(code, str) and bool(code.strip())
            matched = hmac.compare_digest(expected_sha256, candidate_sha256) and valid_input
            if not matched:
                failures = int(enrollment.get('failures', 0)) + 1
                if failures >= MAX_ENROLL_FAILURES:
                    state['enrollment'] = None
                else:
                    enrollment['failures'] = failures
                self._save_locked(state)
                return False
            if consume:
                state['enrollment'] = None
                self._save_locked(state)
            return True

    def consume_enrollment(self) -> None:
        """Clear any active enrollment."""
        with self._lock:
            state = self._load_locked()
            if state.get('enrollment') is not None:
                state['enrollment'] = None
                self._save_locked(state)

    # --------------------------------------------------------- credentials
    @staticmethod
    def _public_view(cred: dict) -> dict:
        cred_id = str(cred.get('id', ''))
        return {
            'id': cred_id,
            'id_prefix': cred_id[:ID_PREFIX_LEN],
            'label': cred.get('label', ''),
            'alg': cred.get('alg'),
            'rp_id': cred.get('rp_id', ''),
            'sign_count': int(cred.get('sign_count', 0) or 0),
            'created_at': cred.get('created_at'),
            'last_used_at': cred.get('last_used_at'),
        }

    def save_credential(self, verified: dict, *, label: str,
                        consume_enrollment: bool = True) -> dict:
        """Persist a verified WebAuthn credential and optionally consume enrollment."""
        clean_label = validate_label(label)
        if not isinstance(verified, dict):
            raise PasskeyStoreError('invalid_credential', 'verified credential must be a dict')
        cred_id = verified.get('id')
        alg = verified.get('alg')
        public_key = verified.get('public_key')
        rp_id = verified.get('rp_id')
        sign_count = int(verified.get('sign_count', 0) or 0)
        if (not isinstance(cred_id, str) or not cred_id
                or not isinstance(rp_id, str) or not rp_id
                or not isinstance(public_key, dict)):
            raise PasskeyStoreError('invalid_credential', 'verified credential fields are incomplete')
        now = float(self._clock())
        with self._lock:
            state = self._load_locked()
            for existing in state['credentials']:
                if hmac.compare_digest(str(existing.get('id', '')), cred_id):
                    raise PasskeyStoreError('duplicate_credential',
                                            'this passkey credential is already registered')
            entry = {
                'id': cred_id,
                'label': clean_label,
                'alg': alg,
                'public_key': dict(public_key),
                'rp_id': rp_id,
                'sign_count': sign_count,
                'created_at': now,
                'last_used_at': None,
            }
            state['credentials'].append(entry)
            if consume_enrollment:
                state['enrollment'] = None
            self._save_locked(state)
            return self._public_view(entry)

    add_credential = save_credential
    register_credential = save_credential

    def list(self, *, rp_id: Optional[str] = None) -> list[dict]:
        """Return stored credentials (without public_key material)."""
        with self._lock:
            if not self._path.exists():
                return []
            state = self._load_locked()
            items = []
            for cred in state['credentials']:
                if rp_id is not None and cred.get('rp_id') != rp_id:
                    continue
                items.append(self._public_view(cred))
            return items

    def get_credential(self, credential_id: str, *, rp_id: Optional[str] = None) -> Optional[dict]:
        """Look up one credential by exact id (and optional rp_id), including public_key."""
        if not isinstance(credential_id, str) or not credential_id:
            return None
        with self._lock:
            if not self._path.exists():
                return None
            state = self._load_locked()
            for cred in state['credentials']:
                if hmac.compare_digest(str(cred.get('id', '')), credential_id):
                    if rp_id is not None and cred.get('rp_id') != rp_id:
                        return None
                    result = dict(cred)
                    result['id_prefix'] = str(cred.get('id', ''))[:ID_PREFIX_LEN]
                    result['public_key'] = dict(cred.get('public_key') or {})
                    return result
            return None

    def revoke(self, id_prefix: str) -> dict:
        """Revoke a credential by unique ID prefix; refuse empty, unknown, or ambiguous prefixes."""
        if not isinstance(id_prefix, str) or not id_prefix.strip():
            raise PasskeyStoreError('invalid_prefix', 'id_prefix must be a non-empty string')
        prefix = id_prefix.strip()
        with self._lock:
            state = self._load_locked()
            matches = [
                (idx, cred) for idx, cred in enumerate(state['credentials'])
                if str(cred.get('id', '')).startswith(prefix)
            ]
            if not matches:
                raise PasskeyStoreError('unknown_credential',
                                        f'no passkey matches prefix {prefix!r}')
            if len(matches) > 1:
                raise PasskeyStoreError('ambiguous_prefix',
                                        f'prefix {prefix!r} is ambiguous ({len(matches)} passkeys match)')
            idx, removed = matches[0]
            state['credentials'].pop(idx)
            self._save_locked(state)
            return self._public_view(removed)

    def resolve_prefix(self, id_prefix: str, *, rp_id: Optional[str] = None) -> dict:
        """Return the full credential uniquely matching ``id_prefix`` (no delete).

        Console deletion flow: resolve the target first (unknown/ambiguous are
        refused before any WebAuthn work), verify the owner's assertion, then
        revoke by the resolved full id. ``rp_id`` scopes the match to one
        relying party so a prefix can never cross consoles.
        """
        if not isinstance(id_prefix, str) or not id_prefix.strip():
            raise PasskeyStoreError('invalid_prefix', 'id_prefix must be a non-empty string')
        prefix = id_prefix.strip()
        with self._lock:
            state = self._load_locked()
            matches = [
                cred for cred in state['credentials']
                if str(cred.get('id', '')).startswith(prefix)
                and (rp_id is None or cred.get('rp_id') == rp_id)
            ]
            if not matches:
                raise PasskeyStoreError('unknown_credential',
                                        f'no passkey matches prefix {prefix!r}')
            if len(matches) > 1:
                raise PasskeyStoreError('ambiguous_prefix',
                                        f'prefix {prefix!r} is ambiguous ({len(matches)} passkeys match)')
            cred = dict(matches[0])
            cred['id_prefix'] = str(cred.get('id', ''))[:ID_PREFIX_LEN]
            return cred

    def update_sign_count(self, credential_id: str, sign_count: int, *,
                          last_used_at: Optional[float] = None) -> dict:
        """Update ``sign_count`` and ``last_used_at`` for ``credential_id``."""
        if not isinstance(credential_id, str) or not credential_id:
            raise PasskeyStoreError('unknown_credential', 'credential_id must be a non-empty string')
        if isinstance(sign_count, bool) or not isinstance(sign_count, int) or sign_count < 0:
            raise PasskeyStoreError('invalid_sign_count', 'sign_count must be a non-negative int')
        now = float(self._clock() if last_used_at is None else last_used_at)
        with self._lock:
            state = self._load_locked()
            for cred in state['credentials']:
                if hmac.compare_digest(str(cred.get('id', '')), credential_id):
                    cred['sign_count'] = sign_count
                    cred['last_used_at'] = now
                    self._save_locked(state)
                    return self._public_view(cred)
            raise PasskeyStoreError('unknown_credential',
                                    f'unknown passkey credential {credential_id!r}')
