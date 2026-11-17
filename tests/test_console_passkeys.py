"""Unit tests for the console passkey store."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from gate.passkeys import (  # noqa: E402
    ConsolePasskeyStore,
    ENROLL_ALPHABET,
    PasskeyStoreError,
)


class FakeClock:
    def __init__(self, now: float = 1_760_000_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


def _sample_verified(cred_id: str = 'cred_alpha_123456', rp_id: str = 'localhost') -> dict:
    return {
        'id': cred_id,
        'alg': -7,
        'public_key': {
            'kty': 'EC2',
            'crv': 'P-256',
            'x': 'Wn2cerKsaT4PpxK249ScXWV_2POwbZc0DHC8TvwZSzY',
            'y': '3BuUMGjziHa2X--JcoVdDfFHvgLvyTLYyb-mBm65SQU',
        },
        'sign_count': 1,
        'rp_id': rp_id,
    }


def test_enrollment_stores_only_sha256_and_enforces_ttl(tmp_path):
    clock = FakeClock()
    path = tmp_path / 'console-passkeys.json'
    store = ConsolePasskeyStore(path, clock=clock)

    uid = store.user_id()
    assert store.user_id() == uid  # created once and persisted

    code = store.new_enrollment(ttl_s=600)
    parts = code.split('-')
    assert len(parts) == 4 and all(len(p) == 4 for p in parts)
    assert all(ch in ENROLL_ALPHABET for p in parts for ch in p)

    raw_text = path.read_text(encoding='utf-8')
    assert code not in raw_text
    disk = json.loads(raw_text)
    assert disk['version'] == 1
    assert disk['enrollment']['code_sha256'] == hashlib.sha256(code.encode('utf-8')).hexdigest()
    assert disk['enrollment']['expires_at'] == clock.now + 600.0
    assert disk['enrollment']['failures'] == 0
    assert store.enrollment_pending() is True

    # Valid code (case/whitespace insensitive) succeeds without consuming when consume=False
    assert store.check_enrollment(code.lower().replace('-', ' '), consume=False) is True
    assert store.enrollment_pending() is True

    # Past TTL -> expired and cleared
    clock.now += 601.0
    assert store.check_enrollment(code) is False
    assert store.enrollment_pending() is False
    assert json.loads(path.read_text(encoding='utf-8'))['enrollment'] is None


def test_enrollment_burns_after_five_wrong_attempts(tmp_path):
    clock = FakeClock()
    path = tmp_path / 'console-passkeys.json'
    store = ConsolePasskeyStore(path, clock=clock)
    code = store.new_enrollment(ttl_s=600)

    for attempt in range(1, 5):
        assert store.check_enrollment('WRNG-WRNG-WRNG-WRNG') is False
        assert store.enrollment_pending() is True
        disk = json.loads(path.read_text(encoding='utf-8'))
        assert disk['enrollment']['failures'] == attempt

    # 5th wrong attempt burns the enrollment
    assert store.check_enrollment('WRNG-WRNG-WRNG-WRNG') is False
    assert store.enrollment_pending() is False
    assert json.loads(path.read_text(encoding='utf-8'))['enrollment'] is None

    # Even the real code now fails
    assert store.check_enrollment(code) is False


def test_registration_consumes_enrollment_and_updates_sign_count(tmp_path):
    clock = FakeClock()
    path = tmp_path / 'console-passkeys.json'
    store = ConsolePasskeyStore(path, clock=clock)
    code = store.new_enrollment(ttl_s=600)
    assert store.check_enrollment(code, consume=False) is True

    saved = store.save_credential(_sample_verified('cred_one_abcdef123456'),
                                  label='Laptop Hello', consume_enrollment=True)
    assert saved['id_prefix'] == 'cred_one_abc'
    assert saved['label'] == 'Laptop Hello'
    assert saved['last_used_at'] is None
    assert store.enrollment_pending() is False

    # Public list never leaks public_key
    listed = store.list()
    assert len(listed) == 1
    assert 'public_key' not in listed[0]

    # Separate store instance sees the file immediately (no IPC)
    reader = ConsolePasskeyStore(path, clock=clock)
    full = reader.get_credential('cred_one_abcdef123456', rp_id='localhost')
    assert full is not None and full['public_key']['kty'] == 'EC2'

    clock.now += 42.0
    updated = store.update_sign_count('cred_one_abcdef123456', 7)
    assert updated['sign_count'] == 7
    assert updated['last_used_at'] == clock.now

    # No leftover temp files from atomic writes
    assert list(tmp_path.glob('*.tmp')) == []


def test_revoke_refuses_ambiguous_or_unknown_prefix(tmp_path):
    path = tmp_path / 'console-passkeys.json'
    store = ConsolePasskeyStore(path)
    store.save_credential(_sample_verified('shared_prefix_aaa111'), label='Key A')
    store.save_credential(_sample_verified('shared_prefix_bbb222'), label='Key B')

    with pytest.raises(PasskeyStoreError) as amb:
        store.revoke('shared_prefix_')
    assert amb.value.code == 'ambiguous_prefix'
    assert len(store.list()) == 2

    with pytest.raises(PasskeyStoreError) as unk:
        store.revoke('nonexistent')
    assert unk.value.code == 'unknown_credential'

    removed = store.revoke('shared_prefix_aaa')
    assert removed['label'] == 'Key A'
    remaining = store.list()
    assert len(remaining) == 1 and remaining[0]['label'] == 'Key B'
