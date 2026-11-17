"""VAPID key material for the gate's own web-push identity."""

import base64
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def _load(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["private_pem"], data["public_key"]


def test_first_boot_generates_and_persists_keypair(tmp_path):
    from gate.vapid import load_or_generate

    path = tmp_path / "vapid.json"
    keys = load_or_generate(path)
    assert path.exists(), "keypair must survive restarts (subscriptions bind to it)"
    private_pem, public_key = _load(path)
    assert keys.private_pem == private_pem
    assert keys.public_key == public_key


def test_reload_returns_the_same_identity(tmp_path):
    from gate.vapid import load_or_generate

    path = tmp_path / "vapid.json"
    first = load_or_generate(path)
    again = load_or_generate(path)
    assert first.public_key == again.public_key
    assert first.private_pem == again.private_pem


def test_public_key_is_browser_application_server_key(tmp_path):
    from gate.vapid import load_or_generate

    keys = load_or_generate(tmp_path / "vapid.json")
    raw = base64.urlsafe_b64decode(keys.public_key + "==")
    assert len(raw) == 65, "uncompressed P-256 point: 0x04 || X || Y"
    assert raw[0] == 4


def test_private_pem_derives_the_advertised_public_key(tmp_path):
    from gate.vapid import load_or_generate

    keys = load_or_generate(tmp_path / "vapid.json")
    priv = serialization.load_pem_private_key(keys.private_pem.encode(), password=None)
    point = priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    import base64 as b64

    assert b64.urlsafe_b64encode(point).rstrip(b"=").decode() == keys.public_key


def test_identity_rotation_mints_and_persists_a_new_keypair(tmp_path):
    """The VAPID key must be rotatable from the console (e.g. after a
    suspected exposure). A rotation replaces the keypair on disk and in
    memory; the old one is gone."""
    from gate.vapid import VapidIdentity, load_or_generate

    path = tmp_path / "vapid.json"
    identity = VapidIdentity(path)
    old_public, old_private = identity.public_key, identity.private_pem

    new_public = identity.rotate()

    assert new_public != old_public
    assert identity.public_key == new_public
    assert identity.private_pem != old_private
    on_disk = load_or_generate(path)
    assert (on_disk.public_key, on_disk.private_pem) == (new_public, identity.private_pem)
    priv = serialization.load_pem_private_key(identity.private_pem.encode(), password=None)
    point = priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    assert base64.urlsafe_b64encode(point).rstrip(b"=").decode() == new_public
    assert not list(tmp_path.glob("*.tmp")), "atomic replace leaves no temp file"
