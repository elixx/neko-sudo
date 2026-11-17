"""VAPID key material for the gate's own web-push identity.

One P-256 keypair per gate, generated at first boot and persisted on the
data volume. The public half is exposed to browsers as the push
``applicationServerKey``; subscriptions bind to it, so replacing the
keypair invalidates every subscription. :class:`VapidIdentity` is the live
holder the sender and the console share, so a rotation takes effect
everywhere at once.
"""

from __future__ import annotations

import base64
import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


@dataclass(frozen=True)
class VapidKeys:
    private_pem: str  # PEM, EC private key — server side only
    public_key: str   # base64url, uncompressed point — the applicationServerKey


def _application_server_key(private: ec.EllipticCurvePrivateKey) -> str:
    point = private.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    return base64.urlsafe_b64encode(point).rstrip(b"=").decode("ascii")


def _generate() -> VapidKeys:
    private = ec.generate_private_key(ec.SECP256R1())
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return VapidKeys(private_pem=private_pem, public_key=_application_server_key(private))


def _persist(path: Path, keys: VapidKeys) -> None:
    """Atomic write: a crash mid-rotation never leaves a torn keypair."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(
        json.dumps(
            {"private_pem": keys.private_pem, "public_key": keys.public_key},
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    os.replace(tmp, path)


def load_or_generate(path: Path) -> VapidKeys:
    """Return the persisted keypair, generating and saving one if absent."""
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        return VapidKeys(
            private_pem=data["private_pem"], public_key=data["public_key"]
        )
    keys = _generate()
    _persist(path, keys)
    return keys


class VapidIdentity:
    """The gate's current VAPID keypair, rotatable at runtime.

    Readers get ``public_key`` / ``private_pem`` from one immutable
    :class:`VapidKeys` snapshot, swapped by reference on rotation, so a
    reader never sees a half-rotated pair.
    """

    def __init__(self, path):
        self.path = Path(path)
        self._keys = load_or_generate(self.path)
        self._lock = threading.Lock()

    @property
    def public_key(self) -> str:
        return self._keys.public_key

    @property
    def private_pem(self) -> str:
        return self._keys.private_pem

    def rotate(self) -> str:
        """Mint, persist, then publish a new keypair; return its public key."""
        with self._lock:
            keys = _generate()
            _persist(self.path, keys)
            self._keys = keys
            return keys.public_key
