"""Payload digest, deliberately identical to gate.store.payload_digest.

Kept as a separate implementation (not an import) because the deployed
wrapper is a standalone script; tests/test_digest_parity.py pins the two
together.
"""

from __future__ import annotations

import hashlib
import json


def payload_digest(host: str, user: str, argv: list[str], cwd: str) -> str:
    canonical = json.dumps(
        {"host": host, "user": user, "argv": argv, "cwd": cwd},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
