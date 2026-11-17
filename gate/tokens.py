"""Host token hashing.

Hosts authenticate with a bearer token; the gate stores only the SHA-256
of each token so a database leak does not leak credentials.
"""

import hashlib


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
