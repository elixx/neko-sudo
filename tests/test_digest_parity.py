"""The wrapper computes the same digest as the gate, independently.

gate.store.payload_digest and hostside.digest.payload_digest must stay
byte-identical in canonicalization; this parity test fails if either
side drifts. (The deployed wrapper is a standalone script, so the two
implementations are deliberately separate.)
"""

import pytest

from gate.store import payload_digest as gate_digest
from hostside.digest import payload_digest as hostside_digest

CASES = [
    ("web01", "agent", ["apt", "update"], "/home/agent"),
    ("db01", "agent", ["systemctl", "restart", "nginx", "--now"], "/"),
    ("db-1", "agent", ["bash", "-c", "echo 'quotes\" and ünïcodé'"], "/tmp"),
    ("build", "agent", ["/usr/local/sbin/backup.sh", "--daily", "--quiet"], "/root"),
]


@pytest.mark.parametrize("host,user,argv,cwd", CASES)
def test_digests_match_across_sides(host, user, argv, cwd):
    assert hostside_digest(host, user, argv, cwd) == gate_digest(host, user, argv, cwd)


def test_digest_is_stable_and_deterministic():
    first = hostside_digest("web01", "agent", ["true"], "/tmp")
    second = hostside_digest("web01", "agent", ["true"], "/tmp")
    assert first == second and len(first) == 64
