"""Operator CLI for the gate's console passkey store.

Run inside the gate container (or against a mounted store file):

    python -m gate.enroll enroll --ttl 600
    python -m gate.enroll list
    python -m gate.enroll revoke <id-prefix>

Enrollment codes are minted here, shown once, stored only as SHA-256,
burn on first successful use (or after five wrong attempts).
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from gate.passkeys import ConsolePasskeyStore, PasskeyStoreError

# Mirrors the server's NEKO_SUDO_PASSKEYS (gate/server.py) so a bare
# `python -m gate.enroll enroll` inside the container writes to the store
# the service actually reads (/data/console-passkeys.json), not a stray
# runtime/ path in the container's ephemeral layer. Resolved per call, not
# at import, so environment changes are always honored.
def _default_store_path() -> Path:
    return Path(
        os.environ.get("NEKO_SUDO_PASSKEYS", "runtime/console-passkeys.json")
    )


def main(argv: list[str] | None = None, *,
         store_path: Path | str | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m gate.enroll",
        description="Manage owner console passkeys for the neko-sudo gate.",
    )
    parser.add_argument(
        "--store", type=Path,
        default=Path(store_path) if store_path else _default_store_path(),
        help="passkey store file (default: $NEKO_SUDO_PASSKEYS, else runtime/)",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    enroll = sub.add_parser("enroll", help="mint a single-use enrollment code")
    enroll.add_argument("--ttl", type=int, default=600,
                        help="seconds the code stays valid (default: %(default)s)")

    sub.add_parser("list", help="list enrolled passkeys")

    revoke = sub.add_parser("revoke", help="revoke a passkey by unique id prefix")
    revoke.add_argument("id_prefix")

    args = parser.parse_args(argv)
    store = ConsolePasskeyStore(args.store)

    if args.cmd == "enroll":
        code = store.new_enrollment(ttl_s=args.ttl)
        print(f"Enrollment code (valid {args.ttl}s, single use): {code}")
        print("Open the console and paste it under 'Enroll a passkey'.")
        return 0

    if args.cmd == "list":
        creds = store.list()
        if not creds:
            print("No console passkeys enrolled.")
            return 0
        for c in creds:
            print(f"{c['id_prefix']}  label={c['label']}  alg={c['alg']}"
                  f"  created_at={c['created_at']}")
        return 0

    if args.cmd == "revoke":
        try:
            removed = store.revoke(args.id_prefix)
        except PasskeyStoreError as exc:
            print(f"{exc.code}: {exc}", file=sys.stderr)
            return 1
        print(f"Revoked {removed['label']} ({removed['id_prefix']})")
        return 0

    parser.error(f"unknown command {args.cmd!r}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
