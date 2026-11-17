#!/bin/sh
# neko-sudo host installer — run as root on a target host, from a checkout
# (or next to a copied hostside/ + deploy/ tree).
#
#   ./install.sh [agent-account]        (default: agent)
#
# Idempotent: re-running never clobbers an existing config or sudoers file.
set -eu

AGENT=${1:-agent}
LIB=/usr/local/lib/neko-sudo
ETC=/usr/local/etc/neko-sudo.conf
SUDOERS=/etc/sudoers.d/neko-sudo-agent
SRC=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ "$(id -u)" -ne 0 ]; then
    echo "neko-sudo: run as root" >&2
    exit 1
fi
if ! id "$AGENT" >/dev/null 2>&1; then
    echo "neko-sudo: agent account '$AGENT' does not exist" >&2
    exit 1
fi

# Wrapper package + shim, all root-owned; the agent can read but not write.
install -d -o root -g root -m 0755 "$LIB/hostside"
for f in "$SRC"/hostside/*.py; do
    install -o root -g root -m 0644 "$f" "$LIB/hostside/"
done
install -o root -g root -m 0755 "$SRC/hostside/run" "$LIB/run"

# Config: create once, root-only. Token must match the gate's tokens.conf
# (host = the name in that file, token = the raw secret minted alongside).
if [ ! -f "$ETC" ]; then
    umask 077
    sed -e "s|@HOST@|$(hostname -s)|" -e "s|@USER@|$AGENT|" "$SRC/deploy/neko-sudo.conf.template" > "$ETC"
    chown root:root "$ETC"
    chmod 0600 "$ETC"
    echo "WROTE $ETC — set the token before first use"
else
    echo "KEEP existing $ETC"
fi

# Sudoers: agent may reach root ONLY through the wrapper. Validate first,
# activate atomically, never overwrite an existing file.
if [ -e "$SUDOERS" ]; then
    if ! grep -q "^$AGENT " "$SUDOERS" 2>/dev/null; then
        echo "WARNING: $SUDOERS exists but does not grant '$AGENT' — wrong account?" >&2
        echo "  Fix: rm $SUDOERS && re-run: $0 $AGENT" >&2
    fi
    echo "KEEP existing $SUDOERS"
else
    TMP=$(mktemp)
    echo "$AGENT ALL=(root) NOPASSWD: $LIB/run" > "$TMP"
    chmod 0440 "$TMP"
    if ! visudo -cf "$TMP" >/dev/null; then
        rm -f "$TMP"
        echo "neko-sudo: sudoers line failed visudo check" >&2
        exit 1
    fi
    mv "$TMP" "$SUDOERS"
    echo "INSTALLED $SUDOERS"
fi

echo "Done. Smoke test as the agent:"
echo "  sudo -u $AGENT sudo $LIB/run -- true"
