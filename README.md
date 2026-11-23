# neko-sudo

A human-in-the-loop sudo gate for an automation or AI-agent account on Linux
hosts. The agent can obtain root **only** through a small wrapper. Every
command it runs that way needs your explicit approval: you get a push
notification and approve with a passkey (WebAuthn, user verification
required). Anything other than an explicit approval (deny, timeout, network
error, gate unreachable) fails closed.

Components:

- **gate** (`gate/`): a FastAPI service with a host-facing API, an approval
  state machine, an owner console (passkey sign-in, approve/deny, request
  history) and web push with its own VAPID identity. Ships as a container.
- **host wrapper** (`hostside/`): stdlib-only Python 3, installed root-owned
  on each host as `/usr/local/lib/neko-sudo/run`. sudoers grants the agent
  account this one command and nothing else.

## How it works

```
agent@host:  sudo /usr/local/lib/neko-sudo/run -- <argv>
  -> sudoers allows the agent account ONLY the wrapper (root-owned)
  -> wrapper
       -> POST https://<gate>/v1/requests      (per-host token; exact argv, user, cwd)
            -> store request, send push       ("approval needed: host · argv")
       -> poll GET /v1/requests/<id>          (own deadline, fail closed)

owner taps the push -> the gate console (/) lists pending cards
  -> card: host, invoking user, exact argv, cwd, digest (rendered as text only)
  -> approve: passkey assertion with user verification
  -> deny:    signed-in owner session

wrapper polls until approved / denied / expired
  -> same host: an approval is handed over only after every earlier
     request from that host is settled; until then the poll says pending
  -> approved: exec exactly the approved argv as root, clean environment
  -> anything else: exit 1
```

## Why a wrapper, not a sudo approval plugin

sudo's approval-plugin API only exists from **sudo 1.9.0**. sudo 1.8.x cannot
load approval plugins, and **sudo-rs** (the default sudo on recent Ubuntu)
has no plugin API at all. Distribution packages also commonly omit
`sudo_plugin_python.so`, so a plugin usually means a custom C plugin built per
distro and architecture, running inside setuid sudo.

The wrapper works the same on all of them:

```
agent ALL=(root) NOPASSWD: /usr/local/lib/neko-sudo/run
```

- The agent account can reach root **only** through the wrapper, so every
  privileged command goes through the gate.
- No plugin loading, no `sudo.conf` change, nothing compiled against the sudo
  plugin API. The audit surface is one root-owned helper.
- Its sudoers rule (`NOPASSWD:` for exactly one command, no argument
  wildcards) is within the subset sudo-rs supports.
- The gate is mechanism-agnostic: requests carry a digest over
  host/user/argv/cwd, so a future approval plugin could emit identical
  requests and the approval card would look the same.

## Security model

**Approvals**

- Approve requires a fresh passkey assertion with user verification. Deny
  requires the owner's signed-in console session (no passkey), so the agent
  cannot approve or deny its own requests.
- Each request is bound to a digest of its canonical argv, cwd, host and
  invoking user, checked by the wrapper at create and at poll time.
- A request is single-use, expires after the gate-owned window
  (`NEKO_SUDO_APPROVAL_TTL_S`, default 300 s; hosts cannot set it), and
  returns allow only on explicit approval.
- The push carries **no authority**. It is end-to-end encrypted (RFC 8291),
  shows the host and an argv preview, and a tap opens the console page.
- Requests are rate-limited per host (30 per minute).
- **Same-host start order.** Requests from one host carry a per-host
  sequence number. A later request cannot be approved while an earlier one
  from the same host is still pending (deny is always allowed), and the
  console says so: cards, the review screen and the push show the
  request's place in its host's queue (`2 of 3 pending on web01`), and
  `approve/options` answers `409 earlier_pending` before any passkey
  ceremony starts. An approved request is handed to its wrapper only once
  every earlier same-host request is denied, expired or already handed
  over; until then the host poll answers `pending` with `held_behind`,
  which the wrapper keeps polling on. An approval nobody collects stops
  holding later requests back, and can no longer be handed over, 30 s
  after its expiry; that pass-over is recorded (`uncollected_at`) in the
  same commit as the hand-over that relied on it, so a clock stepping back
  cannot revive it. The guarantee is start order: the gate never sees a
  command finish.

**Hosts**

- **No shell escape.** The wrapper refuses interactive and login shells and
  `su`/`login`/`sudoedit`/`visudo` outright. `sudo -i`/`sudo -s` are
  impossible because sudoers permits only the wrapper. Anything else, e.g.
  `bash -c '…'`, is shown on the card as that exact string.
- **Scripts.** Approval covers argv, not file contents: keep any script you
  approve root-owned and not writable by the agent.
- **Root-owned pieces.** The wrapper, its config and the per-host token are
  root-owned and unreadable by the agent account. The wrapper execs only the
  approved argv, with no shell re-parsing and a scrubbed environment.
- **Audit before enabling.** sudo is not the only route to root. On a host
  where the agent has another path, the gate is only advisory. Check each
  host for:
  - group membership granting root-equivalent access (docker, lxd, adm, disk, …)
  - writable files root executes or sources (cron jobs, systemd units,
    scripts on root's PATH, root's shell profiles)
  - polkit rules, `pkexec`, `doas` and `su` configuration
  - root's `authorized_keys`, and any SSH key the agent can use as root
  - writable `/etc/sudoers.d` or `/etc/sudo.conf`
- **Rollout.** Keep a root session open while changing sudoers, and keep a
  separate admin account (with keys the agent cannot read) as break-glass.

**Gate**

- The passkey RP ID is the gate's hostname. Passkeys for other sites never
  work here.
- The gate has its own VAPID keypair. Push subscriptions are per origin.
- Per-host tokens are stored only as SHA-256 hashes. A token can create
  requests and read their status, nothing else. `host` is derived from the
  token, never from the request body.
- Gate state is owner-only: the gate runs with umask 077, so every state file
  it writes is `0600`. This matters if the data volume is shared or replicated
  to hosts where the agent has a shell. `tokens.conf` is edited by hand: keep
  it `0600` yourself.
- The console renders every agent-controlled field (host, user, argv, cwd)
  as text only, so a crafted value (for example a directory name) cannot
  restyle or overlay the card you are approving. The CSP allows only
  same-origin scripts.

## Setup

You need: a hostname for the gate with TLS (a reverse proxy such as nginx in
front of the container), Docker (the provided compose file targets Docker
Swarm), a browser or phone with passkey and web-push support for the owner,
and Python 3 on every target host.

### 1. Build the image

```
NEKO_SUDO_IMAGE=registry.example.com/neko-sudo/gate deploy/build-multiarch.sh
```

This builds amd64 + arm64 and pushes. One-time build-host setup is described
at the top of the script. On GitLab, `.gitlab-ci.yml` runs the tests and
builds to the project's own registry on every push to `main`; it needs a
runner with a privileged docker executor.

### 2. Deploy the gate

Edit `docker-compose.yml`: `image`, `NEKO_SUDO_ORIGIN` (your public
`https://` origin), `NEKO_SUDO_RP_ID` (the hostname), `NEKO_SUDO_PUSH_SUBJECT`
(a `mailto:` contact for push services) and the data directory.

```
install -d -m 0700 /srv/neko-sudo
docker stack deploy -c docker-compose.yml neko-sudo
```

Point your reverse proxy at the published port (18443 by default). The
service is a single replica because its stores are local files. The live
db is node-local: a task that floats to a node without local state boots
from the newest replicated snapshot, so floating is safe as long as the
snapshots below are replicated between nodes.

Data layout under the data directory (bind-mounted to `/data`):

- `/srv/neko-sudo/state/` — node-local live db and quarantine forensics.
  Under the data root but NEVER replicated: exclude it from replication on
  every node sharing the data directory BEFORE the gate first writes there.
- `/srv/neko-sudo/snapshots/` — replicated `gate-<gen>-<ts>.db` snapshots,
  keep 100, pruned by generation. Replicate this directory between
  nodes so any node can boot the gate from it.

Unset `NEKO_SUDO_STATE` for the legacy single-file layout.

### 3. Enroll your passkey

```
docker exec -it $(docker ps -qf name=neko-sudo_gate) python -m gate.enroll enroll --ttl 600
```

Open your gate URL, paste the single-use code under "Enroll a passkey", then
sign in with the new passkey and switch **Notifications** on. The same tool
lists and revokes passkeys (`list`, `revoke <id-prefix>`).

### 4. Add a host

With Ansible:

```
ansible-playbook -i <host>, deploy/neko-sudo-host.yml \
    -e neko_sudo_agent_pubkey="$(cat agent.pub)" \
    -e neko_sudo_agent=agent
```

The playbook creates the agent account, deploys its public key, installs the
wrapper and a visudo-validated sudoers file via `deploy/install.sh`, mints the
host token into the root-only config (first run only), and prints a
`<host> <sha256>` line.

Without Ansible: copy `hostside/` and `deploy/` to the host and run
`sh deploy/install.sh <agent-account>` as root. Then mint a token with
`openssl rand -hex 32`, put it in `/usr/local/etc/neko-sudo.conf`, and compute
the gate line with `printf '%s' "$TOKEN" | sha256sum`. Use `printf`, not
`echo`: a trailing newline changes the hash.

Either way, append the line to the gate's `tokens.conf` and restart the gate.
The file is read at boot only:

```
docker service update --force neko-sudo_gate
```

### 5. Use it

```
agent@host$ sudo /usr/local/lib/neko-sudo/run -- apt update
neko-sudo: awaiting approval (expires in 299s)
```

Approve the card on your phone, and the command runs as root with its output
returned to the agent. A shell alias can shorten the wrapper path.

Host config (`/usr/local/etc/neko-sudo.conf`, root-owned, `0600`):

```ini
[gate]
url   = https://sudo.example.com
token = <per-host token>
host  = web01
user  = agent
```

`host` must match the name in the gate's `tokens.conf` line.

## Configuration

All gate settings are environment variables. Paths default under `/data`
(the volume).

| Variable | Default | Purpose |
|---|---|---|
| `NEKO_SUDO_ORIGIN` | *(required)* | Public `https://` origin of the console. The gate refuses to boot without it. |
| `NEKO_SUDO_RP_ID` | origin's host | WebAuthn relying-party ID. |
| `NEKO_SUDO_APPROVAL_TTL_S` | `300` | Approval window in seconds. Invalid values fail the boot. |
| `NEKO_SUDO_PUSH_SUBJECT` | `mailto:admin@example.com` | VAPID contact. Set your own. |
| `NEKO_SUDO_DB` | `/data/gate.sqlite3` | Request store. |
| `NEKO_SUDO_PASSKEYS` | `/data/console-passkeys.json` | Passkey store. |
| `NEKO_SUDO_SESSIONS` | `/data/sessions.json` | Console sessions (hashed IDs). |
| `NEKO_SUDO_TOKENS_FILE` | `/data/tokens.conf` | `host sha256hex` lines. |
| `NEKO_SUDO_VAPID` | `/data/vapid.json` | VAPID keypair (generated on first boot). |
| `NEKO_SUDO_PUSH_SUBSCRIPTIONS` | `/data/push-subscriptions.json` | Browser push subscriptions. |
| `NEKO_SUDO_PUSH_LEDGER` | `/data/push-ledger.jsonl` | One line per push attempt. |

A missing tokens file boots console-only and logs that no host can create
requests; a malformed line fails the boot. Push is a convenience, never a
dependency: if VAPID setup fails, the gate boots without notifications.

## Operations

- **Redeploy a new image:** on a Swarm manager, run
  `docker service update --force --image registry.example.com/neko-sudo/gate:latest neko-sudo_gate`.
  Passing `--image` makes Swarm resolve the tag to its current digest; a
  bare `--force` only restarts the tasks and, depending on your Docker
  version, may keep the digest pinned when the service was created. You
  can route this through the gate itself: the wrapper execs the approved
  command and never contacts the gate afterwards, so restarting the gate
  mid-flight is safe.
- **Restart only** (for example after editing `tokens.conf`):
  `docker service update --force neko-sudo_gate`.
- **Change the approval window:** set `NEKO_SUDO_APPROVAL_TTL_S` on the
  service and restart. Every wrapper learns the window from the create
  response.
- **Rotate the VAPID key:** switch Notifications off and back on in the
  console. Re-enabling mints a new keypair and drops every stored
  subscription (they are bound to the old key). Any other browser
  re-subscribes on its next console visit, because the console compares its
  subscription's key with the gate's current one.
- **Diagnose a missing notification:** every push attempt leaves one line in
  the push ledger: request, host, push-service host + short endpoint tag
  (never the endpoint URL), TTL, ok/status/gone/error, send time. A request
  that found no subscription leaves `error: no_subscriptions`. `ok: true` with
  status 201 means the push service accepted it and the phone or browser held
  it; anything else is on the gate side. The ledger rotates once at 1 MB.
- **Sessions** expire after 12 h idle or 7 days absolute.

## Development

```
pip install -r requirements.txt
pytest -q
```

The suite includes end-to-end tests over real HTTP against the gate app,
WebAuthn known-answer vectors, and a POSIX-only file-mode test that is skipped
on Windows.

## Known limitations

- Approval binds argv, not the contents of scripts it names (see Hosts).
- Single replica with node-local storage; no HA.
- The per-host root-route audit is manual.
- There is no built-in tooling for rotating host tokens yet: mint a new
  token, update both sides and restart the gate.
- Push delivery depends on the owner's browser and OS (background
  restrictions can delay or hold notifications). The console polls every
  5 s, so an open console never misses a card.

## License

Copyright 2026 elixx

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
Unless required by applicable law or agreed to in writing, the software is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.
