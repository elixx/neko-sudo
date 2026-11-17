"""Deploy assets: shim, installer, config template — pinned by test."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SHIM = REPO / "hostside" / "run"
INSTALL = REPO / "deploy" / "install.sh"
TEMPLATE = REPO / "deploy" / "neko-sudo.conf.template"


def test_shim_execs_cli_module_with_local_pythonpath():
    text = SHIM.read_text(encoding="utf-8")
    assert text.startswith("#!/bin/sh")
    # exact argv passthrough, no shell interpolation of arguments
    assert 'exec python3 -m hostside.cli "$@"' in text
    # resolves its own directory so the package ships beside the shim
    assert "dirname" in text and "PYTHONPATH" in text


def test_build_multiarch_script_pins_platforms_and_registry():
    text = (REPO / "deploy" / "build-multiarch.sh").read_text(encoding="utf-8")
    assert text.startswith("#!/bin/sh")
    assert "--platform linux/amd64,linux/arm64" in text    # both swarm arches
    assert "--push" in text                                 # manifest list to registry
    assert "NEKO_SUDO_IMAGE" in text                        # image path is configurable
    assert "registry.example.com/neko-sudo/gate" in text    # …with a placeholder default
    assert "binfmt --install arm64" in text                 # one-time QEMU hint
    assert "not a neko-sudo checkout" in text               # guard: run from a checkout
    # Preflight: a missing arm64 handler must fail the build BEFORE the
    # slow steps die with "exec format error" at RUN.
    assert "binfmt_misc/qemu-aarch64" in text               # kernel handler probe
    assert "exec format error" in text                      # names the failure it prevents
    # …but /proc visibility is per mount namespace: in CI the binfmt mount
    # lives in the dind daemon's namespace, not the job container's, so the
    # /proc probe alone would refuse a perfectly-emulated host. The fallback
    # must probe the real build path: run a tiny arm64 container.
    assert "--platform linux/arm64 alpine" in text          # namespace-proof probe
    # BuildKit >=0.32 pushes attestation manifests (OCI artifacts whose
    # subject names the image manifest) concurrently with that manifest;
    # the GitLab registry enforces referential integrity and rejects the
    # referrer with "blob unknown to registry" whenever the subject is
    # new — an intermittent push failure. No attestations, no race.
    assert "--provenance=false" in text and "--sbom=false" in text


def test_dockerignore_is_allowlist_of_gate_only():
    """Context ships ONLY Dockerfile + gate/ — data files (tokens.conf,
    sqlite, passkey store) next to a mixed checkout can never leak into
    an image, and the context stays minimal."""
    text = (REPO / ".dockerignore").read_text(encoding="utf-8")
    assert text.splitlines()[0] == "*"                       # deny everything…
    assert "!Dockerfile" in text                             # …then allowlist
    assert "!gate" in text and "!gate/**" in text
    assert "tests" not in text.replace("!gate", "")


def test_compose_lets_task_float_via_routing_mesh():
    """With a data dir shared or replicated between nodes, the single
    replica may float. Publishing with mode:ingress makes EVERY node
    listen on 18443 and mesh-forward to the task's node — with mode:host
    the listener lives only on the task's node and the proxy 502s whenever
    the task drifts. No placement constraints by default (the compose file
    explains when to add one)."""
    import yaml

    spec = yaml.safe_load((REPO / "docker-compose.yml").read_text(encoding="utf-8"))
    gate = spec["services"]["gate"]
    deploy = gate["deploy"]
    assert deploy["replicas"] == 1
    assert "placement" not in deploy          # task floats freely
    ports = gate["ports"][0]
    assert ports["mode"] == "ingress"
    assert ports["published"] == 18443
    assert "/srv/neko-sudo:/data" in gate["volumes"]


def test_installer_is_fail_closed_and_idempotent():
    text = INSTALL.read_text(encoding="utf-8")
    assert text.startswith("#!/bin/sh")
    assert "$(id -u)" in text and "run as root" in text          # root-only
    assert 'AGENT=${1:-agent}' in text                            # account arg
    assert "id \"$AGENT\"" in text                                # account must exist
    assert "install -o root -g root -m 0755" in text              # root-owned shim
    assert "NOPASSWD: $LIB/run" in text                           # gate only the wrapper
    assert "visudo -cf" in text                                   # validate before activate
    assert "chmod 0440" in text                                   # sudoers perms
    assert "KEEP existing" in text                                # never clobber config/sudoers
    assert "does not grant" in text                               # warn on wrong-account sudoers


def test_config_template_pins_gate_and_placeholder_host():
    text = TEMPLATE.read_text(encoding="utf-8")
    assert "url = https://sudo.example.com" in text
    assert "@HOST@" in text
    assert "token = " in text


def test_config_template_carries_no_ttl():
    """The approval window is owned by the gate (NEKO_SUDO_APPROVAL_TTL_S,
    default 300s). Host configs carry no ttl_s, so per-host values cannot
    drift from the central policy."""
    text = TEMPLATE.read_text(encoding="utf-8")
    assert "ttl_s" not in text


def test_config_template_parametrizes_agent_user():
    """The config's `user` is payload-bound (host, user, argv, cwd digest):
    it must be substituted per-agent, not hardcoded to the literal name
    from install.sh's default argument."""
    text = TEMPLATE.read_text(encoding="utf-8")
    assert "@USER@" in text
    assert "user = agent" not in text


def test_installer_substitutes_agent_user_into_config():
    text = INSTALL.read_text(encoding="utf-8")
    assert "s|@USER@|" in text


def test_ansible_playbook_bootstraps_a_new_host():
    """deploy/neko-sudo-host.yml automates the full new-host procedure:
    agent account + home + authorized key, wrapper/sudoers via install.sh
    (reused, never forked), first-run-only token write, and the sha256
    line for the gate's tokens.conf. The raw token is never echoed."""
    import yaml

    playbook = REPO / "deploy" / "neko-sudo-host.yml"
    text = playbook.read_text(encoding="utf-8")
    spec = yaml.safe_load(text)                       # valid YAML, jinja included

    assert "install.sh" in text                       # drive the tested installer
    assert "become: true" in text
    assert "ansible.builtin.user" in text             # create agent account + home
    assert "authorized_key" in text                   # deploy the public key
    assert "python3 --version" in text                # prerequisite surfaced early
    assert "neko_sudo_agent" in text                  # agent name is a variable
    assert "REPLACE_WITH_HOST_TOKEN" in text          # guard before writing token
    assert "no_log: true" in text                     # token mint/write not echoed
    assert "hash('sha256')" in text                   # gate line is the sha256
    assert "ttl_s" not in text                        # TTL is gate-owned, not a host knob
    assert "docker service update --force neko-sudo_gate" in text  # bounce reminder


def test_cli_module_fails_closed_without_config(tmp_path):
    env = dict(os.environ, PYTHONPATH=str(REPO))
    env.pop("NEKO_SUDO_CONFIG", None)
    proc = subprocess.run(
        [sys.executable, "-m", "hostside.cli", "true"],
        env=env, capture_output=True, text=True, cwd=str(tmp_path),
    )
    assert proc.returncode == 1
    assert "config file not readable" in proc.stderr


def test_gitlab_ci_builds_gate_on_main_via_multiarch_script():
    """Pushes to main (a completed MR lands as a push) build+push the
    registry image. The job reuses deploy/build-multiarch.sh so CI and a
    manual build cannot drift; tests gate the build on MRs and on main."""
    text = (REPO / ".gitlab-ci.yml").read_text(encoding="utf-8")
    assert 'CI_COMMIT_BRANCH == "main"' in text       # build after commit/MR to main
    assert "build-multiarch.sh" in text               # single source of build truth
    assert "$CI_REGISTRY_IMAGE" in text               # this project's own registry
    assert "CI_REGISTRY_USER" in text and "CI_DEPLOY_USER" in text  # deploy- or job-token auth
    assert 'DOCKER_HOST: tcp://docker:2375' in text   # plain-TCP dind (no cert volumes)
    assert 'DOCKER_TLS_CERTDIR: ""' in text           # …or dind goes TLS on 2376
    assert "tonistiigi/binfmt" in text                # arm64 emulation inside CI
    assert "pytest" in text                           # tests run in-pipeline
    assert "merge_request_event" in text              # …on MRs and main both


def test_dockerfile_ships_web_push_stack():
    """Push notifications need pywebpush (+py_vapid: webpush.py imports
    Vapid directly) and crypto in the runtime image."""
    text = (REPO / "Dockerfile").read_text(encoding="utf-8")
    assert "pywebpush" in text and "py-vapid" in text
