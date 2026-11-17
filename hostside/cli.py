"""CLI entry for the host wrapper.

Deployed as /usr/local/lib/neko-sudo/run (via a shim that calls this
module). Reads an INI config, builds the real HTTP client, and hands
off to runner.run — which fails closed on everything.
"""

import configparser
import dataclasses
import os
import sys
import time

from .client import GateClient
from .runner import run

DEFAULT_CONFIG_PATH = "/usr/local/etc/neko-sudo.conf"
# Sent on create as an optional hint; the gate owns the approval window and
# ignores it. The wrapper's own deadline comes from the gate's create
# response, never from here.
DEFAULT_TTL_S = 300
DEFAULT_POLL_INTERVAL_S = 2.0


class ConfigError(Exception):
    pass


@dataclasses.dataclass(frozen=True)
class Config:
    url: str
    token: str
    host: str
    user: str
    ttl_s: int = DEFAULT_TTL_S


def load_config(path: str) -> Config:
    parser = configparser.ConfigParser()
    if not parser.read(path, encoding="utf-8"):
        raise ConfigError(f"config file not readable: {path}")
    try:
        section = parser["gate"]
        return Config(
            url=section["url"].rstrip("/"),
            token=section["token"],
            host=section["host"],
            user=section["user"],
            ttl_s=section.getint("ttl_s", DEFAULT_TTL_S),
        )
    except KeyError as exc:
        raise ConfigError(f"config missing key: {exc.args[0]}") from exc
    except ValueError as exc:
        raise ConfigError(f"config invalid: {exc}") from exc


def build_client(config: Config) -> GateClient:
    return GateClient(config.url, token=config.token, timeout_s=10.0)


def _notice():
    """Build the stderr notice fired once the request is live on the gate.

    Deliberately carries no URL or request id — the point is for the
    calling agent to know the hold-up and its deadline, nothing else.
    """

    def announce(seconds_left) -> None:
        print(
            f"neko-sudo: awaiting approval (expires in {int(seconds_left)}s)",
            file=sys.stderr,
            flush=True,
        )

    return announce


def main(
    argv: list[str],
    *,
    config_path: str | None = None,
    client_factory=build_client,
    clock=time.time,
    sleep=time.sleep,
    exec_fn=None,
    which=None,
) -> int:
    from .runner import _posix_exec

    path = config_path or os.environ.get("NEKO_SUDO_CONFIG", DEFAULT_CONFIG_PATH)
    try:
        config = load_config(path)
    except ConfigError as exc:
        print(f"neko-sudo: {exc}", file=sys.stderr)
        return 1
    # `sudo ... run -- true`: drop one leading "--" separator (sudo habit)
    # so the gated argv is the real command. A lone "--" is left to the
    # policy layer, which fails closed on it.
    if argv and argv[0] == "--" and len(argv) > 1:
        argv = argv[1:]
    code, message = run(
        argv,
        host=config.host,
        user=config.user,
        cwd=os.getcwd(),
        client=client_factory(config),
        clock=clock,
        sleep=sleep,
        ttl_s=config.ttl_s,
        poll_interval_s=DEFAULT_POLL_INTERVAL_S,
        exec_fn=exec_fn if exec_fn is not None else _posix_exec,
        which=which,
        notice=_notice(),
    )
    if code != 0:
        print(f"neko-sudo: {message}", file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
