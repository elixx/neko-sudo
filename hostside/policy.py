"""Outright refusals, decided locally before the gate is ever contacted.

The wrapper never runs an interactive or login shell, no matter what the
owner would approve: those forms make "exact argv" meaningless. Anything
else goes to the gate and is approved as the exact argv on the card.
"""

from __future__ import annotations

import os

SHELLS = {
    "bash",
    "sh",
    "dash",
    "zsh",
    "ksh",
    "mksh",
    "fish",
    "csh",
    "tcsh",
}

ALWAYS_REFUSE = {"su", "login", "sudoedit", "visudo"}

INTERACTIVE_FLAGS = {"-i", "-l", "-s", "--login", "--interactive", "-il", "-li"}


def check(argv: list[str]) -> str | None:
    """Return a refusal reason, or None if the argv may go to the gate."""
    if not argv:
        return "empty command"
    base = os.path.basename(argv[0])
    if base in ALWAYS_REFUSE:
        return f"{base} is refused outright"
    if base in SHELLS:
        rest = argv[1:]
        if not rest:
            return f"interactive shell ({base})"
        if any(arg in INTERACTIVE_FLAGS for arg in rest):
            return f"interactive/login shell flag on {base}"
    return None
