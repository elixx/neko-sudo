import pytest

from hostside.policy import check


@pytest.mark.parametrize(
    "argv",
    [
        ["bash"],
        ["/bin/bash"],
        ["sh"],
        ["zsh"],
        ["dash"],
        ["bash", "-i"],
        ["bash", "-l"],
        ["bash", "-s"],
        ["bash", "--login"],
        ["/usr/bin/zsh", "-i", "-c", "id"],
        ["su"],
        ["su", "-"],
        ["su", "root"],
        ["login"],
    ],
)
def test_interactive_shell_forms_are_refused(argv):
    reason = check(argv)
    assert reason, f"{argv} must be refused"


@pytest.mark.parametrize(
    "argv",
    [
        ["apt", "update"],
        ["systemctl", "restart", "nginx"],
        ["/usr/local/sbin/backup.sh", "--daily"],
        ["bash", "/root/maintenance.sh"],  # non-interactive: exact argv on the card
        ["bash", "-c", "systemctl restart nginx"],
        ["install", "-i", "something"],  # -i as a plain argument is not a shell flag
    ],
)
def test_noninteractive_commands_pass_to_the_gate(argv):
    assert check(argv) is None


def test_empty_argv_is_refused():
    assert check([]) is not None
