"""Session horizon policy.

A console session gates only card *visibility* and deny; approval always
requires a fresh user-verified passkey ceremony regardless of session age.
So the idle window can be generous without granting approval authority:
12h idle survives a workday without mid-flow re-logins, and the 7d absolute
cap still forces a weekly passkey re-login.
"""
from gate import sessions


def test_default_session_horizons():
    assert sessions.DEFAULT_IDLE_S == 12 * 60 * 60
    assert sessions.DEFAULT_ABSOLUTE_S == 7 * 24 * 60 * 60
