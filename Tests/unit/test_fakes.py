# Imports
import sys

# Third-party imports
import pytest

# Local imports
from joybox.connection import connection_local
from joybox import runoptions
from fakes import RecordingConnection


###########################################################
# Test doubles
#
# A double that answers differently from what it stands in for lets a test
# pin behaviour the real code can never show. These hold the doubles to the
# contract of the real thing.
###########################################################

@pytest.fixture
def failing_local(monkeypatch):
    connection = connection_local.ConnectionLocal(runoptions.RunFlags(verbose = False), runoptions.RunOptions())
    monkeypatch.setattr(connection, "run_blocking", lambda cmd, sudo = False: 3)
    return connection


def test_a_checked_command_that_succeeds_returns_nothing_like_the_real_one(monkeypatch):
    real = connection_local.ConnectionLocal(runoptions.RunFlags(verbose = False), runoptions.RunOptions())
    monkeypatch.setattr(real, "run_blocking", lambda cmd, sudo = False: 0)

    assert RecordingConnection().run_checked(["true"]) is None
    assert real.run_checked(["true"]) is None


def test_a_checked_command_that_fails_ends_the_program_like_the_real_one(failing_local, monkeypatch):
    fake = RecordingConnection()
    fake.return_codes["false"] = 3
    exits = []
    monkeypatch.setattr(sys, "exit", lambda code = 0: exits.append(code))

    failing_local.run_checked(["false"])
    with pytest.raises(SystemExit) as raised:
        fake.run_checked(["false"])

    assert exits == [3]
    assert raised.value.code == 3


def test_a_checked_command_that_fails_can_raise_like_the_real_one(failing_local):
    fake = RecordingConnection()
    fake.return_codes["false"] = 3

    with pytest.raises(ValueError, match = "Unable to run command"):
        failing_local.run_checked(["false"], throw_exception = True)
    with pytest.raises(ValueError, match = "Unable to run command"):
        fake.run_checked(["false"], throw_exception = True)
