# Imports
import subprocess

# Third-party imports
import pytest

# Local imports
from joybox import secretstore


###########################################################
# Secrets kept out of the configuration
#
# The point of a reference is that the file on disk is worth nothing to
# whoever reads it. So what has to hold is that a reference is recognised, a
# secret is fetched only when the field is actually used, and the secret
# itself never reaches a log, the file, or anything that keeps it.
###########################################################

REFERENCE = "op://Private/JoyBox/locker_passphrase"
RESOLVED_SECRET = "correct-horse-battery-staple"


@pytest.fixture(autouse = True)
def forget_secrets():
    secretstore.clear_resolved_secrets()
    yield
    secretstore.clear_resolved_secrets()


class FakeResult:
    def __init__(self, returncode = 0, stdout = "", stderr = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@pytest.fixture
def store(monkeypatch):
    # A workstation with the tool, recording what it was asked for
    calls = []

    def run(cmd, **kwargs):
        calls.append(list(cmd))
        return FakeResult(stdout = RESOLVED_SECRET)

    monkeypatch.setattr(secretstore, "get_secret_tool", lambda: "/usr/bin/op")
    monkeypatch.setattr(secretstore.subprocess, "run", run)
    return calls


@pytest.fixture
def recorded_logs(monkeypatch):
    lines = []
    for name in ["log_error", "log_info", "log_warning"]:
        monkeypatch.setattr(
            secretstore.logger, name, lambda message, *a, **k: lines.append(str(message)))
    return lines


###########################################################
# Recognising a reference
###########################################################

@pytest.mark.parametrize("value", [
    REFERENCE,
    "op://Private/Item/field",
    "  op://Private/Item/field  ",
])
def test_a_reference_is_recognised(value):
    assert secretstore.is_secret_reference(value) is True


@pytest.mark.parametrize("value", [
    "hunter2", "", None, 42, True, "/home/user/key.age", "https://example.com",
])
def test_anything_else_is_left_alone(value):
    assert secretstore.is_secret_reference(value) is False


def test_an_ordinary_value_is_returned_untouched(store):
    assert secretstore.resolve_value("hunter2") == "hunter2"
    assert store == []


###########################################################
# Resolving
###########################################################

def test_a_reference_resolves_to_the_secret(store):
    assert secretstore.resolve_value(REFERENCE) == RESOLVED_SECRET


def test_the_secret_is_asked_for_by_reference(store):
    secretstore.resolve_value(REFERENCE)

    assert REFERENCE in store[0]
    assert "read" in store[0]


def test_a_secret_carries_no_trailing_newline(store):
    # A passphrase with a newline on the end is a different passphrase, and
    # the failure shows up as an archive that will not open.
    secretstore.resolve_value(REFERENCE)

    assert "--no-newline" in store[0]


@pytest.mark.parametrize("reference", [
    "op://Private/JoyBox/locker_passphrase",
    "op://Private/JoyBox/Lockers/hetzner_token",
    "op://Shared Vault/JoyBox Secrets/api key",
])
def test_a_reference_is_passed_on_exactly_as_written(store, reference):
    # A field inside a named section carries the section, and vaults and items
    # may be named with spaces. None of that is this module's business to
    # parse, so it goes to the tool unchanged.
    secretstore.resolve_secret_reference(reference)

    assert store[0][-1] == reference


def test_a_secret_is_asked_for_once(store):
    # Unlocking prompts, so a field read in a loop must not prompt each time.
    for _ in range(5):
        secretstore.resolve_value(REFERENCE)

    assert len(store) == 1


def test_forgetting_makes_it_ask_again(store):
    secretstore.resolve_value(REFERENCE)
    secretstore.clear_resolved_secrets()
    secretstore.resolve_value(REFERENCE)

    assert len(store) == 2


def test_two_references_are_kept_apart(store):
    other = "op://Private/JoyBox/general_passphrase"

    secretstore.resolve_value(REFERENCE)
    secretstore.resolve_value(other)

    assert len(store) == 2


###########################################################
# When it cannot be resolved
#
# Every one of these has to end as nothing rather than as the reference
# itself, which would otherwise be handed to rclone as a passphrase and
# encrypt an archive to a string starting "op://".
###########################################################

def test_a_workstation_without_the_tool_gets_nothing(monkeypatch, recorded_logs):
    monkeypatch.setattr(secretstore, "get_secret_tool", lambda: None)

    assert secretstore.resolve_value(REFERENCE) is None


def test_a_refused_read_gets_nothing(monkeypatch, recorded_logs):
    monkeypatch.setattr(secretstore, "get_secret_tool", lambda: "/usr/bin/op")
    monkeypatch.setattr(
        secretstore.subprocess, "run",
        lambda cmd, **kwargs: FakeResult(returncode = 1, stderr = "item not found"))

    assert secretstore.resolve_secret_reference(REFERENCE) is None


def test_a_vault_that_is_never_unlocked_gets_nothing(monkeypatch, recorded_logs):
    def timeout(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 1)

    monkeypatch.setattr(secretstore, "get_secret_tool", lambda: "/usr/bin/op")
    monkeypatch.setattr(secretstore.subprocess, "run", timeout)

    assert secretstore.resolve_secret_reference(REFERENCE) is None


def test_an_empty_field_gets_nothing(monkeypatch, recorded_logs):
    monkeypatch.setattr(secretstore, "get_secret_tool", lambda: "/usr/bin/op")
    monkeypatch.setattr(
        secretstore.subprocess, "run", lambda cmd, **kwargs: FakeResult(stdout = ""))

    assert secretstore.resolve_secret_reference(REFERENCE) is None


def test_a_failure_is_not_cached(monkeypatch, recorded_logs):
    # The vault may simply have been locked; asking again after unlocking it
    # should work without restarting whatever is running.
    outcomes = [FakeResult(returncode = 1), FakeResult(stdout = RESOLVED_SECRET)]
    monkeypatch.setattr(secretstore, "get_secret_tool", lambda: "/usr/bin/op")
    monkeypatch.setattr(
        secretstore.subprocess, "run", lambda cmd, **kwargs: outcomes.pop(0))

    assert secretstore.resolve_secret_reference(REFERENCE) is None
    assert secretstore.resolve_secret_reference(REFERENCE) == RESOLVED_SECRET


###########################################################
# What gets said out loud
###########################################################

def test_resolving_never_logs_the_secret(store, recorded_logs):
    secretstore.resolve_secret_reference(REFERENCE, verbose = True)

    assert RESOLVED_SECRET not in " ".join(recorded_logs)


def test_a_failure_never_logs_the_secret(monkeypatch, recorded_logs):
    # The tool's own complaint is passed on, so it must not be passed on whole
    # in case it ever quotes what it read.
    monkeypatch.setattr(secretstore, "get_secret_tool", lambda: "/usr/bin/op")
    monkeypatch.setattr(
        secretstore.subprocess, "run",
        lambda cmd, **kwargs: FakeResult(returncode = 1, stderr = "failed\n%s" % RESOLVED_SECRET))

    secretstore.resolve_secret_reference(REFERENCE)

    assert RESOLVED_SECRET not in " ".join(recorded_logs)


def test_the_reference_is_named_when_it_cannot_be_read(monkeypatch, recorded_logs):
    # It names an item rather than holding a secret, so it is safe to print
    # and is the only way to tell which field is wrong.
    monkeypatch.setattr(secretstore, "get_secret_tool", lambda: None)

    secretstore.resolve_secret_reference(REFERENCE)

    assert REFERENCE in " ".join(recorded_logs)
