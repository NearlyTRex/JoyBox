# Imports
import json
import os
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


NO_ACCOUNT = (
    "No accounts configured for use with 1Password CLI.\n"
    "\n"
    " - Turn on the 1Password desktop app integration to sign in with the accounts you've added to the app.")


def test_the_tool_is_given_no_input(monkeypatch, recorded_logs):
    # With a terminal it offers to add an account, then prompts into output
    # that is being captured, and the read hangs until it times out.
    seen = []
    monkeypatch.setattr(secretstore, "get_secret_tool", lambda: "/usr/bin/op")
    monkeypatch.setattr(
        secretstore.subprocess, "run", lambda cmd, **kwargs: seen.append(kwargs) or FakeResult(stdout = RESOLVED_SECRET))

    secretstore.resolve_secret_reference(REFERENCE)

    assert seen[0]["stdin"] is subprocess.DEVNULL


def test_no_account_is_reported_with_how_to_sign_in(monkeypatch, recorded_logs):
    monkeypatch.setattr(secretstore, "get_secret_tool", lambda: "/usr/bin/op")
    monkeypatch.setattr(
        secretstore.subprocess, "run", lambda cmd, **kwargs: FakeResult(returncode = 1, stderr = NO_ACCOUNT))

    assert secretstore.resolve_secret_reference(REFERENCE) is None

    assert any("desktop app integration" in line for line in recorded_logs)
    assert any("Docs/reference/secrets.md" in line for line in recorded_logs)


def test_no_account_is_reported_once_per_run(monkeypatch, recorded_logs):
    # Unlike a locked vault, nothing in the run can sign in, so each further
    # reference would only repeat the same complaint.
    calls = []
    monkeypatch.setattr(secretstore, "get_secret_tool", lambda: "/usr/bin/op")
    monkeypatch.setattr(
        secretstore.subprocess, "run", lambda cmd, **kwargs: calls.append(cmd) or FakeResult(returncode = 1, stderr = NO_ACCOUNT))

    assert secretstore.resolve_secret_reference(REFERENCE) is None
    assert secretstore.resolve_secret_reference("op://Private/JoyBox/general_passphrase") is None

    assert len(calls) == 1


def test_forgetting_asks_again_after_signing_in(monkeypatch, recorded_logs):
    outcomes = [FakeResult(returncode = 1, stderr = NO_ACCOUNT), FakeResult(stdout = RESOLVED_SECRET)]
    monkeypatch.setattr(secretstore, "get_secret_tool", lambda: "/usr/bin/op")
    monkeypatch.setattr(
        secretstore.subprocess, "run", lambda cmd, **kwargs: outcomes.pop(0))

    assert secretstore.resolve_secret_reference(REFERENCE) is None
    secretstore.clear_resolved_secrets()

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


###########################################################
# Finding the tool
###########################################################

def make_executable(path, mode = 0o755):
    path.write_text("#!/bin/sh\n")
    path.chmod(mode)
    return str(path)


def test_a_known_install_location_wins_over_the_path(monkeypatch, tmp_path):
    known = make_executable(tmp_path / "known-op")
    on_path = tmp_path / "bin"
    on_path.mkdir()
    make_executable(on_path / secretstore.secret_tool)
    monkeypatch.setattr(secretstore, "secret_tool_paths", [known])
    monkeypatch.setenv("PATH", str(on_path))

    assert secretstore.get_secret_tool() == known


def test_the_tool_is_found_on_the_path(monkeypatch, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    on_path = tmp_path / "bin"
    on_path.mkdir()
    found = make_executable(on_path / secretstore.secret_tool)
    monkeypatch.setattr(secretstore, "secret_tool_paths", [str(tmp_path / "absent")])
    monkeypatch.setenv("PATH", os.pathsep.join([str(empty), str(on_path)]))

    assert secretstore.get_secret_tool() == found


def test_a_non_executable_tool_is_not_found(monkeypatch, tmp_path):
    make_executable(tmp_path / secretstore.secret_tool, mode = 0o644)
    monkeypatch.setattr(secretstore, "secret_tool_paths", [str(tmp_path / secretstore.secret_tool)])
    monkeypatch.setenv("PATH", str(tmp_path))

    assert secretstore.get_secret_tool() is None


###########################################################
# Storing
#
# A tool that signs in somewhere writes what it got back into the field its
# setting references. The item is read and written back whole, so every
# other field has to come through unchanged, and the value has to travel on
# standard input, never the command line, where other processes can read it.
###########################################################

STORED_REFERENCE = "op://Personal/JoyBox/UserData.Share/locker_gdrive_config"
STORED_VALUE = "fresh-options"


def make_item(fields = None, sections = None):
    item = {"id": "itemid", "vault": {"id": "vaultid"}, "fields": fields or []}
    if sections is not None:
        item["sections"] = sections
    return item


class FakeVault:

    # Answers item get with its item and records each item edit
    def __init__(self, monkeypatch, item, get_result = None, edit_result = None):
        self.item = item
        self.get_result = get_result
        self.edit_result = edit_result
        self.calls = []
        self.edited = None
        monkeypatch.setattr(secretstore, "get_secret_tool", lambda: "/usr/bin/op")
        monkeypatch.setattr(secretstore.subprocess, "run", self.run)

    def run(self, cmd, **kwargs):
        self.calls.append((list(cmd), kwargs))
        if cmd[2] == "get":
            return self.get_result or FakeResult(stdout = json.dumps(self.item))
        self.edited = json.loads(kwargs["input"])
        return self.edit_result or FakeResult()


@pytest.mark.parametrize("reference, expected", [
    (STORED_REFERENCE, ("Personal", "JoyBox", "UserData.Share", "locker_gdrive_config")),
    ("op://Personal/JoyBox/field", ("Personal", "JoyBox", None, "field")),
    (" op://Personal/JoyBox/field ", ("Personal", "JoyBox", None, "field")),
])
def test_a_reference_splits_into_its_parts(reference, expected):
    assert secretstore.parse_secret_reference(reference) == expected


@pytest.mark.parametrize("reference", [
    "plain", None, "op://Personal/JoyBox", "op://Personal//field", "op://a/b/c/d/e",
])
def test_anything_but_a_reference_to_one_field_does_not_split(reference):
    assert secretstore.parse_secret_reference(reference) is None


def test_an_existing_field_gets_the_value_and_everything_else_is_kept(monkeypatch, recorded_logs):
    other = {"id": "pw", "label": "password", "type": "CONCEALED", "value": "keep"}
    target = {"id": "f1", "label": "locker_gdrive_config", "type": "CONCEALED",
              "value": "old", "section": {"id": "s1", "label": "UserData.Share"}}
    vault = FakeVault(monkeypatch, make_item([other, target], [{"id": "s1", "label": "UserData.Share"}]))

    assert secretstore.store_secret_reference(STORED_REFERENCE, STORED_VALUE) is True
    assert vault.edited["fields"][0] == other
    assert vault.edited["fields"][1]["value"] == STORED_VALUE
    assert vault.edited["fields"][1]["id"] == "f1"


def test_the_item_is_read_with_its_values(monkeypatch, recorded_logs):
    # Read concealed, every secret on the item would be written back blank
    vault = FakeVault(monkeypatch, make_item())
    secretstore.store_secret_reference(STORED_REFERENCE, STORED_VALUE)

    assert "--reveal" in vault.calls[0][0]
    assert vault.calls[0][1]["stdin"] is subprocess.DEVNULL


def test_the_value_travels_on_standard_input(monkeypatch, recorded_logs):
    vault = FakeVault(monkeypatch, make_item())
    secretstore.store_secret_reference(STORED_REFERENCE, STORED_VALUE)
    edit_cmd, edit_kwargs = vault.calls[1]

    assert edit_cmd == ["/usr/bin/op", "item", "edit", "itemid", "--vault", "vaultid"]
    assert STORED_VALUE in edit_kwargs["input"]
    assert not any(STORED_VALUE in part for part in edit_cmd)


def test_a_missing_field_is_added_concealed_in_a_new_section(monkeypatch, recorded_logs):
    vault = FakeVault(monkeypatch, {"id": "itemid"})
    secretstore.store_secret_reference(STORED_REFERENCE, STORED_VALUE)
    field = vault.edited["fields"][0]
    section = vault.edited["sections"][0]

    assert field["type"] == "CONCEALED"
    assert field["label"] == "locker_gdrive_config"
    assert section["label"] == "UserData.Share"
    assert field["section"] == {"id": section["id"]}
    assert vault.calls[1][0][-1] == "Personal"


def test_a_missing_field_joins_the_section_already_there(monkeypatch, recorded_logs):
    vault = FakeVault(monkeypatch, make_item(sections = [{"id": "s1", "label": "UserData.Share"}]))
    secretstore.store_secret_reference(STORED_REFERENCE, STORED_VALUE)

    assert vault.edited["fields"][0]["section"] == {"id": "s1"}
    assert len(vault.edited["sections"]) == 1


def test_a_reference_without_a_section_adds_a_field_outside_any(monkeypatch, recorded_logs):
    vault = FakeVault(monkeypatch, make_item())
    secretstore.store_secret_reference("op://Personal/JoyBox/field", STORED_VALUE)

    assert "section" not in vault.edited["fields"][0]
    assert "sections" not in vault.edited


@pytest.mark.parametrize("field, matches", [
    ({"id": "f", "label": "other"}, False),
    ({"id": "locker_gdrive_config", "label": "renamed", "section": {"id": "UserData.Share"}}, True),
    ({"id": "f", "label": "locker_gdrive_config", "section": {"id": "s", "label": "Elsewhere"}}, False),
    ({"id": "f", "label": "locker_gdrive_config"}, False),
])
def test_a_field_matches_by_label_or_id_within_its_section(field, matches):
    assert secretstore.is_referenced_field(field, "locker_gdrive_config", "UserData.Share") is matches


def test_a_reference_naming_two_fields_stores_nothing(monkeypatch, recorded_logs):
    twins = [{"id": "a", "label": "field"}, {"id": "b", "label": "field"}]
    vault = FakeVault(monkeypatch, make_item(twins))

    assert secretstore.store_secret_reference("op://Personal/JoyBox/field", STORED_VALUE) is False
    assert vault.edited is None


def test_storing_forgets_the_old_value(monkeypatch, recorded_logs):
    outcomes = [FakeResult(stdout = "old")]
    monkeypatch.setattr(secretstore, "get_secret_tool", lambda: "/usr/bin/op")
    monkeypatch.setattr(secretstore.subprocess, "run", lambda cmd, **kwargs: outcomes.pop(0))
    secretstore.resolve_secret_reference(STORED_REFERENCE)
    FakeVault(monkeypatch, make_item())

    assert secretstore.store_secret_reference(" %s " % STORED_REFERENCE, STORED_VALUE, verbose = True) is True
    assert secretstore._resolved == {}
    assert "Storing" in recorded_logs[-1]


def test_a_value_is_never_logged_when_storing(monkeypatch, recorded_logs):
    FakeVault(monkeypatch, make_item(), edit_result = FakeResult(returncode = 1, stderr = "denied"))
    secretstore.store_secret_reference(STORED_REFERENCE, STORED_VALUE, verbose = True)

    assert recorded_logs
    assert not any(STORED_VALUE in line for line in recorded_logs)


def test_storing_to_something_not_a_field_reference_is_refused(monkeypatch, recorded_logs):
    monkeypatch.setattr(secretstore.subprocess, "run", lambda *a, **k: pytest.fail("ran the tool"))

    assert secretstore.store_secret_reference("op://Personal/JoyBox", STORED_VALUE) is False


def test_storing_without_the_tool_is_refused(monkeypatch, recorded_logs):
    monkeypatch.setattr(secretstore, "get_secret_tool", lambda: None)

    assert secretstore.store_secret_reference(STORED_REFERENCE, STORED_VALUE) is False


@pytest.mark.parametrize("get_result, edit_result", [
    (FakeResult(returncode = 1, stderr = "item not found\nmore"), None),
    (FakeResult(returncode = 1), None),
    (FakeResult(stdout = "not json"), None),
    (FakeResult(stdout = "[1]"), None),
    (None, FakeResult(returncode = 1, stderr = "denied")),
    (None, FakeResult(returncode = 1)),
])
def test_a_refused_read_or_write_stores_nothing(monkeypatch, recorded_logs, get_result, edit_result):
    FakeVault(monkeypatch, make_item(), get_result = get_result, edit_result = edit_result)

    assert secretstore.store_secret_reference(STORED_REFERENCE, STORED_VALUE) is False
    assert any("Unable" in line for line in recorded_logs)


@pytest.mark.parametrize("failing_call", [0, 1])
@pytest.mark.parametrize("error", [subprocess.TimeoutExpired("op", 1), OSError("gone")])
def test_a_tool_that_cannot_run_stores_nothing(monkeypatch, recorded_logs, failing_call, error):
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        if len(calls) - 1 == failing_call:
            raise error
        return FakeResult(stdout = json.dumps(make_item()))

    monkeypatch.setattr(secretstore, "get_secret_tool", lambda: "/usr/bin/op")
    monkeypatch.setattr(secretstore.subprocess, "run", run)

    assert secretstore.store_secret_reference(STORED_REFERENCE, STORED_VALUE) is False
    assert len(calls) == failing_call + 1
