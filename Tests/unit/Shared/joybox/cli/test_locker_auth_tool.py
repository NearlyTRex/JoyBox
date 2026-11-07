# Imports
import json

# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox import lockerauth, settings
from joybox.cli import locker_auth_tool


###########################################################
# Signing a locker in with OAuth
#
# The new options are only worth storing once they are known to work, and
# storing them must keep whatever else the field held, apart from a service
# account, which would otherwise win over the token.
###########################################################

SHARE = "UserData.Share"
REFERENCE = "op://Personal/JoyBox/UserData.Share/locker_gdrive_config"
CLIENT_ID = "client.apps.googleusercontent.com"
CLIENT_PHRASE = "client-phrase-value"
FOLDER_ID = "1AbCdEfGhIjKlMnOp"
TOKEN = {"access_token": "a", "refresh_token": "r"}
STORED = {"client_id": "stored-id", "client_secret": "stored-secret", "root_folder_id": "storedfolder",
          "team_drive": "keep", "service_account_credentials": {"type": "service_account"}}


@pytest.fixture
def tool(monkeypatch, tmp_path, isolated_settings):
    harness = CommandHarness(monkeypatch, locker_auth_tool)
    settings.set_value(SHARE, "locker_gdrive_type", "Drive")
    settings.set_value(SHARE, "locker_gdrive_name", "Gdrive")
    settings.set_value(SHARE, "locker_gdrive_remote_path", "/")
    settings.set_value(SHARE, "locker_gdrive_config", REFERENCE)
    harness.stored_value = json.dumps(STORED)
    harness.resolved = []
    harness.signed_in = []
    harness.listed_with = []
    harness.saved = []
    harness.token = dict(TOKEN)
    harness.entries = 3
    harness.store_result = True

    def resolve(reference, verbose = False):
        harness.resolved.append(reference)
        return harness.stored_value

    def authorize(**kwargs):
        harness.signed_in.append(kwargs)
        return harness.token

    def count(**kwargs):
        harness.listed_with.append(json.loads(settings.get_value(SHARE, "locker_gdrive_config")))
        return harness.entries

    def store(reference, value, verbose = False):
        harness.saved.append((reference, json.loads(value)))
        return harness.store_result

    monkeypatch.setattr(lockerauth.secretstore, "resolve_secret_reference", resolve)
    monkeypatch.setattr(lockerauth.secretstore, "store_secret_reference", store)
    monkeypatch.setattr(lockerauth.sync, "authorize_remote", authorize)
    monkeypatch.setattr(lockerauth.sync, "count_remote_entries", count)
    harness.client_file = write_client(tmp_path, {"installed": {"client_id": CLIENT_ID, "client_secret": CLIENT_PHRASE}})
    return harness


def write_client(tmp_path, data, name = "client_secret.json"):
    path = tmp_path / name
    path.write_text(json.dumps(data))
    return str(path)


def new_client_args(tool, *extra):
    return ["--client_file", tool.client_file, "--folder_id", FOLDER_ID, *extra]


###########################################################
# A sign-in that works
###########################################################

def test_a_new_client_and_folder_are_signed_in_and_stored(tool):
    tool.run(*new_client_args(tool))

    assert tool.resolved == []
    assert tool.saved == [(REFERENCE, {
        "client_id": CLIENT_ID, "client_secret": CLIENT_PHRASE, "token": TOKEN, "root_folder_id": FOLDER_ID})]
    assert tool.signed_in[0]["client_id"] == CLIENT_ID
    assert tool.signed_in[0]["open_browser"] is True


def test_the_options_are_checked_before_they_are_stored(tool):
    tool.run(*new_client_args(tool))

    assert tool.listed_with == [tool.saved[0][1]]


def test_signing_in_again_reuses_the_stored_client_and_folder(tool):
    tool.run("--no_browser")
    stored = tool.saved[0][1]

    assert tool.resolved == [REFERENCE]
    assert tool.signed_in[0]["client_id"] == "stored-id"
    assert tool.signed_in[0]["open_browser"] is False
    assert stored["root_folder_id"] == "storedfolder"
    assert stored["team_drive"] == "keep"
    assert stored["token"] == TOKEN
    assert "service_account_credentials" not in stored


def test_a_folder_url_is_accepted(tool):
    tool.run("--folder_id", "https://drive.google.com/drive/folders/%s?usp=sharing" % FOLDER_ID)

    assert tool.saved[0][1]["root_folder_id"] == FOLDER_ID


def test_the_preview_names_what_is_signed_in_and_where_it_goes(tool):
    tool.run(*new_client_args(tool))

    assert tool.previews == [("Authorize Gdrive", [
        "Remote: Gdrive:/", "Client: %s" % CLIENT_ID, "Folder: %s" % FOLDER_ID, "Store: %s" % REFERENCE])]


def test_the_preview_can_be_skipped(tool):
    tool.run(*new_client_args(tool, "--no-preview"))

    assert tool.previews == []
    assert len(tool.saved) == 1


def test_a_missing_remote_path_is_the_root(tool):
    settings.set_value(SHARE, "locker_gdrive_remote_path", "")
    tool.run(*new_client_args(tool))

    assert tool.previews[0][1][0] == "Remote: Gdrive:/"


###########################################################
# Stopping before anything is stored
###########################################################

def test_a_cancelled_preview_signs_nothing_in(tool):
    tool.confirm = False
    tool.run(*new_client_args(tool))

    assert tool.signed_in == []
    assert tool.saved == []


def test_a_pretend_run_signs_nothing_in(tool, monkeypatch):
    pretended = []
    monkeypatch.setattr(lockerauth.sync, "authorize_remote",
                        lambda *args, **kwargs: pretended.append(kwargs))
    tool.run(*new_client_args(tool, "-p"))

    assert pretended == [{"open_browser": True, "pretend_run": True}]
    assert tool.saved == []


@pytest.mark.parametrize("change, expected", [
    ("token", None),
    ("entries", None),
    ("store_result", False),
])
def test_a_failed_step_is_an_error(tool, change, expected):
    setattr(tool, change, expected)

    assert tool.exit_code(*new_client_args(tool)) == 1
    assert len(tool.saved) == (1 if change == "store_result" else 0)


@pytest.mark.parametrize("setting, value", [
    ("locker_gdrive_type", ""),
    ("locker_gdrive_name", ""),
    ("locker_gdrive_type", "SFTP"),
    ("locker_gdrive_config", '{"client_id": "inline"}'),
    ("locker_gdrive_config", ""),
])
def test_a_locker_that_cannot_be_signed_in_is_refused(tool, setting, value):
    settings.set_value(SHARE, setting, value)

    assert tool.exit_code(*new_client_args(tool)) != 0
    assert tool.signed_in == []


@pytest.mark.parametrize("stored, args", [
    ("", []),
    ("[1, 2]", []),
    (json.dumps({"root_folder_id": "f"}), []),
    (json.dumps({"client_id": "i", "client_secret": "s"}), []),
])
def test_without_a_stored_client_or_folder_one_must_be_given(tool, stored, args):
    tool.stored_value = stored

    assert tool.exit_code(*args) != 0
    assert tool.signed_in == []


def test_a_folder_that_is_not_an_id_is_refused(tool):
    assert tool.exit_code("--client_file", tool.client_file, "--folder_id", "not a folder!") != 0
    assert tool.signed_in == []


@pytest.mark.parametrize("data", [
    {"web": {"client_id": CLIENT_ID, "client_secret": CLIENT_PHRASE}},
    {"installed": {"client_id": CLIENT_ID}},
    [CLIENT_ID],
    None,
])
def test_a_client_file_without_a_desktop_client_is_refused(tool, tmp_path, data):
    path = write_client(tmp_path, data, name = "other.json") if data is not None else str(tmp_path / "absent.json")

    assert tool.exit_code("--client_file", path, "--folder_id", FOLDER_ID) == 1
    assert tool.signed_in == []


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, locker_auth_tool)
