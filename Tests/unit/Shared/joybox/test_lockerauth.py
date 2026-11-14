# Imports
import json

# Third-party imports
import pytest

# Local imports
from joybox import lockerauth


###########################################################
# Locker OAuth sign-in
###########################################################

SHARE = lockerauth.SHARE_SECTION
REFERENCE = "op://Personal/JoyBox/UserData.Share/locker_gdrive_config"
FOLDER = "1AbC-d_E"
CLIENT = ("client-id", "client-phrase")
REMOTE = ("Drive", "Gdrive", "/Games")
TOKEN = {"access_token": "a"}


@pytest.fixture
def drive_locker(isolated_settings):
    isolated_settings.set_value(SHARE, "locker_gdrive_type", "Drive")
    isolated_settings.set_value(SHARE, "locker_gdrive_name", "Gdrive")
    isolated_settings.set_value(SHARE, "locker_gdrive_remote_path", "/Games")
    isolated_settings.set_value(SHARE, "locker_gdrive_config", REFERENCE)
    return isolated_settings


def write_client(tmp_path, data):
    path = tmp_path / "client.json"
    path.write_text(json.dumps(data))
    return str(path)


###########################################################
# Remote and reference
###########################################################

def test_the_locker_key_is_lowercased():
    assert lockerauth.get_locker_key("Gdrive") == "locker_gdrive"


def test_a_drive_locker_names_its_remote(drive_locker):
    assert lockerauth.get_locker_remote("Gdrive") == REMOTE


def test_a_blank_remote_path_is_the_root(drive_locker):
    drive_locker.set_value(SHARE, "locker_gdrive_remote_path", "")

    assert lockerauth.get_locker_remote("Gdrive") == ("Drive", "Gdrive", "/")


@pytest.mark.parametrize("setting, value", [
    ("locker_gdrive_type", ""), ("locker_gdrive_name", ""), ("locker_gdrive_type", "B2")])
def test_a_locker_that_cannot_use_oauth_has_no_remote(drive_locker, setting, value):
    drive_locker.set_value(SHARE, setting, value)

    assert lockerauth.get_locker_remote("Gdrive") is None


def test_the_options_reference_is_read_unresolved(drive_locker):
    assert lockerauth.get_options_reference("Gdrive") == REFERENCE


@pytest.mark.parametrize("value", ["", '{"client_id": "inline"}', "op://Personal"])
def test_a_config_that_is_not_a_field_reference_is_refused(drive_locker, value, caplog):
    drive_locker.set_value(SHARE, "locker_gdrive_config", value)

    assert lockerauth.get_options_reference("Gdrive") is None
    assert "op://Personal/JoyBox/UserData.Share/locker_gdrive_config" in caplog.text


@pytest.mark.parametrize("stored, expected", [
    ("", {}), ("[1]", {}), ('{"team_drive": "x"}', {"team_drive": "x"})])
def test_stored_options_are_only_ever_a_dict(monkeypatch, stored, expected):
    monkeypatch.setattr(lockerauth.secretstore, "resolve_value", lambda reference: stored)

    assert lockerauth.read_stored_options(REFERENCE) == expected


###########################################################
# Client and folder
###########################################################

def test_a_desktop_client_file_gives_its_id_and_secret(tmp_path):
    path = write_client(tmp_path, {"installed": {"client_id": CLIENT[0], "client_secret": CLIENT[1]}})

    assert lockerauth.read_client_file(path) == CLIENT


@pytest.mark.parametrize("data", [
    {"web": {"client_id": "i", "client_secret": "s"}}, {"installed": {"client_id": "i"}}, ["i"], {}])
def test_a_client_file_without_a_desktop_client_is_refused(tmp_path, data):
    assert lockerauth.read_client_file(write_client(tmp_path, data)) is None


def test_a_missing_client_file_is_refused(tmp_path):
    assert lockerauth.read_client_file(str(tmp_path / "absent.json")) is None


def test_a_client_file_wins_over_the_stored_client(tmp_path):
    path = write_client(tmp_path, {"installed": {"client_id": CLIENT[0], "client_secret": CLIENT[1]}})

    assert lockerauth.choose_client(path, {"client_id": "old", "client_secret": "old"}) == CLIENT


def test_the_stored_client_is_reused():
    assert lockerauth.choose_client("", {"client_id": "old", "client_secret": "s"}) == ("old", "s")


def test_no_client_at_all_is_refused():
    assert lockerauth.choose_client("", {"client_id": "old"}) is None


@pytest.mark.parametrize("value, expected", [
    (FOLDER, FOLDER),
    ("  %s  " % FOLDER, FOLDER),
    ("https://drive.google.com/drive/u/0/folders/%s?usp=sharing" % FOLDER, FOLDER),
    ("not a folder!", None),
    ("", None),
    (None, None),
])
def test_folder_ids_are_parsed_from_ids_and_urls(value, expected):
    assert lockerauth.parse_folder_id(value) == expected


def test_a_given_folder_wins_over_the_stored_one():
    assert lockerauth.choose_folder(FOLDER, {"root_folder_id": "old"}) == FOLDER


def test_a_given_folder_that_does_not_parse_is_refused():
    assert lockerauth.choose_folder("bad folder", {"root_folder_id": "old"}) is None


def test_the_stored_folder_is_reused():
    assert lockerauth.choose_folder("", {"root_folder_id": "old"}) == "old"


def test_no_folder_at_all_is_refused():
    assert lockerauth.choose_folder("", {}) is None


###########################################################
# Building and storing
###########################################################

def test_built_options_keep_extras_and_drop_service_accounts():
    stored = {"team_drive": "keep", "service_account_file": "/sa.json",
        "service_account_credentials": "{}", "client_id": "old"}

    assert lockerauth.build_options(stored, CLIENT, FOLDER, TOKEN) == {
        "team_drive": "keep", "client_id": CLIENT[0], "client_secret": CLIENT[1],
        "token": TOKEN, "root_folder_id": FOLDER}


@pytest.fixture
def remote_calls(drive_locker, monkeypatch):
    state = {"token": TOKEN, "entries": 2, "stored": True, "authorized": [], "listed": [], "saved": []}

    def authorize(**kwargs):
        state["authorized"].append(kwargs)
        return state["token"]

    def count(**kwargs):
        state["listed"].append((kwargs, json.loads(drive_locker.get_raw_value(SHARE, "locker_gdrive_config"))))
        return state["entries"]

    def store(reference, value, verbose = False):
        state["saved"].append((reference, json.loads(value)))
        return state["stored"]

    monkeypatch.setattr(lockerauth.sync, "authorize_remote", authorize)
    monkeypatch.setattr(lockerauth.sync, "count_remote_entries", count)
    monkeypatch.setattr(lockerauth.secretstore, "store_secret_reference", store)
    return state


def sign_in(**kwargs):
    return lockerauth.sign_in_locker("Gdrive", REMOTE, REFERENCE, {"team_drive": "keep"}, CLIENT, FOLDER, **kwargs)


def test_signing_in_checks_the_new_options_then_stores_them(remote_calls):
    assert sign_in(open_browser = False)

    expected = {"team_drive": "keep", "client_id": CLIENT[0], "client_secret": CLIENT[1],
        "token": TOKEN, "root_folder_id": FOLDER}
    assert remote_calls["authorized"] == [{"remote_type": "Drive", "client_id": CLIENT[0],
        "client_secret": CLIENT[1], "open_browser": False, "verbose": False}]
    assert remote_calls["listed"] == [(
        {"remote_name": "Gdrive", "remote_type": "Drive", "remote_path": "/Games", "verbose": False}, expected)]
    assert remote_calls["saved"] == [(REFERENCE, expected)]


def test_no_token_lists_and_stores_nothing(remote_calls):
    remote_calls["token"] = None

    assert not sign_in()
    assert remote_calls["listed"] == []
    assert remote_calls["saved"] == []


def test_a_token_that_cannot_list_the_folder_is_not_stored(remote_calls):
    remote_calls["entries"] = None

    assert not sign_in()
    assert remote_calls["saved"] == []


def test_an_empty_folder_still_signs_in(remote_calls):
    remote_calls["entries"] = 0

    assert sign_in()


def test_a_failed_store_fails_the_sign_in(remote_calls):
    remote_calls["stored"] = False

    assert not sign_in()
    assert len(remote_calls["saved"]) == 1
