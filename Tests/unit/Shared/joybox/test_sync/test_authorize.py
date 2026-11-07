# Third-party imports
import pytest

# Local imports
from joybox import config, sync
from sync_helpers import REMOTE, REMOTE_TYPE, REMOTE_PATH, record


###########################################################
# Signing in with an OAuth client
#
# rclone authorize waits for a browser sign-in and prints the token between
# paste markers. The client has to reach it through the environment, never
# the command line, and the token is only good with a refresh token in it:
# without one it stops working within the hour.
###########################################################

CLIENT_ID = "client.apps.googleusercontent.com"
CLIENT_PHRASE = "client-phrase-value"
TOKEN_JSON = '{"access_token":"a","token_type":"Bearer","refresh_token":"r","expiry":"2026-10-30T22:00:00Z"}'
AUTHORIZE_OUTPUT = "Paste the following into your remote machine --->\n%s\n<---End paste\n" % TOKEN_JSON


def sign_in(**kwargs):
    return sync.authorize_remote(config.RemoteType.DRIVE, CLIENT_ID, CLIENT_PHRASE, **kwargs)


def test_the_printed_token_is_returned(rclone, monkeypatch):
    record(monkeypatch, output = AUTHORIZE_OUTPUT)

    assert sign_in() == {
        "access_token": "a", "token_type": "Bearer", "refresh_token": "r", "expiry": "2026-10-30T22:00:00Z"}


def test_the_client_travels_in_the_environment(rclone, monkeypatch):
    recorder = record(monkeypatch, output = AUTHORIZE_OUTPUT)
    sign_in()
    call = recorder.calls[0]
    environment = call["options"].get_env()

    assert call["cmd"] == ["/tools/rclone", "authorize", "drive"]
    assert environment["RCLONE_DRIVE_CLIENT_ID"] == CLIENT_ID
    assert environment["RCLONE_DRIVE_CLIENT_SECRET"] == CLIENT_PHRASE
    assert not any(CLIENT_PHRASE in part for part in call["cmd"])


def test_the_token_is_captured_and_the_sign_in_link_is_not(rclone, monkeypatch):
    # Captured stdout holds the token; stderr, with the link, stays on the terminal
    recorder = record(monkeypatch, output = AUTHORIZE_OUTPUT)
    sign_in()
    kwargs = recorder.calls[0]["kwargs"]

    assert kwargs["capture_output"] is True
    assert "log_stdout" not in kwargs
    assert "log_stderr" not in kwargs


def test_the_browser_can_be_left_closed(rclone, monkeypatch):
    recorder = record(monkeypatch, output = AUTHORIZE_OUTPUT)
    sign_in(open_browser = False)

    assert recorder.calls[0]["cmd"][-1] == "--auth-no-open-browser"


def test_a_pretend_sign_in_gets_nothing(rclone, monkeypatch):
    recorder = record(monkeypatch, output = AUTHORIZE_OUTPUT)

    assert sign_in(pretend_run = True, verbose = True) is None
    assert recorder.calls[0]["kwargs"]["pretend_run"] is True
    assert recorder.calls[0]["kwargs"]["verbose"] is True


def test_signing_in_without_rclone_gets_nothing(no_rclone, quiet, monkeypatch):
    recorder = record(monkeypatch)

    assert sign_in() is None
    assert recorder.calls == []


@pytest.mark.parametrize("returncode, output", [
    (1, AUTHORIZE_OUTPUT),
    (0, "no markers here"),
    (0, AUTHORIZE_OUTPUT.replace('"refresh_token":"r",', "")),
    (0, "--->\n{not json}\n<---End paste\n"),
])
def test_a_failed_sign_in_gets_nothing(rclone, quiet, monkeypatch, returncode, output):
    record(monkeypatch, returncode = returncode, output = output)

    assert sign_in() is None


def test_no_output_holds_no_token():
    assert sync.parse_authorize_output(None) is None


###########################################################
# Checking a remote can be listed
###########################################################

def test_the_top_level_entries_are_counted(rclone, monkeypatch):
    recorder = record(monkeypatch, output = "Games/\nnotes.txt\n\n")

    assert sync.count_remote_entries(REMOTE, REMOTE_TYPE, REMOTE_PATH) == 2
    cmd = recorder.calls[0]["cmd"]
    assert cmd[1:4] == ["lsf", "--max-depth", "1"]
    assert cmd[-1] == sync.get_remote_connection_path(REMOTE, REMOTE_TYPE, REMOTE_PATH)


def test_an_empty_remote_has_no_entries(rclone, monkeypatch):
    record(monkeypatch, output = "")

    assert sync.count_remote_entries(REMOTE, REMOTE_TYPE, REMOTE_PATH) == 0


def test_a_failed_listing_counts_nothing(rclone, monkeypatch):
    record(monkeypatch, returncode = 1, output = "")

    assert sync.count_remote_entries(REMOTE, REMOTE_TYPE, REMOTE_PATH) is None


def test_counting_without_rclone_counts_nothing(no_rclone, quiet):
    assert sync.count_remote_entries(REMOTE, REMOTE_TYPE, REMOTE_PATH) is None
