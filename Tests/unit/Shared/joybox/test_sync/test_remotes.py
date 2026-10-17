# Local imports
from joybox import sync
from fakes import RecordingCommand
from sync_helpers import REMOTE, REMOTE_TYPE


###########################################################
# Listing remotes
#
# rclone sees a remote the settings define only in the environment of a
# command that names it, and lowercases a name it read from there.
###########################################################

def test_configured_remotes_are_listed_with_their_types(rclone, monkeypatch):
    recorder = RecordingCommand(monkeypatch, output = "hetzner: sftp\ngdrive:  drive\n")

    assert sync.get_configured_remotes() == {"hetzner": "sftp", "gdrive": "drive"}
    assert recorder.only() == ["/tools/rclone", "listremotes", "--long"]


def test_byte_output_is_decoded(rclone, monkeypatch):
    RecordingCommand(monkeypatch, output = b"hetzner: sftp\n")

    assert sync.get_configured_remotes() == {"hetzner": "sftp"}


def test_names_are_listed_lowercase(rclone, monkeypatch):
    RecordingCommand(monkeypatch, output = "HetznerBox: sftp\n")

    assert sync.get_configured_remotes() == {"hetznerbox": "sftp"}


def test_no_remotes_lists_nothing(rclone, monkeypatch):
    RecordingCommand(monkeypatch, output = "")

    assert sync.get_configured_remotes() == {}


def test_listing_without_rclone_lists_nothing(no_rclone, recording_command):
    assert sync.get_configured_remotes() == {}
    assert recording_command.ran() is False


def test_the_listing_sees_the_remotes_it_is_asked_about(rclone, isolated_settings, monkeypatch):
    isolated_settings.set_value("UserData.Share", "locker_hetzner_name", "HetznerBox")
    isolated_settings.set_value("UserData.Share", "locker_hetzner_type", "SFTP")
    isolated_settings.set_value("UserData.Share", "locker_hetzner_config", '{"host": "box.example"}')
    monkeypatch.setattr(sync.rcloneremotes.knownhosts, "remember_host", lambda host, port = 22: True)
    recorder = RecordingCommand(monkeypatch, output = "hetznerbox: sftp\n")

    sync.get_configured_remotes(remote_names = ["HetznerBox"])

    assert recorder.options().get_env()["RCLONE_CONFIG_HETZNERBOX_HOST"] == "box.example"


###########################################################
# Remote configuration
###########################################################

def test_a_configured_remote_of_the_right_type_matches(rclone, quiet, monkeypatch):
    raw = sync.get_remote_raw_type(REMOTE_TYPE)
    monkeypatch.setattr(sync, "get_configured_remotes", lambda **kwargs: {"hetzner": raw})

    assert sync.is_remote_configured(REMOTE, REMOTE_TYPE) is True


def test_a_remote_is_matched_whatever_the_case_of_its_name(rclone, quiet, monkeypatch):
    raw = sync.get_remote_raw_type(REMOTE_TYPE)
    monkeypatch.setattr(sync, "get_configured_remotes", lambda **kwargs: {"hetznerbox": raw})

    assert sync.is_remote_configured("HetznerBox", REMOTE_TYPE) is True


def test_a_remote_of_another_type_does_not_match(rclone, quiet, monkeypatch):
    # Talking to the wrong backend would sync to a different place entirely.
    monkeypatch.setattr(sync, "get_configured_remotes", lambda **kwargs: {"hetzner": "somethingelse"})

    assert sync.is_remote_configured(REMOTE, REMOTE_TYPE) is False


def test_an_unlisted_remote_is_not_configured(rclone, quiet, monkeypatch):
    monkeypatch.setattr(sync, "get_configured_remotes", lambda **kwargs: {"gdrive": "drive"})

    assert sync.is_remote_configured(REMOTE, REMOTE_TYPE) is False
