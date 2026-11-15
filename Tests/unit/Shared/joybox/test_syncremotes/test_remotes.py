# Local imports
from joybox import logger
from joybox import rcloneremotes
from joybox import sync
from joybox import syncremotes
from fakes import RecordingCommand
from sync_helpers import REMOTE, REMOTE_TYPE, record


###########################################################
# Listing remotes
#
# rclone sees a remote the settings define only in the environment of a
# command that names it, and lowercases a name it read from there.
###########################################################

def test_configured_remotes_are_listed_with_their_types(rclone, monkeypatch):
    recorder = RecordingCommand(monkeypatch, output = "hetzner: sftp\ngdrive:  drive\n")

    assert syncremotes.get_configured_remotes() == {"hetzner": "sftp", "gdrive": "drive"}
    assert recorder.only() == ["/tools/rclone", "listremotes", "--long"]


def test_byte_output_is_decoded(rclone, monkeypatch):
    RecordingCommand(monkeypatch, output = b"hetzner: sftp\n")

    assert syncremotes.get_configured_remotes() == {"hetzner": "sftp"}


def test_names_are_listed_lowercase(rclone, monkeypatch):
    RecordingCommand(monkeypatch, output = "HetznerBox: sftp\n")

    assert syncremotes.get_configured_remotes() == {"hetznerbox": "sftp"}


def test_no_remotes_lists_nothing(rclone, monkeypatch):
    RecordingCommand(monkeypatch, output = "")

    assert syncremotes.get_configured_remotes() == {}


def test_listing_without_rclone_lists_nothing(no_rclone, recording_command):
    assert syncremotes.get_configured_remotes() == {}
    assert recording_command.ran() is False


def test_the_listing_sees_the_remotes_it_is_asked_about(rclone, isolated_settings, monkeypatch):
    isolated_settings.set_value("UserData.Share", "locker_hetzner_name", "HetznerBox")
    isolated_settings.set_value("UserData.Share", "locker_hetzner_type", "SFTP")
    isolated_settings.set_value("UserData.Share", "locker_hetzner_config", '{"host": "box.example"}')
    monkeypatch.setattr(rcloneremotes.knownhosts, "remember_host", lambda host, port = 22: True)
    recorder = RecordingCommand(monkeypatch, output = "hetznerbox: sftp\n")

    syncremotes.get_configured_remotes(remote_names = ["HetznerBox"])

    assert recorder.options().get_env()["RCLONE_CONFIG_HETZNERBOX_HOST"] == "box.example"


###########################################################
# Remote configuration
###########################################################

def test_a_configured_remote_of_the_right_type_matches(rclone, quiet, monkeypatch):
    raw = sync.get_remote_raw_type(REMOTE_TYPE)
    monkeypatch.setattr(syncremotes, "get_configured_remotes", lambda **kwargs: {"hetzner": raw})

    assert syncremotes.is_remote_configured(REMOTE, REMOTE_TYPE) is True


def test_a_remote_is_matched_whatever_the_case_of_its_name(rclone, quiet, monkeypatch):
    raw = sync.get_remote_raw_type(REMOTE_TYPE)
    monkeypatch.setattr(syncremotes, "get_configured_remotes", lambda **kwargs: {"hetznerbox": raw})

    assert syncremotes.is_remote_configured("HetznerBox", REMOTE_TYPE) is True


def test_a_remote_of_another_type_does_not_match(rclone, quiet, monkeypatch):
    # Talking to the wrong backend would sync to a different place entirely.
    monkeypatch.setattr(syncremotes, "get_configured_remotes", lambda **kwargs: {"hetzner": "somethingelse"})

    assert syncremotes.is_remote_configured(REMOTE, REMOTE_TYPE) is False


def test_an_unlisted_remote_is_not_configured(rclone, quiet, monkeypatch):
    monkeypatch.setattr(syncremotes, "get_configured_remotes", lambda **kwargs: {"gdrive": "drive"})

    assert syncremotes.is_remote_configured(REMOTE, REMOTE_TYPE) is False


###########################################################
# Configured remotes
###########################################################

def test_a_failed_remote_listing_lists_nothing(rclone, quiet, monkeypatch):
    record(monkeypatch, returncode = 1, output = "hetzner: sftp\n")

    assert syncremotes.get_configured_remotes() == {}


def test_blank_lines_are_not_remotes(rclone, monkeypatch):
    record(monkeypatch, output = "hetzner: sftp\n\n  \ngdrive: drive\n")

    assert syncremotes.get_configured_remotes() == {"hetzner": "sftp", "gdrive": "drive"}


def test_the_remote_check_lists_the_remote_it_names_with_its_flags(rclone, quiet, monkeypatch):
    seen = []
    monkeypatch.setattr(syncremotes, "get_configured_remotes", lambda **kwargs: seen.append(kwargs) or {})
    syncremotes.is_remote_configured(REMOTE, REMOTE_TYPE, verbose = True, pretend_run = True, exit_on_failure = True)

    assert seen == [{"remote_names": [REMOTE], "verbose": True, "pretend_run": True, "exit_on_failure": True}]


def test_a_remote_whose_name_only_starts_the_same_is_not_configured(rclone, quiet, monkeypatch):
    # hetznerEnc being defined says nothing about hetzner itself.
    raw = sync.get_remote_raw_type(REMOTE_TYPE)
    monkeypatch.setattr(syncremotes, "get_configured_remotes", lambda **kwargs: {"hetznerenc": raw})

    assert syncremotes.is_remote_configured(REMOTE, REMOTE_TYPE) is False


def test_a_configured_remote_check_without_rclone_is_false(no_rclone, quiet, recording_command):
    assert syncremotes.is_remote_configured(REMOTE, REMOTE_TYPE) is False
    assert recording_command.ran() is False


###########################################################
# Setting up remotes
#
# Remotes are defined by the settings, so setting one up creates nothing: it
# checks the remote resolves, and never puts a credential on a command line.
###########################################################

def test_a_remote_the_settings_define_is_set_up(rclone, quiet, monkeypatch, recording_command):
    checked = []
    monkeypatch.setattr(syncremotes, "is_remote_configured", lambda **kwargs: checked.append(kwargs) or True)

    assert syncremotes.setup_remote(REMOTE, REMOTE_TYPE, verbose = True) is True
    assert checked == [{"remote_name": REMOTE, "remote_type": REMOTE_TYPE,
                        "verbose": True, "pretend_run": False, "exit_on_failure": False}]
    assert recording_command.ran() is False


def test_a_remote_the_settings_do_not_define_says_where_to_define_it(rclone, monkeypatch):
    errors = []
    monkeypatch.setattr(syncremotes, "is_remote_configured", lambda **kwargs: False)
    monkeypatch.setattr(logger, "log_error", errors.append)

    assert syncremotes.setup_remote(REMOTE, REMOTE_TYPE) is False
    assert errors == ["Remote 'hetzner' is not defined as %s; set the locker's _name, _type and _config in "
                      "[UserData.Share]" % sync.get_remote_raw_type(REMOTE_TYPE)]
