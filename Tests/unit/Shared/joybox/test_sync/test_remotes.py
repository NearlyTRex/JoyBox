# Local imports
from joybox import sync
from sync_helpers import REMOTE, REMOTE_TYPE


###########################################################
# Listing remotes
###########################################################

def test_configured_remotes_are_listed(rclone, monkeypatch):
    from fakes import RecordingCommand
    recorder = RecordingCommand(monkeypatch, output = "hetzner:\ngdrive:\n")

    assert sync.get_configured_remotes() == ["hetzner:", "gdrive:"]
    assert recorder.only()[:2] == ["/tools/rclone", "listremotes"]


def test_byte_output_is_decoded(rclone, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, output = b"hetzner:\n")

    assert sync.get_configured_remotes() == ["hetzner:"]


def test_no_remotes_lists_nothing(rclone, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, output = "")

    assert sync.get_configured_remotes() == []


def test_listing_without_rclone_lists_nothing(no_rclone, recording_command):
    assert sync.get_configured_remotes() == []
    assert recording_command.ran() is False


###########################################################
# Remote configuration
###########################################################

def test_a_configured_remote_of_the_right_type_matches(rclone, quiet, monkeypatch):
    raw = sync.get_remote_raw_type(REMOTE_TYPE)
    monkeypatch.setattr(
        sync, "get_configured_remotes", lambda **kwargs: ["hetzner:"])
    monkeypatch.setattr(
        sync.command, "run_output_command",
        lambda **kwargs: "[hetzner]\ntype = %s\n" % raw)

    assert sync.is_remote_configured(REMOTE, REMOTE_TYPE)


def test_a_remote_of_another_type_does_not_match(rclone, quiet, monkeypatch):
    # Talking to the wrong backend would sync to a different place entirely.
    monkeypatch.setattr(
        sync, "get_configured_remotes", lambda **kwargs: ["hetzner:"])
    monkeypatch.setattr(
        sync.command, "run_output_command",
        lambda **kwargs: "[hetzner]\ntype = somethingelse\n")

    assert not sync.is_remote_configured(REMOTE, REMOTE_TYPE)


def test_an_unlisted_remote_is_not_configured(rclone, quiet, monkeypatch):
    monkeypatch.setattr(
        sync, "get_configured_remotes", lambda **kwargs: ["gdrive:"])

    assert sync.is_remote_configured(REMOTE, REMOTE_TYPE) is False


def test_a_remote_without_a_type_is_not_configured(rclone, quiet, monkeypatch):
    monkeypatch.setattr(
        sync, "get_configured_remotes", lambda **kwargs: ["hetzner:"])
    monkeypatch.setattr(
        sync.command, "run_output_command",
        lambda **kwargs: "couldn't find type of fs for hetzner")

    assert sync.is_remote_configured(REMOTE, REMOTE_TYPE) is False


