# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox import config
from joybox.cli import download_audio_files


###########################################################
# Genre dispatch and order
#
# The order flags override the configured default, newest winning when both
# are given; a failed download reaches the caller as a non-zero exit.
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings):
    harness = CommandHarness(monkeypatch, download_audio_files)
    harness.story = []
    harness.asmr = []
    harness.result = True

    def story(**kwargs):
        harness.story.append(kwargs)
        return harness.result

    def asmr(**kwargs):
        harness.asmr.append(kwargs)
        return harness.result

    monkeypatch.setattr(download_audio_files.audio, "download_story_audio_files", story)
    monkeypatch.setattr(download_audio_files.audio, "download_asmr_audio_files", asmr)
    return harness


@pytest.mark.parametrize("flags, oldest_first", [
    ([], None),
    (["--oldest_first"], True),
    (["--newest_first"], False),
    (["--oldest_first", "--newest_first"], False),
])
def test_order_flags_override_the_configured_default(tool, flags, oldest_first):
    tool.run("-g", "Story", *flags)

    [call] = tool.story
    assert call["oldest_first"] is oldest_first


def test_story_downloads_pass_the_selection_through(tool):
    tool.run("-g", "Story", "-n", "Channel", "-c", "cookies.txt", "-l", "Hetzner", "-o", "out")

    [call] = tool.story
    assert call["channel_name"] == "Channel"
    assert call["cookie_source"] == "cookies.txt"
    assert call["locker_type"] == config.LockerType.HETZNER
    assert call["output_path"] == "out"
    assert tool.asmr == []


def test_asmr_downloads_use_the_asmr_channels(tool):
    tool.run("-g", "ASMR")

    [call] = tool.asmr
    assert call["cookie_source"] == "firefox"
    assert call["locker_type"] == config.LockerType.ALL
    assert tool.story == []


@pytest.mark.parametrize("genre, message", [("Story", "Story audio download failed"), ("ASMR", "ASMR audio download failed")])
def test_a_failed_download_exits_with_an_error(tool, genre, message):
    tool.result = False

    assert tool.exit_code("-g", genre) == 1
    assert tool.errors == [message]


@pytest.mark.parametrize("flags", [[], ["-g", "Classical"]])
def test_other_genres_download_nothing(tool, flags):
    tool.run(*flags)

    assert tool.story == tool.asmr == []


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, download_audio_files)
