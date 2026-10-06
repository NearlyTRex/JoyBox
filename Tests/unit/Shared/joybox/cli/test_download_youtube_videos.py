# Imports
import os

# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, Recorder, assert_entry_points
from joybox.cli import download_youtube_videos


###########################################################
# download_youtube_videos
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings):
    command = CommandHarness(monkeypatch, download_youtube_videos)
    command.download = Recorder()
    monkeypatch.setattr(download_youtube_videos.google, "download_video", command.download)
    return command


def test_defaults_download_video_into_the_current_directory_with_firefox_cookies(tool):
    tool.main("https://youtube.example/watch?v=abc")

    call = tool.download.calls[0]
    assert call["video_url"] == "https://youtube.example/watch?v=abc"
    assert call["output_dir"] == os.path.realpath(".")
    assert call["cookie_source"] == "firefox"
    assert (call["audio_only"], call["output_file"], call["download_archive"], call["sanitize_filenames"]) == (False, None, None, False)


def test_options_reach_the_download(tool, tmp_path):
    archive = str(tmp_path / "archive.txt")

    tool.main("https://youtube.example/@channel", "-a", "-o", "clip.mp3", "-d", str(tmp_path),
        "-r", archive, "-c", "cookies.txt", "-s", "-v", "-p", "-x")

    call = tool.download.calls[0]
    assert (call["audio_only"], call["output_file"], call["output_dir"]) == (True, "clip.mp3", str(tmp_path))
    assert (call["download_archive"], call["cookie_source"], call["sanitize_filenames"]) == (archive, "cookies.txt", True)
    assert (call["verbose"], call["pretend_run"], call["exit_on_failure"]) == (True, True, True)


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, download_youtube_videos)
