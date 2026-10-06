# Imports
import pytest

# Local imports
from cli_helpers import CommandHarness, Recorder, assert_entry_points
from joybox import config
from joybox.cli import tag_audio_files


###########################################################
# tag_audio_files
#
# One genre is tagged when named, otherwise every genre with albums; a bad
# --set stops the run before anything is tagged.
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings):
    command = CommandHarness(monkeypatch, tag_audio_files)
    command.tag = Recorder(result = True)
    command.all_genres = []

    def process_all_genres(handler, album_name, artist_name):
        command.all_genres.append((album_name, artist_name))
        return handler(config.AudioGenreType.GAME)

    monkeypatch.setattr(tag_audio_files.audio, "tag_genre_with_policy", command.tag)
    monkeypatch.setattr(tag_audio_files.audio, "process_all_genres", process_all_genres)
    return command


def test_a_named_genre_is_tagged_alone(tool):
    result = tool.main("-g", "Classical", "-b", "Album", "-r", "Artist", "--set", "album_artist=Various", "--clear_existing", "--no_apply")

    assert result is True
    assert tool.all_genres == []
    assert tool.tag.calls == [{
        "genre_type": config.AudioGenreType.CLASSICAL,
        "album_name": "Album",
        "artist_name": "Artist",
        "extra_force_tags": {"album_artist": "Various"},
        "apply_tags": False,
        "clear_existing": True,
        "verbose": False,
        "pretend_run": False,
        "exit_on_failure": False}]


def test_without_a_genre_every_genre_is_processed(tool):
    tool.tag.result = False

    result = tool.main("-b", "Album")

    assert result is False
    assert tool.all_genres == [("Album", None)]
    assert tool.tag.values("genre_type") == [config.AudioGenreType.GAME]
    assert tool.tag.values("apply_tags") == [True]
    assert tool.tag.values("extra_force_tags") == [{}]


def test_an_invalid_forced_tag_stops_before_tagging(tool):
    assert tool.exit_code("--set", "missing_equals") == 1
    assert tool.errors[0] == "Invalid --set value (expected field=value): missing_equals"
    assert tool.tag.calls == []


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, tag_audio_files)
