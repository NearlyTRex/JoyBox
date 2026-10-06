# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox import config
from joybox.cli import audio_metadata_tool


###########################################################
# Action dispatch and exit status
###########################################################

@pytest.fixture
def tool(monkeypatch):
    harness = CommandHarness(monkeypatch, audio_metadata_tool)
    harness.actions = []
    harness.result = True
    harness.all_genres = []

    def run_action(**kwargs):
        harness.actions.append(kwargs)
        return harness.result

    def all_genres(handler, album_name, artist_name):
        harness.all_genres.append((album_name, artist_name))
        return handler(config.AudioGenreType.GAME) and handler(config.AudioGenreType.RADIO)

    monkeypatch.setattr(audio_metadata_tool.audio, "run_metadata_action", run_action)
    monkeypatch.setattr(audio_metadata_tool.audio, "process_all_genres", all_genres)
    return harness


def test_tag_passes_forced_tags_for_one_genre(tool):
    tool.run("-g", "Game", "-b", "Album", "--set", "genre=Chiptune", "--use_index_for_track_number")

    [call] = tool.actions
    assert call["action"] == config.AudioMetadataAction.TAG
    assert call["genre_type"] == config.AudioGenreType.GAME
    assert call["album_name"] == "Album"
    assert call["force_tags"] == {"genre": "Chiptune"}
    assert call["use_index_for_track_number"] is True
    assert tool.all_genres == []


def test_an_invalid_forced_tag_stops_before_any_action(tool):
    assert tool.exit_code("--set", "genre") == 1
    assert tool.actions == []


def test_other_actions_take_no_forced_tags(tool):
    tool.run("-a", "Clear", "-g", "Radio")

    assert [call["force_tags"] for call in tool.actions] == [None]


def test_without_a_genre_every_genre_is_processed(tool):
    tool.run("-r", "Artist")

    assert tool.all_genres == [(None, "Artist")]
    assert [call["genre_type"] for call in tool.actions] == [config.AudioGenreType.GAME, config.AudioGenreType.RADIO]


def test_a_failed_action_exits_with_an_error(tool):
    tool.result = False

    assert tool.exit_code("-g", "Game") == 1


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, audio_metadata_tool)
