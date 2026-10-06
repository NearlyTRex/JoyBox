# Imports
import pytest

# Local imports
from cli_helpers import CommandHarness, Recorder, assert_entry_points
from joybox.cli import generate_playlist


###########################################################
# generate_playlist
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings):
    command = CommandHarness(monkeypatch, generate_playlist)
    command.tree = Recorder(result = True)
    command.local = Recorder(result = True)
    monkeypatch.setattr(generate_playlist.playlist, "generate_tree_playlist", command.tree)
    monkeypatch.setattr(generate_playlist.playlist, "generate_local_playlists", command.local)
    return command


def test_tree_is_the_default_and_writes_to_the_output(tool, tmp_path):
    output = str(tmp_path / "all.m3u")

    tool.main("-i", str(tmp_path), "-o", output, "-f", ".mp3,.flac", "--allow_single_lists")

    assert tool.tree.calls == [{
        "source_dir": str(tmp_path),
        "output_file": output,
        "extensions": [".mp3", ".flac"],
        "allow_empty_lists": False,
        "allow_single_lists": True,
        "verbose": False,
        "pretend_run": False,
        "exit_on_failure": False}]
    assert tool.local.calls == []


def test_local_writes_a_playlist_per_directory(tool, tmp_path):
    tool.main("-i", str(tmp_path), "-t", "Local", "-f", ".mp3", "--allow_empty_lists", "-p")

    assert tool.local.calls == [{
        "source_dir": str(tmp_path),
        "extensions": [".mp3"],
        "allow_empty_lists": True,
        "allow_single_lists": False,
        "verbose": False,
        "pretend_run": True,
        "exit_on_failure": False}]
    assert tool.tree.calls == []


def test_file_types_are_required(tool, tmp_path, capsys):
    with pytest.raises(SystemExit) as raised:
        tool.main("-i", str(tmp_path))
    assert raised.value.code == 2
    assert "--file_types" in capsys.readouterr().err
    assert tool.tree.calls == []


def test_tree_without_an_output_path_stops_the_run(tool, tmp_path):
    with pytest.raises(SystemExit):
        tool.main("-i", str(tmp_path), "-f", ".mp3")
    assert tool.errors == ["Output path is required for Tree playlists (-o/--output_path)"]
    assert tool.tree.calls == []


def test_local_needs_no_output_path(tool, tmp_path):
    tool.main("-i", str(tmp_path), "-t", "Local", "-f", ".mp3")

    assert len(tool.local.calls) == 1


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, generate_playlist)
