# Imports
import os

# Third-party imports
import pytest

# Local imports
import joybox.gui as gui
from joybox import config, sandbox
from sandbox_helpers import WINE, SANDBOXIE, NEITHER


###########################################################
# Wrapping a command for its prefix
#
# The runner has to come first and the game's own argv after it, or the game
# starts on the host instead of inside the prefix.
###########################################################

@pytest.fixture
def popups(monkeypatch):
    shown = []
    monkeypatch.setattr(gui, "display_error_popup", lambda **kwargs: shown.append(kwargs))
    return shown


def wine(**kwargs):
    return WINE(prefix_name = config.PrefixType.GAME, **kwargs)


def sandboxie(prefix_name = config.PrefixType.GAME):
    return SANDBOXIE(prefix_name = prefix_name)


def test_a_non_prefix_command_is_not_wrapped():
    entry = NEITHER()

    assert sandbox.setup_prefix_command(["game.exe"], options = entry) == (["game.exe"], entry)


def test_a_command_without_options_is_not_wrapped():
    cmd, built = sandbox.setup_prefix_command(["game.exe"])

    assert cmd == ["game.exe"]
    assert not built.is_prefix()


def test_an_empty_command_is_not_wrapped(installed_runners):
    entry = wine()

    assert sandbox.setup_prefix_command([], options = entry) == ([], entry)


def test_a_wine_command_starts_with_wine(installed_runners):
    cmd, built = sandbox.setup_prefix_command(["game.exe", "-windowed"], options = wine())

    assert cmd == ["/tools/wine", "game.exe", "-windowed"]


def test_a_wine_command_gets_a_copy_of_its_options(installed_runners):
    entry = wine()
    cmd, built = sandbox.setup_prefix_command(["game.exe"], options = entry)

    assert built is not entry


def test_a_virtual_desktop_wraps_the_game_in_explorer(installed_runners):
    entry = wine()
    entry.set_use_virtual_desktop(True)
    entry.set_desktop_width(1024)
    entry.set_desktop_height(768)

    cmd, built = sandbox.setup_prefix_command(["game.exe"], options = entry)

    assert cmd == ["/tools/wine", "explorer", "/desktop=1024x768", "game.exe"]


def test_a_sandboxie_command_names_its_box(installed_runners):
    cmd, built = sandbox.setup_prefix_command(["game.exe"], options = sandboxie())

    assert cmd == ["/tools/start.exe", "/box:Game", "game.exe"]


def test_a_sandboxed_tool_runs_hidden(installed_runners):
    cmd, built = sandbox.setup_prefix_command(["tool.exe"], options = sandboxie(config.PrefixType.TOOL))

    assert cmd == ["/tools/start.exe", "/box:Tool", "/hide_window", "tool.exe"]


def test_a_batch_file_runs_through_cmd_under_sandboxie(installed_runners):
    cmd, built = sandbox.setup_prefix_command(["setup.bat", "/q"], options = sandboxie())

    assert cmd == ["/tools/start.exe", "/box:Game", "cmd", "/c", "setup.bat", "/q"]


def test_a_batch_file_runs_directly_under_wine(installed_runners):
    cmd, built = sandbox.setup_prefix_command(["setup.bat"], options = wine())

    assert cmd == ["/tools/wine", "setup.bat"]


def test_a_shortcut_runs_its_target_from_its_directory(installed_runners, popups, tmp_path, monkeypatch):
    target = tmp_path / "Game.exe"
    target.write_text("")
    monkeypatch.setattr(sandbox.fileops, "get_link_info", lambda lnk_path, lnk_base_path: {
        "target": str(target), "cwd": str(tmp_path), "args": ["-fullscreen"]})

    cmd, built = sandbox.setup_prefix_command(["Game.lnk"], options = wine())

    assert cmd == ["/tools/wine", str(target), "-fullscreen"]
    assert built.get_cwd() == str(tmp_path)
    assert popups == []


def test_a_shortcut_that_resolves_nowhere_is_reported(installed_runners, popups, monkeypatch):
    monkeypatch.setattr(sandbox.fileops, "get_link_info", lambda lnk_path, lnk_base_path: {
        "target": "", "cwd": "", "args": []})

    sandbox.setup_prefix_command(["Game.lnk"], options = wine())

    assert "Game.lnk" in popups[0]["message_text"]


###########################################################
# Mapping the working directory into the prefix
###########################################################

def test_the_working_directory_is_mapped_to_its_drive(tmp_path):
    entry = WINE(prefix_dir = str(tmp_path / "prefix"))
    entry.set_is_prefix_mapped_cwd(True)
    entry.set_cwd(str(tmp_path))

    sandbox.setup_prefix_environment(["game.exe"], options = entry)

    drive = sandbox.get_real_drive_path(entry, config.drive_prefix_cwd)
    assert os.path.realpath(drive) == str(tmp_path)


def test_an_unmapped_working_directory_gets_no_drive(tmp_path):
    entry = WINE(prefix_dir = str(tmp_path / "prefix"))
    entry.set_cwd(str(tmp_path))

    sandbox.setup_prefix_environment(["game.exe"], options = entry)

    assert not os.path.lexists(sandbox.get_real_drive_path(entry, config.drive_prefix_cwd))


def test_a_mapped_working_directory_needs_a_prefix_to_map_into(tmp_path, monkeypatch):
    def fail(**kwargs):
        raise AssertionError("there is no prefix drive to link")

    monkeypatch.setattr(sandbox.fileops, "create_symlink", fail)
    entry = WINE(prefix_dir = None)
    entry.set_is_prefix_mapped_cwd(True)
    entry.set_cwd(str(tmp_path))

    sandbox.setup_prefix_environment(["game.exe"], options = entry)


def test_environment_setup_without_options_changes_nothing():
    cmd, built = sandbox.setup_prefix_environment(["game.exe"])

    assert cmd == ["game.exe"]
    assert not built.is_prefix()


###########################################################
# Cleaning up after a command
###########################################################

def test_wine_cleanup_stops_the_wine_server(recording_command, monkeypatch):
    killed = []
    monkeypatch.setattr(sandbox.programs, "get_tool_program", lambda name: "/tools/" + name)
    monkeypatch.setattr(sandbox.process, "kill_active_named_processes", lambda names: killed.append(names))

    sandbox.cleanup_wine(["game.exe"], wine(), pretend_run = True)

    assert recording_command.only() == ["/tools/WineServer", "-k"]
    assert recording_command.calls[0]["kwargs"]["pretend_run"] is True
    assert recording_command.calls[0]["options"].is_shell()
    assert killed == [["/tools/WineServer"]]


def test_sandboxie_cleanup_has_nothing_to_stop(recording_command):
    sandbox.cleanup_sandboxie(["game.exe"], sandboxie())

    assert recording_command.calls == []
