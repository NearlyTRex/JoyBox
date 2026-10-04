# Imports
import pytest

# Local imports
from joybox import computer
from computer_helpers import FakeOptions, TOKEN_MAP, program


###########################################################
# Launch guard
#
# run() builds its command in four mutually exclusive branches. An entry that
# matches none of them named nothing to run, and the code below assumed one had
# been taken.
###########################################################

def test_a_program_with_nothing_to_run_is_refused():
    assert computer.Program().run(FakeOptions(), {}) is False


def test_a_program_with_only_a_working_directory_is_refused():
    entry = program(cwd = "Game")

    assert entry.run(FakeOptions(), {}) is False


def test_a_program_with_an_empty_executable_is_refused():
    entry = program(exe = "", cwd = "Game")

    assert entry.run(FakeOptions(), {}) is False


def test_a_refused_program_does_not_reach_the_launcher(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("nothing should be launched")

    monkeypatch.setattr(computer.command, "run_capture_command", fail)

    assert computer.Program().run(FakeOptions(), {}) is False


@pytest.mark.parametrize("setter", ["set_is_dos", "set_is_win31", "set_is_scumm"])
def test_an_emulated_program_needs_no_executable(setter, monkeypatch):
    # dos, win31 and scumm entries are launched through an emulator, so the
    # guard must not reject them for having no windows executable.
    captured = []
    monkeypatch.setattr(
        computer.command, "run_capture_command",
        lambda **kwargs: captured.append(kwargs) or True)
    monkeypatch.setattr(
        computer.display, "restore_default_screen_resolution", lambda **kwargs: True)
    for name in ["get_dos_launch_command", "get_win31_launch_command",
                 "get_scumm_launch_command"]:
        monkeypatch.setattr(computer.command, name, lambda **kwargs: ["emulator"])
    monkeypatch.setattr(
        computer.programs, "get_emulator_program", lambda name: "/tools/dosboxx")

    entry = computer.Program()
    getattr(entry, setter)(True)

    assert entry.run(FakeOptions(), {}) is True
    assert captured


###########################################################
# Launching
#
# Each launch type builds its command differently and decides which process
# the launcher waits on. Waiting on the wrong one returns while the game is
# still running, and the screen resolution is restored under it.
###########################################################

@pytest.fixture
def launcher(monkeypatch):
    calls = {"capture": [], "restore": [], "dos": [], "win31": [], "scumm": []}
    results = {"capture": True, "restore": True}

    def recorder(name, value):
        return lambda **kwargs: calls[name].append(kwargs) or value

    monkeypatch.setattr(
        computer.command, "run_capture_command",
        lambda **kwargs: calls["capture"].append(kwargs) or results["capture"])
    monkeypatch.setattr(
        computer.display, "restore_default_screen_resolution",
        lambda **kwargs: calls["restore"].append(kwargs) or results["restore"])
    monkeypatch.setattr(
        computer.command, "get_dos_launch_command", recorder("dos", ["dosbox", "dos"]))
    monkeypatch.setattr(
        computer.command, "get_win31_launch_command", recorder("win31", ["dosbox", "win31"]))
    monkeypatch.setattr(
        computer.command, "get_scumm_launch_command", recorder("scumm", ["scummvm"]))
    monkeypatch.setattr(
        computer.programs, "get_emulator_program", lambda name: "/tools/" + name)
    calls["results"] = results
    return calls


def test_a_windows_program_runs_from_the_prefix_drive(launcher):
    options = FakeOptions()
    entry = program(exe = "game.exe", cwd = "Game", args = ["-windowed"])

    assert entry.run(options, TOKEN_MAP) is True
    cmd = launcher["capture"][0]["cmd"]
    assert cmd == ["/prefix/drive_c/Game/game.exe", "-windowed"]


def test_a_windows_program_runs_inside_its_prefix(launcher):
    options = FakeOptions()
    program(exe = "game.exe", cwd = "Game").run(options, TOKEN_MAP)

    assert options.forced is True
    assert options.mapped is True
    assert options.cwd == computer.os.path.expanduser("~")
    assert options.blocking == ["/prefix/drive_c/Game/game.exe"]


def test_a_windows_program_resolves_its_tokens(launcher):
    # A token that expands to an absolute path replaces the drive root.
    entry = program(exe = "game.exe", cwd = "$GAME_SAVE_DIR")
    entry.run(FakeOptions(), TOKEN_MAP)

    assert launcher["capture"][0]["cmd"][0] == "/prefix/saves/game.exe"


def test_the_launch_settings_reach_the_launcher(launcher):
    options = FakeOptions()
    program(exe = "game.exe").run(
        options, TOKEN_MAP, capture_type = "video", capture_file = "/out.mp4",
        verbose = True, pretend_run = True, exit_on_failure = True)
    call = launcher["capture"][0]

    assert call["options"] is options
    assert (call["capture_type"], call["capture_file"]) == ("video", "/out.mp4")
    assert (call["verbose"], call["pretend_run"], call["exit_on_failure"]) == (True, True, True)
    assert launcher["restore"][0]["pretend_run"] is True


def test_a_dos_program_runs_under_dosbox(launcher):
    options = FakeOptions()
    entry = program(exe = "GAME.EXE", cwd = "GAME", args = ["/S"], is_dos = True)

    assert entry.run(options, TOKEN_MAP, fullscreen = True) is True
    call = launcher["dos"][0]
    assert call["start_program"] == "GAME.EXE"
    assert call["start_args"] == ["/S"]
    assert call["fullscreen"] is True
    assert options.blocking == ["/tools/DosBoxX"]
    assert launcher["capture"][0]["cmd"] == ["dosbox", "dos"]


def test_a_dos_program_is_found_on_the_dos_drive(launcher):
    program(exe = "GAME.EXE", cwd = "GAME", is_dos = True).run(FakeOptions(), TOKEN_MAP)
    call = launcher["dos"][0]
    expected = computer.paths.get_filename_directory("/prefix/dos/GAME/GAME.EXE")

    assert call["start_letter"] == computer.paths.get_filename_drive(expected)
    assert call["start_offset"] == computer.paths.get_filename_drive_offset(expected)


def test_a_win31_program_runs_under_dosbox(launcher):
    options = FakeOptions()
    entry = program(exe = "GAME.EXE", cwd = "GAME", is_win31 = True)

    assert entry.run(options, TOKEN_MAP) is True
    assert launcher["win31"][0]["start_program"] == "GAME.EXE"
    assert options.blocking == ["/tools/DosBoxX"]
    assert launcher["capture"][0]["cmd"] == ["dosbox", "win31"]
    assert launcher["dos"] == []


def test_a_scumm_program_runs_under_scummvm(launcher):
    options = FakeOptions()

    assert program(is_scumm = True).run(options, TOKEN_MAP, fullscreen = True) is True
    assert launcher["scumm"][0]["fullscreen"] is True
    assert launcher["capture"][0]["cmd"] == ["scummvm"]
    assert options.forced is False


def test_a_failed_launch_leaves_the_resolution_alone(launcher):
    launcher["results"]["capture"] = False

    assert program(exe = "game.exe").run(FakeOptions(), TOKEN_MAP) is False
    assert launcher["restore"] == []


def test_a_resolution_that_cannot_be_restored_is_reported(launcher):
    launcher["results"]["restore"] = False

    assert program(exe = "game.exe").run(FakeOptions(), TOKEN_MAP) is False
