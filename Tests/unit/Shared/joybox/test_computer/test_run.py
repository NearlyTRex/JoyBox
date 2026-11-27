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

    monkeypatch.setattr(computer.capture, "run_capture_command", fail)

    assert computer.Program().run(FakeOptions(), {}) is False


@pytest.mark.parametrize("setter", ["set_is_dos", "set_is_win31", "set_is_scumm"])
def test_an_emulated_program_needs_no_executable(setter, monkeypatch):
    # dos, win31 and scumm entries are launched through an emulator, so the
    # guard must not reject them for having no windows executable.
    captured = []
    monkeypatch.setattr(
        computer.capture, "run_capture_command",
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
        computer.capture, "run_capture_command",
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


def test_win31_program_arguments_reach_the_launch_command(launcher, monkeypatch):
    received = []

    def get_win31_launch_command(options, start_program = None, start_args = None, start_letter = "c", start_offset = None, fullscreen = False):
        received.append(start_args)
        return ["dosbox", "win31"]

    monkeypatch.setattr(computer.command, "get_win31_launch_command", get_win31_launch_command)

    assert program(exe = "GAME.EXE", cwd = "GAME", args = ["/S"], is_win31 = True).run(FakeOptions(), TOKEN_MAP) is True
    assert received == [["/S"]]


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


###########################################################
# Running as an installer
#
# A setup program that cannot run stops the setup. Wine and old installers
# often exit non-zero after installing correctly, so a non-zero exit only
# warns unless the entry sets check_exit_code, and a resolution that cannot be
# restored afterwards never fails the install.
###########################################################

@pytest.fixture
def installer(monkeypatch, tmp_path):
    state = {"code": 0, "restore": True, "runs": [], "restores": [], "warnings": [], "errors": []}
    (tmp_path / "drive_c" / "Game").mkdir(parents = True)
    (tmp_path / "drive_c" / "Game" / "SETUP.EXE").write_text("")

    def run_returncode_command(cmd, options = None, verbose = False, pretend_run = False, exit_on_failure = False):
        state["runs"].append({"cmd": cmd, "options": options, "verbose": verbose,
                              "pretend_run": pretend_run, "exit_on_failure": exit_on_failure})
        return state["code"]

    def restore_default_screen_resolution(verbose = False, pretend_run = False, exit_on_failure = False):
        state["restores"].append(exit_on_failure)
        return state["restore"]

    monkeypatch.setattr(computer.command, "run_returncode_command", run_returncode_command)
    monkeypatch.setattr(computer.display, "restore_default_screen_resolution", restore_default_screen_resolution)
    monkeypatch.setattr(computer.logger, "log_warning", state["warnings"].append)
    monkeypatch.setattr(
        computer.logger, "log_error",
        lambda message, quit_program = False: state["errors"].append((message, quit_program)))
    monkeypatch.setattr(
        computer.programs, "get_emulator_program", lambda name: "/tools/" + name)
    monkeypatch.setattr(
        computer.command, "get_dos_launch_command", lambda **kwargs: ["dosbox", "dos"])
    options = FakeOptions()
    options.get_prefix_c_drive_real = lambda: str(tmp_path / "drive_c")
    state["options"] = options
    return state


def test_an_installer_that_exits_cleanly_succeeds(installer):
    entry = program(exe = "setup.exe", cwd = "Game", args = ["/S"])

    assert entry.run_setup(installer["options"], {}) is True
    assert installer["runs"][0]["cmd"][1:] == ["/S"]
    assert installer["warnings"] == []


def test_an_installer_that_cannot_be_found_is_not_started(installer):
    entry = program(exe = "missing.exe", cwd = "Game")

    assert entry.run_setup(installer["options"], {}, exit_on_failure = True) is False
    assert installer["runs"] == []
    assert installer["errors"][0][1] is True


def test_a_pretend_run_does_not_need_the_installer(installer):
    entry = program(exe = "missing.exe", cwd = "Game")

    assert entry.run_setup(installer["options"], {}, pretend_run = True) is True
    assert installer["runs"][0]["pretend_run"] is True


def test_an_installer_with_nothing_to_run_is_refused(installer):
    assert computer.Program().run_setup(installer["options"], {}) is False
    assert installer["runs"] == []


def test_a_non_zero_exit_is_tolerated_with_a_warning(installer):
    installer["code"] = 1

    assert program(exe = "setup.exe", cwd = "Game").run_setup(installer["options"], {}) is True
    assert "code 1" in installer["warnings"][0]
    assert installer["errors"] == []


def test_a_strict_installer_fails_on_a_non_zero_exit(installer):
    installer["code"] = 2
    entry = program(exe = "setup.exe", cwd = "Game", check_exit_code = True)

    assert entry.should_check_exit_code() is True
    assert entry.run_setup(installer["options"], {}, exit_on_failure = True) is False
    assert installer["errors"] == [(installer["errors"][0][0], True)]
    assert "code 2" in installer["errors"][0][0]
    assert installer["restores"] == []


def test_an_unrestored_resolution_does_not_fail_the_install(installer):
    installer["restore"] = False

    assert program(exe = "setup.exe", cwd = "Game").run_setup(installer["options"], {}, exit_on_failure = True) is True
    assert installer["restores"] == [False]
    assert installer["warnings"]


def test_an_emulated_installer_is_not_looked_up_on_the_windows_drive(installer):
    entry = program(exe = "INSTALL.EXE", cwd = "GAME", is_dos = True)

    assert entry.run_setup(installer["options"], {}) is True
    assert installer["runs"][0]["cmd"] == ["dosbox", "dos"]


def test_installer_exit_codes_are_tolerated_by_default():
    assert computer.Program().should_check_exit_code() is False
