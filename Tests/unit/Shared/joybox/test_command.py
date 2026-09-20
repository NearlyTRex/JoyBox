# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import command, config


###########################################################
# Command preparation
#
# Every command is rewritten before it runs: wrapped for powershell, pointed
# at a private home directory for an appimage, or routed through a prefix.
# What comes out of that rewrite is what actually executes.
###########################################################

def options_with_prefix(tmp_path):
    options = command.create_command_options()
    options.set_prefix_c_drive_real(str(tmp_path))
    return options


###########################################################
# Powershell
###########################################################

def test_a_plain_command_is_wrapped_for_powershell():
    new_cmd, _ = command.setup_powershell_command(["Get-Process"])

    assert new_cmd == ["powershell", "-NoProfile", "-Command", "Get-Process"]


def test_the_profile_is_not_loaded():
    # A developer's own profile changes what the command sees.
    new_cmd, _ = command.setup_powershell_command(["Get-Process"])

    assert "-NoProfile" in new_cmd


def test_a_command_that_already_calls_powershell_is_not_wrapped_twice():
    new_cmd, _ = command.setup_powershell_command(["powershell", "-Command", "Get-Process"])

    assert new_cmd == ["powershell", "-Command", "Get-Process"]


def test_a_powershell_executable_is_recognised():
    new_cmd, _ = command.setup_powershell_command([r"C:\Windows\powershell.exe", "-Command", "x"])

    assert new_cmd[0] == r"C:\Windows\powershell.exe"


def test_a_string_command_is_split_into_a_list():
    new_cmd, _ = command.setup_powershell_command("Get-Process -Name x")

    assert new_cmd == ["powershell", "-NoProfile", "-Command", "Get-Process", "-Name", "x"]


def test_preparing_for_powershell_leaves_the_original_options_alone():
    options = command.create_command_options()

    _, new_options = command.setup_powershell_command(["Get-Process"], options = options)

    assert new_options is not options


###########################################################
# AppImages
###########################################################

def test_an_appimage_with_a_home_directory_gets_its_own_config_paths(tmp_path):
    # An AppImage otherwise writes into the real ~/.config, which is the whole
    # reason the sidecar home directory exists.
    appimage = tmp_path / "Tool.AppImage"
    appimage.write_text("")
    home = tmp_path / "Tool.AppImage.home"
    home.mkdir()

    _, new_options = command.setup_appimage_command([str(appimage)])

    assert new_options.get_env_var("XDG_CONFIG_HOME") == str(home / ".config")
    assert new_options.get_env_var("XDG_CACHE_HOME") == str(home / ".cache")
    assert new_options.get_env_var("XDG_DATA_HOME") == str(home / ".local" / "share")
    assert new_options.get_env_var("XDG_STATE_HOME") == str(home / ".local" / "state")


def test_an_appimage_without_a_home_directory_is_left_alone(tmp_path):
    appimage = tmp_path / "Tool.AppImage"
    appimage.write_text("")

    _, new_options = command.setup_appimage_command([str(appimage)])

    assert new_options.get_env_var("XDG_CONFIG_HOME") is None


def test_an_appimage_is_recognised_whatever_its_case(tmp_path):
    appimage = tmp_path / "Tool.appimage"
    appimage.write_text("")
    home = tmp_path / "Tool.appimage.home"
    home.mkdir()

    _, new_options = command.setup_appimage_command([str(appimage)])

    assert new_options.get_env_var("XDG_CONFIG_HOME") == str(home / ".config")


def test_an_appimage_named_later_in_the_command_is_found(tmp_path):
    appimage = tmp_path / "Tool.AppImage"
    appimage.write_text("")
    home = tmp_path / "Tool.AppImage.home"
    home.mkdir()

    _, new_options = command.setup_appimage_command(["/usr/bin/env", str(appimage), "--flag"])

    assert new_options.get_env_var("XDG_CONFIG_HOME") == str(home / ".config")


def test_the_command_itself_is_unchanged_for_an_appimage(tmp_path):
    appimage = tmp_path / "Tool.AppImage"
    appimage.write_text("")

    new_cmd, _ = command.setup_appimage_command([str(appimage), "--flag"])

    assert new_cmd == [str(appimage), "--flag"]


###########################################################
# Preprocessing
###########################################################

def test_a_powershell_command_is_preprocessed_for_powershell():
    new_cmd, _ = command.preprocess_command(["powershell.exe", "-Command", "x"])

    assert new_cmd[0] == "powershell.exe"


def test_an_ordinary_command_is_left_as_it_is():
    new_cmd, _ = command.preprocess_command(["/usr/bin/true"])

    assert new_cmd == ["/usr/bin/true"]


def test_powershell_can_be_forced_onto_an_ordinary_command():
    options = command.create_command_options(force_powershell = True)

    new_cmd, _ = command.preprocess_command(["Get-Process"], options = options)

    assert new_cmd[:3] == ["powershell", "-NoProfile", "-Command"]


def test_appimage_handling_can_be_forced(tmp_path):
    target = tmp_path / "Tool.AppImage"
    target.write_text("")
    (tmp_path / "Tool.AppImage.home").mkdir()
    options = command.create_command_options(force_appimage = True)

    _, new_options = command.preprocess_command([str(target)], options = options)

    assert new_options.get_env_var("XDG_CONFIG_HOME") is not None


def test_a_prefix_command_is_routed_through_the_sandbox(monkeypatch):
    seen = {}

    def setup_prefix_command(cmd, options, **kwargs):
        seen["cmd"] = cmd
        return (["wine"] + cmd, options)

    monkeypatch.setattr(command.sandbox, "should_be_run_via_wine", lambda cmd: True)
    monkeypatch.setattr(command, "setup_prefix_command", setup_prefix_command)

    new_cmd, _ = command.preprocess_command(["/games/Game.exe"])

    assert new_cmd == ["wine", "/games/Game.exe"]


def test_a_native_command_is_not_routed_through_the_sandbox(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("a native command needs no prefix")

    monkeypatch.setattr(command.sandbox, "should_be_run_via_wine", lambda cmd: False)
    monkeypatch.setattr(command.sandbox, "should_be_run_via_sandboxie", lambda cmd: False)
    monkeypatch.setattr(command, "setup_prefix_command", fail)

    command.preprocess_command(["/usr/bin/true"])


###########################################################
# Postprocessing
###########################################################

def test_a_wine_command_is_cleaned_up_afterwards(monkeypatch):
    cleaned = []
    monkeypatch.setattr(command.sandbox, "should_be_run_via_wine", lambda cmd: True)
    monkeypatch.setattr(command.sandbox, "should_be_run_via_sandboxie", lambda cmd: False)
    monkeypatch.setattr(command.sandbox, "cleanup_wine", lambda **kwargs: cleaned.append("wine"))

    command.postprocess_command(["/games/Game.exe"])

    assert cleaned == ["wine"]


def test_a_sandboxie_command_is_cleaned_up_afterwards(monkeypatch):
    cleaned = []
    monkeypatch.setattr(command.sandbox, "should_be_run_via_wine", lambda cmd: False)
    monkeypatch.setattr(command.sandbox, "should_be_run_via_sandboxie", lambda cmd: True)
    monkeypatch.setattr(command.sandbox, "cleanup_sandboxie", lambda **kwargs: cleaned.append("sandboxie"))

    command.postprocess_command(["/games/Game.exe"])

    assert cleaned == ["sandboxie"]


def test_a_native_command_needs_no_cleanup(monkeypatch):
    def fail(**kwargs):
        raise AssertionError("a native command was never sandboxed")

    monkeypatch.setattr(command.sandbox, "should_be_run_via_wine", lambda cmd: False)
    monkeypatch.setattr(command.sandbox, "should_be_run_via_sandboxie", lambda cmd: False)
    monkeypatch.setattr(command.sandbox, "cleanup_wine", fail)
    monkeypatch.setattr(command.sandbox, "cleanup_sandboxie", fail)

    command.postprocess_command(["/usr/bin/true"])


def test_every_output_path_is_transferred_out_of_the_sandbox(monkeypatch):
    # Anything the command wrote inside the prefix is lost unless it is copied
    # back out afterwards.
    transferred = []
    monkeypatch.setattr(command.sandbox, "should_be_run_via_wine", lambda cmd: False)
    monkeypatch.setattr(command.sandbox, "should_be_run_via_sandboxie", lambda cmd: False)
    monkeypatch.setattr(
        command.sandbox, "transfer_from_sandbox",
        lambda path, **kwargs: transferred.append(path))
    options = command.create_command_options(output_paths = ["/out/one", "/out/two"])

    command.postprocess_command(["/games/Game.exe"], options = options)

    assert transferred == ["/out/one", "/out/two"]


###########################################################
# DOS launch commands
###########################################################

@pytest.fixture
def dosbox(monkeypatch):
    monkeypatch.setattr(command.programs, "get_emulator_program", lambda name: "/emus/dosbox-x")
    monkeypatch.setattr(
        command.programs, "get_emulator_path_config_value",
        lambda name, key: "/emus/%s.conf" % key)


@pytest.fixture
def no_discs(monkeypatch):
    monkeypatch.setattr(command.paths, "build_file_list_by_extensions", lambda root, extensions = []: [])


def test_a_dos_launch_uses_its_own_config(dosbox, no_discs, tmp_path):
    # DOSBox-X reads its machine setup from the config file, and the Windows
    # 3.1 profile is a different file entirely.
    cmd = command.get_dos_launch_command(options_with_prefix(tmp_path))

    assert cmd[0] == "/emus/dosbox-x"
    assert "/emus/config_file.conf" in cmd


def test_a_win31_launch_uses_the_windows_config(dosbox, no_discs, tmp_path):
    cmd = command.get_win31_launch_command(options_with_prefix(tmp_path))

    assert "/emus/config_file_win31.conf" in cmd


@pytest.mark.parametrize("builder", [
    command.get_dos_launch_command,
    command.get_win31_launch_command,
])
def test_the_c_drive_is_mounted(dosbox, no_discs, tmp_path, builder):
    cmd = builder(options_with_prefix(tmp_path))
    expected = os.path.join(str(tmp_path), config.computer_folder_dos, "C")

    assert 'mount c "%s"' % expected in cmd


@pytest.mark.parametrize("builder", [
    command.get_dos_launch_command,
    command.get_win31_launch_command,
])
def test_each_disc_image_is_mounted_on_its_own_drive(dosbox, monkeypatch, tmp_path, builder):
    # A second image mounted on the same letter replaces the first.
    monkeypatch.setattr(
        command.paths, "build_file_list_by_extensions",
        lambda root, extensions = []: ["/discs/one.chd", "/discs/two.chd"])

    cmd = builder(options_with_prefix(tmp_path))

    assert 'imgmount d "/discs/one.chd" -t iso' in cmd
    assert 'imgmount e "/discs/two.chd" -t iso' in cmd


@pytest.mark.parametrize("builder", [
    command.get_dos_launch_command,
    command.get_win31_launch_command,
])
def test_the_start_drive_is_selected(dosbox, no_discs, tmp_path, builder):
    cmd = builder(options_with_prefix(tmp_path), start_letter = "d")

    assert "d:" in cmd


@pytest.mark.parametrize("builder", [
    command.get_dos_launch_command,
    command.get_win31_launch_command,
])
def test_the_start_offset_is_entered(dosbox, no_discs, tmp_path, builder):
    cmd = builder(options_with_prefix(tmp_path), start_offset = "GAMES\\DOOM")

    assert "cd GAMES\\DOOM" in cmd


def test_a_dos_program_is_launched_by_its_filename(dosbox, no_discs, tmp_path):
    # The mount has already made the directory current, so a full host path
    # means nothing inside the emulator.
    cmd = command.get_dos_launch_command(
        options_with_prefix(tmp_path), start_program = "/host/games/DOOM.EXE")

    assert "DOOM.EXE" in cmd
    assert "/host/games/DOOM.EXE" not in cmd


def test_dos_program_arguments_follow_the_program(dosbox, no_discs, tmp_path):
    cmd = command.get_dos_launch_command(
        options_with_prefix(tmp_path),
        start_program = "/host/games/DOOM.EXE",
        start_args = ["-warp", "1"])

    assert "DOOM.EXE -warp 1" in cmd


def test_a_win31_program_is_launched_through_windows(dosbox, no_discs, tmp_path):
    cmd = command.get_win31_launch_command(
        options_with_prefix(tmp_path), start_program = "/host/games/GAME.EXE")

    assert "WIN RUNEXIT GAME.EXE" in cmd


def test_a_win31_launch_exits_when_the_program_does(dosbox, no_discs, tmp_path):
    # Without the exit the emulator sits at a DOS prompt after the game ends.
    cmd = command.get_win31_launch_command(
        options_with_prefix(tmp_path), start_program = "/host/games/GAME.EXE")

    assert "EXIT" in cmd


def test_a_win31_launch_without_a_program_does_not_exit(dosbox, no_discs, tmp_path):
    cmd = command.get_win31_launch_command(options_with_prefix(tmp_path))

    assert "EXIT" not in cmd


def test_a_win31_launch_sets_up_the_windows_environment(dosbox, no_discs, tmp_path):
    cmd = command.get_win31_launch_command(options_with_prefix(tmp_path))

    assert r"SET PATH=%PATH%;C:\WINDOWS;" in cmd
    assert r"SET TEMP=C:\WINDOWS\TEMP" in cmd


@pytest.mark.parametrize("builder", [
    command.get_dos_launch_command,
    command.get_win31_launch_command,
])
def test_fullscreen_is_only_requested_when_asked(dosbox, no_discs, tmp_path, builder):
    assert "-fullscreen" not in builder(options_with_prefix(tmp_path))
    assert "-fullscreen" in builder(options_with_prefix(tmp_path), fullscreen = True)


###########################################################
# ScummVM launch commands
###########################################################

@pytest.fixture
def scummvm(monkeypatch):
    monkeypatch.setattr(command.programs, "get_emulator_program", lambda name: "/emus/scummvm")


def test_a_scumm_launch_points_at_the_game_directory(scummvm, tmp_path):
    cmd = command.get_scumm_launch_command(options_with_prefix(tmp_path))
    expected = os.path.join(str(tmp_path), config.computer_folder_scumm)

    assert cmd[0] == "/emus/scummvm"
    assert "--path=%s" % expected in cmd


def test_a_scumm_launch_detects_the_game(scummvm, tmp_path):
    # The collection stores game data without a ScummVM game id.
    cmd = command.get_scumm_launch_command(options_with_prefix(tmp_path))

    assert "--auto-detect" in cmd


def test_a_scumm_launch_keeps_saves_with_the_profile(scummvm, tmp_path):
    cmd = command.get_scumm_launch_command(options_with_prefix(tmp_path))

    assert any(part.startswith("--savepath=") for part in cmd)


def test_a_scumm_launch_is_windowed_unless_asked(scummvm, tmp_path):
    assert "--fullscreen" not in command.get_scumm_launch_command(options_with_prefix(tmp_path))
    assert "--fullscreen" in command.get_scumm_launch_command(
        options_with_prefix(tmp_path), fullscreen = True)
