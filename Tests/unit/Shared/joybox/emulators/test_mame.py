# Imports
import pytest

# Local imports
from joybox import config
from joybox.emulators import mame


###########################################################
# Mame
#
# Windows downloads a release, Linux builds an AppImage from source. Configure
# writes the ini files and copies verified BIOS zips; launch runs arcade sets
# by name from the game dir and everything else as a system driver plus media.
###########################################################

PLATFORMS = ["windows", "linux"]


class Release:
    def __init__(self):
        self.calls = []
        self.failures = set()

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        return len(self.calls) not in self.failures


@pytest.fixture
def program_paths(monkeypatch):
    installed = set(PLATFORMS)
    monkeypatch.setattr(mame.programs, "should_program_be_installed",
        lambda name, platform: platform in installed)
    monkeypatch.setattr(mame.programs, "get_program_install_dir",
        lambda name, platform: "/install/%s/%s" % (name, platform))
    monkeypatch.setattr(mame.programs, "get_program_backup_dir",
        lambda name, platform: "/backup/%s/%s" % (name, platform))
    return installed


@pytest.fixture
def online(monkeypatch, program_paths):
    # One fake for both so calls stay in order across platforms
    fake = Release()
    monkeypatch.setattr(mame.release, "download_github_release", fake)
    monkeypatch.setattr(mame.release, "build_appimage_from_source", fake)
    return fake


@pytest.fixture
def stored(monkeypatch, program_paths):
    fake = Release()
    monkeypatch.setattr(mame.release, "setup_stored_release", fake)
    return fake


def test_identity():
    emulator = mame.Mame()

    assert emulator.get_name() == "Mame"
    assert config.Platform.OTHER_ARCADE in emulator.get_platforms()
    assert set(mame.system_drivers) == set(emulator.get_platforms()) - {config.Platform.OTHER_ARCADE}
    assert emulator.get_config()["Mame"]["program"]["linux"] == "Mame/linux/Mame.AppImage"


###########################################################
# Setup
###########################################################

def test_setup_downloads_windows_and_builds_linux(online):
    params = config.SetupParams(locker_type = "local", verbose = True)

    assert mame.Mame().setup(params) is True

    windows, linux = online.calls
    assert (windows["github_repo"], windows["install_dir"]) == ("mame", "/install/Mame/windows")
    assert (linux["release_url"], linux["install_dir"]) == (
        "https://github.com/NearlyTRex/Mame.git", "/install/Mame/linux")
    assert {call["locker_type"] for call in online.calls} == {"local"}


def test_setup_skips_platforms_that_are_not_wanted(online, program_paths):
    program_paths.clear()

    assert mame.Mame().setup() is True
    assert online.calls == []


@pytest.mark.parametrize("failing_call", [1, 2])
def test_setup_stops_at_the_first_failure(online, failing_call):
    online.failures.add(failing_call)

    assert mame.Mame().setup() is False
    assert len(online.calls) == failing_call


def test_setup_offline_restores_each_platform(stored):
    assert mame.Mame().setup_offline() is True

    assert [(c["archive_dir"], c["install_dir"]) for c in stored.calls] == [
        ("/backup/Mame/windows", "/install/Mame/windows"),
        ("/backup/Mame/linux", "/install/Mame/linux"),
    ]


def test_setup_offline_skips_platforms_that_are_not_wanted(stored, program_paths):
    program_paths.clear()

    assert mame.Mame().setup_offline(config.SetupParams()) is True
    assert stored.calls == []


@pytest.mark.parametrize("failing_call", [1, 2])
def test_setup_offline_stops_at_the_first_failure(stored, failing_call):
    stored.failures.add(failing_call)

    assert mame.Mame().setup_offline() is False
    assert len(stored.calls) == failing_call


###########################################################
# Configure
###########################################################

class Configure:
    def __init__(self, monkeypatch):
        self.touched = []
        self.copied = []
        self.touch_ok = True
        self.copy_ok = True
        self.hashes = dict(mame.system_files)
        monkeypatch.setattr(mame.environment, "get_emulators_root_dir", lambda: "/emulators")
        monkeypatch.setattr(mame.environment, "get_locker_gaming_emulator_setup_dir",
            lambda name: "/locker/%s" % name)
        monkeypatch.setattr(mame.programs, "get_emulator_path_config_value",
            lambda name, key, platform = None: "/emu/%s/%s" % (key, platform))
        monkeypatch.setattr(mame.fileops, "touch_file", self.touch)
        monkeypatch.setattr(mame.fileops, "smart_copy", self.copy)
        monkeypatch.setattr(mame.emulatorbase.hashing, "calculate_file_md5", self.md5)

    def touch(self, src, contents, **kwargs):
        self.touched.append((src, contents))
        return self.touch_ok

    def copy(self, src, dest, **kwargs):
        self.copied.append((src, dest))
        return self.copy_ok

    def md5(self, src, pretend_run = False, **kwargs):
        if pretend_run:
            return ""
        return self.hashes[src.removeprefix("/locker/Mame/")]


@pytest.fixture
def configure(monkeypatch):
    return Configure(monkeypatch)


def test_configure_writes_inis_and_copies_system_files_to_each_platform(configure):
    assert mame.Mame().configure() is True

    assert [src for src, _ in configure.touched] == ["/emulators/%s" % name for name in mame.config_files]
    assert all(contents.startswith("#\n# CORE SEARCH PATH OPTIONS") for _, contents in configure.touched)
    assert len(configure.copied) == 2 * len(mame.system_files)
    assert configure.copied[:2] == [
        ("/locker/Mame/roms/cdimono1.zip", "/emu/setup_dir/windows/roms/cdimono1.zip"),
        ("/locker/Mame/roms/cdimono1.zip", "/emu/setup_dir/linux/roms/cdimono1.zip"),
    ]


def test_configure_fails_when_an_ini_cannot_be_written(configure):
    configure.touch_ok = False

    assert mame.Mame().configure() is False
    assert len(configure.touched) == 1
    assert configure.copied == []


def test_configure_refuses_a_system_file_with_the_wrong_hash(configure):
    configure.hashes["roms/intv.zip"] = "0" * 32

    assert mame.Mame().configure() is False
    assert configure.copied == []


def test_configure_fails_when_a_system_file_cannot_be_copied(configure):
    configure.copy_ok = False

    assert mame.Mame().configure() is False
    assert len(configure.copied) == 1


def test_a_pretend_configure_succeeds_without_real_hashes(configure):
    assert mame.Mame().configure(config.SetupParams(pretend_run = True)) is True
    assert len(configure.copied) == 2 * len(mame.system_files)


###########################################################
# Launch
###########################################################

class PopupQuit(Exception):
    pass


class Game:
    def __init__(self, platform):
        self.platform = platform

    def get_platform(self):
        return self.platform


@pytest.fixture
def launcher(monkeypatch):
    launched = {}
    popups = []

    def popup(title_text, message_text):
        popups.append(title_text)
        raise PopupQuit()

    def simple_launch(**kwargs):
        launched.update(kwargs)
        return True

    monkeypatch.setattr(mame.programs, "get_emulator_path_config_value",
        lambda name, key, platform = None: "/emu/%s" % key)
    monkeypatch.setattr(mame.programs, "get_emulator_program", lambda name: "/bin/mame")
    monkeypatch.setattr(mame.gui, "display_error_popup", popup)
    monkeypatch.setattr(mame.emulatorcommon, "simple_launch", simple_launch)
    return {"launched": launched, "popups": popups}


def test_an_arcade_set_runs_by_name_from_the_game_dir(launcher):
    game = Game(config.Platform.OTHER_ARCADE)

    assert mame.Mame().launch(game, capture_type = "video", capture_file = "/cap.mp4", fullscreen = True) is True

    launched = launcher["launched"]
    assert launched["launch_cmd"] == [
        "/bin/mame", "-inipath", "/emu/config_dir",
        "-rompath", config.token_game_dir, config.token_game_name]
    assert launched["game_info"] is game
    assert (launched["capture_type"], launched["capture_file"]) == ("video", "/cap.mp4")


@pytest.mark.parametrize("platform, system_name, media_flag", [
    (config.Platform.OTHER_ATARI_5200, "a5200", "-cart"),
    (config.Platform.OTHER_ATARI_7800, "a7800", "-cart"),
    (config.Platform.OTHER_MAGNAVOX_ODYSSEY_2, "odyssey2", "-cart"),
    (config.Platform.OTHER_MATTEL_INTELLIVISION, "intv", "-cart"),
    (config.Platform.OTHER_PHILIPS_CDI, "cdimono1", "-cdrom"),
    (config.Platform.OTHER_TEXAS_INSTRUMENTS_TI994A, "ti99_4a", "-cart"),
    (config.Platform.OTHER_TIGER_GAMECOM, "gamecom", "-cart1"),
])
def test_a_console_runs_its_system_driver_with_the_game_as_media(launcher, platform, system_name, media_flag):
    mame.Mame().launch(Game(platform), fullscreen = True)

    assert launcher["launched"]["launch_cmd"] == [
        "/bin/mame", "-inipath", "/emu/config_dir",
        "-rompath", "/emu/roms_dir", system_name, media_flag, config.token_game_file]


def test_a_windowed_launch_asks_mame_for_a_window(launcher):
    mame.Mame().launch(Game(config.Platform.OTHER_ARCADE))

    assert launcher["launched"]["launch_cmd"][-1] == "-window"


def test_launch_rejects_an_unsupported_platform(launcher):
    with pytest.raises(PopupQuit):
        mame.Mame().launch(Game(config.Platform.OTHER_SEGA_CD))

    assert launcher["popups"] == ["Launch platform not defined"]
    assert launcher["launched"] == {}
