# Imports
import pytest

# Local imports
from joybox import config
from joybox.emulators import retroarch


###########################################################
# RetroArch
#
# Setup downloads (or restores) the program and a cores archive per platform,
# configure writes config files and copies verified BIOS files, and launch
# picks the libretro core mapped to the game's platform.
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
    monkeypatch.setattr(retroarch.programs, "should_program_be_installed",
        lambda name, platform: platform in installed)
    monkeypatch.setattr(retroarch.programs, "get_program_install_dir",
        lambda name, platform: "/install/%s/%s" % (name, platform))
    monkeypatch.setattr(retroarch.programs, "get_program_backup_dir",
        lambda name, platform: "/backup/%s/%s" % (name, platform))
    monkeypatch.setattr(retroarch.programs, "get_emulator_path_config_value",
        lambda name, key, platform = None: "/emu/%s/%s/%s" % (name, key, platform))
    return installed


@pytest.fixture
def download(monkeypatch, program_paths):
    fake = Release()
    monkeypatch.setattr(retroarch.release, "download_general_release", fake)
    return fake


@pytest.fixture
def stored(monkeypatch, program_paths):
    fake = Release()
    monkeypatch.setattr(retroarch.release, "setup_stored_release", fake)
    return fake


def test_identity():
    emulator = retroarch.RetroArch()

    assert emulator.get_name() == "RetroArch"
    assert emulator.get_platforms() == [
        config.Platform.OTHER_PANASONIC_3DO, config.Platform.OTHER_SEGA_SATURN]
    assert set(emulator.get_config()["RetroArch"]["cores_mapping"]) == set(emulator.get_platforms())


###########################################################
# Setup
###########################################################

def test_setup_downloads_the_program_and_cores_for_each_platform(download):
    assert retroarch.RetroArch().setup() is True

    assert [(c["search_file"], c["install_dir"]) for c in download.calls] == [
        ("retroarch.exe", "/install/RetroArch/windows"),
        ("snes9x_libretro.dll", "/emu/RetroArch/cores_dir/windows"),
        ("RetroArch-Linux-x86_64.AppImage", "/install/RetroArch/linux"),
        ("snes9x_libretro.so", "/emu/RetroArch/cores_dir/linux"),
    ]


def test_setup_passes_the_setup_params_through(download):
    params = config.SetupParams(locker_type = "local", verbose = True, pretend_run = True, exit_on_failure = True)

    retroarch.RetroArch().setup(params)

    for call in download.calls:
        assert (call["locker_type"], call["verbose"], call["pretend_run"], call["exit_on_failure"]) == (
            "local", True, True, True)


def test_setup_skips_platforms_that_are_not_wanted(download, program_paths):
    program_paths.clear()

    assert retroarch.RetroArch().setup() is True
    assert download.calls == []


@pytest.mark.parametrize("failing_call", [1, 2, 3, 4])
def test_setup_stops_at_the_first_failed_download(download, failing_call):
    download.failures.add(failing_call)

    assert retroarch.RetroArch().setup() is False
    assert len(download.calls) == failing_call


def test_setup_offline_restores_the_program_and_cores_for_each_platform(stored):
    assert retroarch.RetroArch().setup_offline() is True

    assert [(c["preferred_archive"], c["install_dir"]) for c in stored.calls] == [
        ("RetroArch.7z", "/install/RetroArch/windows"),
        ("RetroArch_cores.7z", "/emu/RetroArch/cores_dir/windows"),
        ("RetroArch.7z", "/install/RetroArch/linux"),
        ("RetroArch_cores.7z", "/emu/RetroArch/cores_dir/linux"),
    ]
    assert {c["archive_dir"] for c in stored.calls} == {
        "/backup/RetroArch/windows", "/backup/RetroArch/linux"}


def test_setup_offline_skips_platforms_that_are_not_wanted(stored, program_paths):
    program_paths.clear()

    assert retroarch.RetroArch().setup_offline(config.SetupParams()) is True
    assert stored.calls == []


@pytest.mark.parametrize("failing_call", [1, 2, 3, 4])
def test_setup_offline_stops_at_the_first_failed_restore(stored, failing_call):
    stored.failures.add(failing_call)

    assert retroarch.RetroArch().setup_offline() is False
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
        self.hashes = dict(retroarch.system_files)
        monkeypatch.setattr(retroarch.environment, "get_emulators_root_dir", lambda: "/emulators")
        monkeypatch.setattr(retroarch.environment, "get_locker_gaming_emulator_setup_dir",
            lambda name: "/locker/%s" % name)
        monkeypatch.setattr(retroarch.programs, "get_emulator_path_config_value",
            lambda name, key, platform = None: "/emu/%s/%s" % (key, platform))
        monkeypatch.setattr(retroarch.fileops, "touch_file", self.touch)
        monkeypatch.setattr(retroarch.fileops, "smart_copy", self.copy)
        monkeypatch.setattr(retroarch.emulatorbase.hashing, "calculate_file_md5", self.md5)

    def touch(self, src, contents, **kwargs):
        self.touched.append(src)
        return self.touch_ok

    def copy(self, src, dest, **kwargs):
        self.copied.append((src, dest))
        return self.copy_ok

    def md5(self, src, pretend_run = False, **kwargs):
        if pretend_run:
            return ""
        return self.hashes[src.removeprefix("/locker/RetroArch/")]


@pytest.fixture
def configure(monkeypatch):
    return Configure(monkeypatch)


def test_configure_writes_configs_and_copies_system_files_to_each_platform(configure):
    assert retroarch.RetroArch().configure() is True

    assert configure.touched == ["/emulators/%s" % name for name in retroarch.config_files]
    assert len(configure.copied) == 2 * len(retroarch.system_files)
    assert configure.copied[:2] == [
        ("/locker/RetroArch/system/panafz1.bin", "/emu/setup_dir/windows/system/panafz1.bin"),
        ("/locker/RetroArch/system/panafz1.bin", "/emu/setup_dir/linux/system/panafz1.bin"),
    ]


def test_configure_fails_when_a_config_file_cannot_be_written(configure):
    configure.touch_ok = False

    assert retroarch.RetroArch().configure() is False
    assert len(configure.touched) == 1
    assert configure.copied == []


def test_configure_refuses_a_system_file_with_the_wrong_hash(configure):
    configure.hashes["system/goldstar.bin"] = "0" * 32

    assert retroarch.RetroArch().configure() is False
    assert configure.copied == []


def test_configure_fails_when_a_system_file_cannot_be_copied(configure):
    configure.copy_ok = False

    assert retroarch.RetroArch().configure() is False
    assert len(configure.copied) == 1


def test_a_pretend_configure_succeeds_without_real_hashes(configure):
    assert retroarch.RetroArch().configure(config.SetupParams(pretend_run = True)) is True
    assert len(configure.copied) == 2 * len(retroarch.system_files)


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
def launcher(monkeypatch, tmp_path):
    launched = {}
    popups = []
    cores_dir = tmp_path / "cores"
    cores_dir.mkdir()
    values = {
        "cores_ext": ".so",
        "cores_mapping": retroarch.RetroArch().get_config()["RetroArch"]["cores_mapping"],
    }

    def popup(title_text, message_text):
        popups.append(title_text)
        raise PopupQuit()

    def simple_launch(**kwargs):
        launched.update(kwargs)
        return True

    monkeypatch.setattr(retroarch.programs, "get_emulator_path_config_value",
        lambda name, key, platform = None: str(cores_dir))
    monkeypatch.setattr(retroarch.programs, "get_emulator_config_value",
        lambda name, key, platform = None: values[key])
    monkeypatch.setattr(retroarch.programs, "get_emulator_program", lambda name: "/bin/retroarch")
    monkeypatch.setattr(retroarch.gui, "display_error_popup", popup)
    monkeypatch.setattr(retroarch.emulatorcommon, "simple_launch", simple_launch)
    return {"launched": launched, "popups": popups, "cores_dir": cores_dir}


def install_core(launcher, name):
    core = launcher["cores_dir"] / (name + ".so")
    core.write_text("")
    return str(core)


def test_launch_loads_the_core_mapped_to_the_platform(launcher):
    core = install_core(launcher, "mednafen_saturn_libretro")
    game = Game(config.Platform.OTHER_SEGA_SATURN)

    assert retroarch.RetroArch().launch(game, capture_type = "video", capture_file = "/cap.mp4") is True

    launched = launcher["launched"]
    assert launched["launch_cmd"] == ["/bin/retroarch", "-L", core, config.token_game_file]
    assert launched["game_info"] is game
    assert (launched["capture_type"], launched["capture_file"]) == ("video", "/cap.mp4")


def test_launch_fullscreen_adds_the_fullscreen_flag(launcher):
    install_core(launcher, "opera_libretro")

    retroarch.RetroArch().launch(Game(config.Platform.OTHER_PANASONIC_3DO), fullscreen = True)

    assert launcher["launched"]["launch_cmd"][-1] == "-f"


def test_launch_rejects_an_unmapped_platform(launcher):
    with pytest.raises(PopupQuit):
        retroarch.RetroArch().launch(Game(config.Platform.OTHER_SEGA_CD))

    assert launcher["popups"] == ["Launch platform not defined"]
    assert launcher["launched"] == {}


def test_launch_rejects_a_missing_core(launcher):
    with pytest.raises(PopupQuit):
        retroarch.RetroArch().launch(Game(config.Platform.OTHER_SEGA_SATURN))

    assert launcher["popups"] == ["RetroArch core not found"]
    assert launcher["launched"] == {}
