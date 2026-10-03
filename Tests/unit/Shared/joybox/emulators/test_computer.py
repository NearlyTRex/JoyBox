# Imports
import pytest

# Local imports
from joybox import config
from joybox.emulators import computer


###########################################################
# Computer
#
# Windows downloads DosBoxX and ScummVM releases, Linux builds both as
# AppImages from source. Configure writes their config files, and launch hands
# off to the computer game launcher, which owns saves and sandboxing.
###########################################################

PROGRAMS = ["DosBoxX", "ScummVM"]
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
    installed = {(name, platform) for name in PROGRAMS for platform in PLATFORMS}
    monkeypatch.setattr(computer.programs, "should_program_be_installed",
        lambda name, platform: (name, platform) in installed)
    monkeypatch.setattr(computer.programs, "get_program_install_dir",
        lambda name, platform: "/install/%s/%s" % (name, platform))
    monkeypatch.setattr(computer.programs, "get_program_backup_dir",
        lambda name, platform: "/backup/%s/%s" % (name, platform))
    return installed


@pytest.fixture
def online(monkeypatch, program_paths):
    # One fake for every source so calls stay in order across platforms
    fake = Release()
    monkeypatch.setattr(computer.release, "download_github_release", fake)
    monkeypatch.setattr(computer.release, "download_webpage_release", fake)
    monkeypatch.setattr(computer.release, "build_appimage_from_source", fake)
    return fake


@pytest.fixture
def stored(monkeypatch, program_paths):
    fake = Release()
    monkeypatch.setattr(computer.release, "setup_stored_release", fake)
    return fake


def test_identity():
    emulator = computer.Computer()

    assert emulator.get_name() == "Computer"
    assert config.Platform.COMPUTER_STEAM in emulator.get_platforms()
    assert all(str(platform).startswith("Computer") for platform in emulator.get_platforms())
    assert set(emulator.get_config()) == set(PROGRAMS)


def test_every_program_runs_unsandboxed():
    for entry in computer.Computer().get_config().values():
        assert entry["run_sandboxed"] == {"windows": False, "linux": False}


def test_the_config_files_match_the_configured_paths():
    configured = set()
    for entry in computer.Computer().get_config().values():
        for key in ("config_file", "config_file_win31"):
            configured |= set(entry.get(key, {}).values())

    assert configured == set(computer.config_files)


@pytest.mark.parametrize("is_windows,save_type", [
    (True, config.SaveType.SANDBOXIE),
    (False, config.SaveType.WINE),
])
def test_the_save_type_follows_the_host(monkeypatch, is_windows, save_type):
    monkeypatch.setattr(computer.platform_info, "is_windows_platform", lambda: is_windows)

    assert computer.Computer().get_save_type() == save_type


def test_there_is_no_single_config_or_save_location():
    emulator = computer.Computer()

    for platform in [None] + PLATFORMS:
        assert emulator.get_config_file(platform) is None
        assert emulator.get_save_base_dir(platform) is None
        assert emulator.get_save_sub_dirs(platform) is None
        assert emulator.get_save_dir(platform) is None


###########################################################
# Setup
###########################################################

def test_setup_installs_both_programs_for_each_platform(online):
    assert computer.Computer().setup() is True

    assert [(c["install_name"], c["install_dir"], c["backups_dir"]) for c in online.calls] == [
        ("DosBoxX", "/install/DosBoxX/windows", "/backup/DosBoxX/windows"),
        ("ScummVM", "/install/ScummVM/windows", "/backup/ScummVM/windows"),
        ("DosBoxX", "/install/DosBoxX/linux", "/backup/DosBoxX/linux"),
        ("ScummVM", "/install/ScummVM/linux", "/backup/ScummVM/linux"),
    ]
    assert [c.get("search_file") for c in online.calls[:2]] == ["dosbox-x.exe", "scummvm.exe"]
    assert [c["output_file"] for c in online.calls[2:]] == [
        "DOSBox-X-x86_64.AppImage", "ScummVM-x86_64.AppImage"]


def test_the_linux_builds_link_their_binary_as_the_apprun(online):
    computer.Computer().setup()

    for call in online.calls[2:]:
        (symlink,) = call["internal_symlinks"]
        assert symlink["to"] == "AppRun"
        assert any(copy["to"] == "AppImage/" + symlink["from"] for copy in call["internal_copies"])


def test_setup_passes_the_setup_params_through(online):
    params = config.SetupParams(locker_type = "local", verbose = True, pretend_run = True, exit_on_failure = True)

    computer.Computer().setup(params)

    for call in online.calls:
        assert (call["locker_type"], call["verbose"], call["pretend_run"], call["exit_on_failure"]) == (
            "local", True, True, True)


@pytest.mark.parametrize("wanted", PROGRAMS)
def test_setup_skips_programs_that_are_not_wanted(online, program_paths, wanted):
    program_paths.clear()
    program_paths.add((wanted, "linux"))

    assert computer.Computer().setup() is True
    assert [(c["install_name"], c["install_dir"]) for c in online.calls] == [
        (wanted, "/install/%s/linux" % wanted)]


@pytest.mark.parametrize("failing_call", [1, 2, 3, 4])
def test_setup_stops_at_the_first_failure(online, failing_call):
    online.failures.add(failing_call)

    assert computer.Computer().setup() is False
    assert len(online.calls) == failing_call


def test_setup_offline_restores_both_programs_for_each_platform(stored):
    assert computer.Computer().setup_offline() is True

    assert [(c["archive_dir"], c["install_dir"], c.get("search_file")) for c in stored.calls] == [
        ("/backup/DosBoxX/windows", "/install/DosBoxX/windows", "dosbox-x.exe"),
        ("/backup/ScummVM/windows", "/install/ScummVM/windows", "scummvm.exe"),
        ("/backup/DosBoxX/linux", "/install/DosBoxX/linux", None),
        ("/backup/ScummVM/linux", "/install/ScummVM/linux", None),
    ]


def test_setup_offline_passes_the_setup_params_through(stored):
    computer.Computer().setup_offline(config.SetupParams(verbose = True, pretend_run = True, exit_on_failure = True))

    for call in stored.calls:
        assert (call["verbose"], call["pretend_run"], call["exit_on_failure"]) == (True, True, True)


def test_setup_offline_skips_programs_that_are_not_wanted(stored, program_paths):
    program_paths.clear()

    assert computer.Computer().setup_offline() is True
    assert stored.calls == []


@pytest.mark.parametrize("failing_call", [1, 2, 3, 4])
def test_setup_offline_stops_at_the_first_failure(stored, failing_call):
    stored.failures.add(failing_call)

    assert computer.Computer().setup_offline() is False
    assert len(stored.calls) == failing_call


###########################################################
# Configure
###########################################################

@pytest.fixture
def touched(monkeypatch):
    calls = []
    state = {"ok": True}

    def touch(src, contents, **kwargs):
        calls.append((src, contents, kwargs))
        return state["ok"]

    monkeypatch.setattr(computer.environment, "get_emulators_root_dir", lambda: "/emulators")
    monkeypatch.setattr(computer.fileops, "touch_file", touch)
    return {"calls": calls, "state": state}


def test_configure_writes_every_config_file_stripped(touched):
    assert computer.Computer().configure() is True

    assert [src for src, _, _ in touched["calls"]] == ["/emulators/%s" % name for name in computer.config_files]
    for (_, contents, _), expected in zip(touched["calls"], computer.config_files.values(), strict = True):
        assert contents == expected.strip()


def test_the_win31_config_keeps_the_dosbox_section_first(touched):
    computer.Computer().configure()

    win31 = [contents for src, contents, _ in touched["calls"] if src.endswith("dosbox-x.win31.conf")]
    assert len(win31) == 2
    assert all(contents.startswith("[dosbox]") and "memsize = 256" in contents for contents in win31)


def test_configure_passes_the_setup_params_through(touched):
    computer.Computer().configure(config.SetupParams(verbose = True, pretend_run = True, exit_on_failure = True))

    for _, _, kwargs in touched["calls"]:
        assert kwargs == {"verbose": True, "pretend_run": True, "exit_on_failure": True}


def test_configure_stops_when_a_config_file_cannot_be_written(touched):
    touched["state"]["ok"] = False

    assert computer.Computer().configure() is False
    assert len(touched["calls"]) == 1


###########################################################
# Launch
###########################################################

def test_launch_hands_off_to_the_computer_launcher(monkeypatch):
    launched = {}

    def launch_computer_game(**kwargs):
        launched.update(kwargs)
        return True

    monkeypatch.setattr(computer.computer, "launch_computer_game", launch_computer_game)
    game = object()

    assert computer.Computer().launch(
        game, capture_type = "video", capture_file = "/cap.mp4", fullscreen = True,
        verbose = True, pretend_run = True, exit_on_failure = True) is True
    assert launched == {
        "game_info": game, "capture_type": "video", "capture_file": "/cap.mp4", "fullscreen": True,
        "verbose": True, "pretend_run": True, "exit_on_failure": True}
