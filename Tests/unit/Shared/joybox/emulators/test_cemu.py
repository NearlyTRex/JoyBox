# Imports
import pytest

# Local imports
from joybox import config
from joybox.emulators import cemu


###########################################################
# Cemu
#
# Setup downloads (or restores) a release per platform, configure writes empty
# settings and keys files, add-ons are installed as NUS packages into the
# emulated NAND, and launch merges any bundled keys before starting the game.
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
    monkeypatch.setattr(cemu.programs, "should_program_be_installed",
        lambda name, platform: platform in installed)
    monkeypatch.setattr(cemu.programs, "get_program_install_dir",
        lambda name, platform: "/install/%s/%s" % (name, platform))
    monkeypatch.setattr(cemu.programs, "get_program_backup_dir",
        lambda name, platform: "/backup/%s/%s" % (name, platform))
    monkeypatch.setattr(cemu.programs, "get_emulator_path_config_value",
        lambda name, key, platform = None: "/emu/%s/%s/%s" % (name, key, platform))
    return installed


@pytest.fixture
def download(monkeypatch, program_paths):
    fake = Release()
    monkeypatch.setattr(cemu.release, "download_github_release", fake)
    return fake


@pytest.fixture
def stored(monkeypatch, program_paths):
    fake = Release()
    monkeypatch.setattr(cemu.release, "setup_stored_release", fake)
    return fake


def test_identity():
    emulator = cemu.Cemu()

    assert emulator.get_name() == "Cemu"
    assert emulator.get_platforms() == [
        config.Platform.NINTENDO_WII_U, config.Platform.NINTENDO_WII_U_ESHOP]
    assert set(emulator.get_config()["Cemu"]) >= {"program", "save_dir", "setup_dir", "config_file", "keys_file"}


def test_the_config_files_match_the_configured_paths():
    entry = cemu.Cemu().get_config()["Cemu"]
    configured = {entry[key][platform] for key in ("config_file", "keys_file") for platform in PLATFORMS}

    assert configured == set(cemu.config_files)


def test_saves_live_inside_the_setup_dir():
    entry = cemu.Cemu().get_config()["Cemu"]

    for platform in PLATFORMS:
        assert entry["save_dir"][platform].startswith(entry["setup_dir"][platform] + "/mlc01/")


###########################################################
# Setup
###########################################################

def test_setup_downloads_a_release_for_each_platform(download):
    assert cemu.Cemu().setup() is True

    assert [(c["ends_with"], c["install_dir"], c["backups_dir"]) for c in download.calls] == [
        ("windows-x64.zip", "/install/Cemu/windows", "/backup/Cemu/windows"),
        (".AppImage", "/install/Cemu/linux", "/backup/Cemu/linux"),
    ]
    assert download.calls[0]["search_file"] == "Cemu.exe"
    assert {(c["github_user"], c["github_repo"]) for c in download.calls} == {("cemu-project", "Cemu")}


def test_setup_passes_the_setup_params_through(download):
    params = config.SetupParams(locker_type = "local", verbose = True, pretend_run = True, exit_on_failure = True)

    cemu.Cemu().setup(params)

    for call in download.calls:
        assert (call["locker_type"], call["verbose"], call["pretend_run"], call["exit_on_failure"]) == (
            "local", True, True, True)


def test_setup_skips_platforms_that_are_not_wanted(download, program_paths):
    program_paths.clear()

    assert cemu.Cemu().setup() is True
    assert download.calls == []


@pytest.mark.parametrize("failing_call", [1, 2])
def test_setup_stops_at_the_first_failed_download(download, failing_call):
    download.failures.add(failing_call)

    assert cemu.Cemu().setup() is False
    assert len(download.calls) == failing_call


def test_setup_offline_restores_each_platform(stored):
    assert cemu.Cemu().setup_offline() is True

    assert [(c["archive_dir"], c["install_dir"]) for c in stored.calls] == [
        ("/backup/Cemu/windows", "/install/Cemu/windows"),
        ("/backup/Cemu/linux", "/install/Cemu/linux"),
    ]
    assert stored.calls[0]["search_file"] == "Cemu.exe"


def test_setup_offline_passes_the_setup_params_through(stored):
    cemu.Cemu().setup_offline(config.SetupParams(verbose = True, pretend_run = True, exit_on_failure = True))

    for call in stored.calls:
        assert (call["verbose"], call["pretend_run"], call["exit_on_failure"]) == (True, True, True)


def test_setup_offline_skips_platforms_that_are_not_wanted(stored, program_paths):
    program_paths.clear()

    assert cemu.Cemu().setup_offline() is True
    assert stored.calls == []


@pytest.mark.parametrize("failing_call", [1, 2])
def test_setup_offline_stops_at_the_first_failed_restore(stored, failing_call):
    stored.failures.add(failing_call)

    assert cemu.Cemu().setup_offline() is False
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

    monkeypatch.setattr(cemu.environment, "get_emulators_root_dir", lambda: "/emulators")
    monkeypatch.setattr(cemu.fileops, "touch_file", touch)
    return {"calls": calls, "state": state}


def test_configure_writes_every_config_file(touched):
    assert cemu.Cemu().configure() is True

    assert [src for src, _, _ in touched["calls"]] == ["/emulators/%s" % name for name in cemu.config_files]
    assert {contents for _, contents, _ in touched["calls"]} == {""}


def test_configure_passes_the_setup_params_through(touched):
    cemu.Cemu().configure(config.SetupParams(verbose = True, pretend_run = True, exit_on_failure = True))

    for _, _, kwargs in touched["calls"]:
        assert kwargs == {"verbose": True, "pretend_run": True, "exit_on_failure": True}


def test_configure_stops_when_a_config_file_cannot_be_written(touched):
    touched["state"]["ok"] = False

    assert cemu.Cemu().configure() is False
    assert len(touched["calls"]) == 1


###########################################################
# Add-ons
###########################################################

@pytest.fixture
def nus(monkeypatch, tmp_path):
    installed = []
    state = {"ok": True}

    def install(nus_package_dir, nand_dir, **kwargs):
        installed.append((nus_package_dir, nand_dir, kwargs))
        return state["ok"]

    monkeypatch.setattr(cemu.programs, "get_emulator_path_config_value",
        lambda name, key, platform = None: "/emu/%s/%s" % (name, key))
    monkeypatch.setattr(cemu.nintendo, "install_wiiu_nus_package", install)
    return {"installed": installed, "state": state, "root": tmp_path}


def make_package(root, *parts, ticket = "title.tik"):
    package = root.joinpath(*parts)
    package.mkdir(parents = True)
    (package / ticket).write_text("")
    return package


def test_install_addons_installs_each_ticketed_package_into_the_nand(nus):
    dlc = make_package(nus["root"], "dlc", "pack")
    update = make_package(nus["root"], "update", "v1")

    assert cemu.Cemu().install_addons(
        dlc_dirs = [str(nus["root"] / "dlc")], update_dirs = [str(nus["root"] / "update")],
        verbose = True, pretend_run = True, exit_on_failure = True) is True

    assert [(d, n) for d, n, _ in nus["installed"]] == [
        (str(dlc), "/emu/Cemu/setup_dir/mlc01"),
        (str(update), "/emu/Cemu/setup_dir/mlc01"),
    ]
    assert nus["installed"][0][2] == {"verbose": True, "pretend_run": True, "exit_on_failure": True}


def test_install_addons_ignores_tickets_that_are_not_title_tickets(nus):
    make_package(nus["root"], "dlc", "pack", ticket = "cetk.tik")

    assert cemu.Cemu().install_addons(dlc_dirs = [str(nus["root"] / "dlc")]) is True
    assert nus["installed"] == []


def test_install_addons_with_nothing_to_install_succeeds(nus):
    assert cemu.Cemu().install_addons() is True
    assert nus["installed"] == []


def test_install_addons_stops_at_the_first_failed_package(nus):
    make_package(nus["root"], "dlc", "pack")
    make_package(nus["root"], "update", "v1")
    nus["state"]["ok"] = False

    assert cemu.Cemu().install_addons(
        dlc_dirs = [str(nus["root"] / "dlc")], update_dirs = [str(nus["root"] / "update")]) is False
    assert len(nus["installed"]) == 1


###########################################################
# Launch
###########################################################

class Game:
    def __init__(self, cache_dir):
        self.cache_dir = cache_dir

    def get_local_cache_dir(self):
        return self.cache_dir


@pytest.fixture
def launcher(monkeypatch, tmp_path):
    launched = {}
    keys = []
    state = {"keys_result": True}

    def simple_launch(**kwargs):
        launched.update(kwargs)
        return True

    def update_keys(src_key_file, dest_key_file, **kwargs):
        keys.append((src_key_file, dest_key_file, kwargs))
        return state["keys_result"]

    monkeypatch.setattr(cemu.programs, "get_emulator_path_config_value",
        lambda name, key, platform = None: "/emu/%s/%s" % (key, platform))
    monkeypatch.setattr(cemu.programs, "get_emulator_program", lambda name: "/bin/cemu")
    monkeypatch.setattr(cemu.nintendo, "update_wiiu_keys", update_keys)
    monkeypatch.setattr(cemu.emulatorcommon, "simple_launch", simple_launch)
    return {"launched": launched, "keys": keys, "cache": tmp_path, "state": state}


def test_launch_runs_the_game_file(launcher):
    game = Game(str(launcher["cache"]))

    assert cemu.Cemu().launch(game, capture_type = "video", capture_file = "/cap.mp4", verbose = True) is True

    launched = launcher["launched"]
    assert launched["launch_cmd"] == ["/bin/cemu", "-g", config.token_game_file]
    assert launched["game_info"] is game
    assert (launched["capture_type"], launched["capture_file"], launched["verbose"]) == ("video", "/cap.mp4", True)
    assert launcher["keys"] == []


def test_launch_fullscreen_adds_the_fullscreen_flag(launcher):
    cemu.Cemu().launch(Game(str(launcher["cache"])), fullscreen = True)

    assert launcher["launched"]["launch_cmd"][-1] == "-f"


def test_launch_merges_bundled_keys_into_both_platforms(launcher):
    key_file = launcher["cache"] / "game.key.txt"
    key_file.write_text("")
    (launcher["cache"] / "readme.txt").write_text("")

    cemu.Cemu().launch(Game(str(launcher["cache"])), pretend_run = True)

    assert [(src, dest) for src, dest, _ in launcher["keys"]] == [
        (str(key_file), "/emu/keys_file/windows"),
        (str(key_file), "/emu/keys_file/linux"),
    ]
    assert launcher["keys"][0][2]["pretend_run"] is True


def test_launch_stops_when_the_keys_cannot_be_updated(launcher, monkeypatch):
    errors = []
    monkeypatch.setattr(cemu.logger, "log_error", lambda message, **kwargs: errors.append(message))
    key_file = launcher["cache"] / "game.key.txt"
    key_file.write_text("")
    launcher["state"]["keys_result"] = False

    assert cemu.Cemu().launch(Game(str(launcher["cache"]))) is False
    assert errors == ["Could not update Cemu keys from %s" % key_file]
    assert len(launcher["keys"]) == 1
    assert launcher["launched"] == {}
