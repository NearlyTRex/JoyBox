# Imports
import os
import pytest

# Local imports
from joybox.collection import installing


###########################################################
# Installing games
#
# Store games are handed to the store client; local games are unpacked from the
# locker into a cache. The dispatch decides which, and a store game routed down
# the local path looks for files that were never downloaded.
###########################################################

class FakeGameInfo:

    def __init__(self, platform = "Microsoft Windows", valid = True,
                 local_cache_dir = None, remote_cache_dir = None,
                 store_key = "steam", subvalues = None):
        self.platform = platform
        self.valid = valid
        self.local_cache_dir = local_cache_dir or "/cache/local"
        self.remote_cache_dir = remote_cache_dir or "/cache/remote"
        self.store_key = store_key
        self.subvalues = subvalues or {"appid": "12345"}

    def is_valid(self):
        return self.valid

    def get_platform(self):
        return self.platform

    def get_local_cache_dir(self):
        return self.local_cache_dir

    def get_remote_cache_dir(self):
        return self.remote_cache_dir

    def get_main_store_key(self):
        return self.store_key

    def get_subvalue(self, store_key, identifier_key):
        return self.subvalues.get(identifier_key)


class FakeStore:

    def __init__(self, handles_installing = True, installed = False, result = True):
        self.handles_installing = handles_installing
        self.installed = installed
        self.result = result
        self.installs = []
        self.uninstalls = []
        self.checks = []

    def can_handle_installing(self):
        return self.handles_installing

    def get_install_identifier_key(self):
        return "appid"

    def is_installed(self, identifier):
        self.checks.append(identifier)
        return self.installed

    def install(self, identifier, **kwargs):
        self.installs.append(identifier)
        return self.result

    def uninstall(self, identifier, **kwargs):
        self.uninstalls.append(identifier)
        return self.result


@pytest.fixture
def store(monkeypatch):
    holder = {"store": FakeStore(), "is_store": True}
    monkeypatch.setattr(
        installing.stores, "get_store_by_platform",
        lambda platform, **kwargs: holder["store"])
    monkeypatch.setattr(
        installing.stores, "is_store_platform", lambda platform: holder["is_store"])
    return holder


###########################################################
# Store games
###########################################################

def test_an_installed_store_game_is_reported_installed(store):
    store["store"] = FakeStore(installed = True)

    assert installing.is_store_game_installed(FakeGameInfo()) is True


def test_an_absent_store_game_is_reported_missing(store):
    store["store"] = FakeStore(installed = False)

    assert installing.is_store_game_installed(FakeGameInfo()) is False


def test_the_store_identifier_reaches_the_store(store):
    store["store"] = FakeStore()
    installing.is_store_game_installed(FakeGameInfo(subvalues = {"appid": "99999"}))

    assert store["store"].checks == ["99999"]


def test_an_invalid_game_is_not_installed(store):
    assert installing.is_store_game_installed(FakeGameInfo(valid = False)) is False


def test_a_missing_game_is_not_installed(store):
    assert installing.is_store_game_installed(None) is False


def test_a_platform_without_a_store_is_not_installed(monkeypatch):
    monkeypatch.setattr(
        installing.stores, "get_store_by_platform", lambda platform, **kwargs: None)

    assert installing.is_store_game_installed(FakeGameInfo()) is False


def test_a_store_that_cannot_install_reports_nothing_installed(store):
    # A store JoyBox cannot drive has no opinion about what is installed.
    store["store"] = FakeStore(handles_installing = False, installed = True)

    assert installing.is_store_game_installed(FakeGameInfo()) is False


def test_a_store_game_is_installed_through_its_store(store):
    store["store"] = FakeStore()

    assert installing.install_store_game(FakeGameInfo()) is True
    assert store["store"].installs == ["12345"]


def test_a_failed_store_install_is_reported(store):
    store["store"] = FakeStore(result = False)

    assert installing.install_store_game(FakeGameInfo()) is False


def test_an_invalid_game_is_not_installed_anywhere(store):
    store["store"] = FakeStore()

    assert installing.install_store_game(FakeGameInfo(valid = False)) is False
    assert store["store"].installs == []


def test_a_store_that_cannot_install_is_not_asked_to(store):
    store["store"] = FakeStore(handles_installing = False)

    assert installing.install_store_game(FakeGameInfo()) is False
    assert store["store"].installs == []


def test_a_store_game_is_uninstalled_through_its_store(store):
    store["store"] = FakeStore()

    assert installing.uninstall_store_game(FakeGameInfo()) is True
    assert store["store"].uninstalls == ["12345"]


def test_a_store_that_cannot_install_is_not_asked_to_uninstall(store):
    store["store"] = FakeStore(handles_installing = False)

    assert installing.uninstall_store_game(FakeGameInfo()) is False
    assert store["store"].uninstalls == []


def test_store_addons_need_no_work(store):
    # Store clients fetch their own DLC.
    assert installing.install_store_game_addons(FakeGameInfo()) is True


###########################################################
# Local games
###########################################################

def test_a_populated_cache_means_installed(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "game.exe").write_text("content")

    assert installing.is_local_game_installed(
        FakeGameInfo(local_cache_dir = str(cache))) is True


def test_an_empty_cache_means_not_installed(tmp_path):
    # A directory left behind by a failed install is not an install.
    cache = tmp_path / "cache"
    cache.mkdir()

    assert installing.is_local_game_installed(
        FakeGameInfo(local_cache_dir = str(cache))) is False


def test_a_missing_cache_means_not_installed(tmp_path):
    assert installing.is_local_game_installed(
        FakeGameInfo(local_cache_dir = str(tmp_path / "absent"))) is False


def test_a_cache_with_only_subdirectories_means_not_installed(tmp_path):
    cache = tmp_path / "cache"
    (cache / "empty").mkdir(parents = True)

    assert installing.is_local_game_installed(
        FakeGameInfo(local_cache_dir = str(cache))) is False


###########################################################
# Uninstalling locally
###########################################################

@pytest.fixture
def installed_game(tmp_path):
    local = tmp_path / "local"
    remote = tmp_path / "remote"
    local.mkdir()
    remote.mkdir()
    (local / "game.exe").write_text("content")
    (remote / "game.zip").write_text("content")
    return FakeGameInfo(local_cache_dir = str(local), remote_cache_dir = str(remote))


def test_uninstalling_removes_the_local_cache(tmp_path, installed_game):
    assert installing.uninstall_local_game(installed_game) is True
    assert not os.path.exists(installed_game.get_local_cache_dir())


def test_uninstalling_removes_the_remote_cache(tmp_path, installed_game):
    # Both caches go, or the next install sees a stale copy.
    installing.uninstall_local_game(installed_game)

    assert not os.path.exists(installed_game.get_remote_cache_dir())


def test_uninstalling_something_absent_is_success(tmp_path):
    game = FakeGameInfo(
        local_cache_dir = str(tmp_path / "absent"),
        remote_cache_dir = str(tmp_path / "absent-remote"))

    assert installing.uninstall_local_game(game) is True


def test_uninstalling_something_absent_touches_nothing(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("nothing should be removed")

    monkeypatch.setattr(installing.fileops, "remove_directory", fail)
    game = FakeGameInfo(local_cache_dir = str(tmp_path / "absent"))

    assert installing.uninstall_local_game(game) is True


def test_a_failed_local_removal_is_reported(installed_game, monkeypatch):
    monkeypatch.setattr(installing.fileops, "remove_directory", lambda **kwargs: False)

    assert installing.uninstall_local_game(installed_game) is False


def test_the_remote_cache_is_not_removed_after_a_local_failure(installed_game, monkeypatch):
    # Losing the remote copy while the local one is still there is the worst
    # outcome of the pair.
    removed = []

    def remove(src, **kwargs):
        removed.append(src)
        return False

    monkeypatch.setattr(installing.fileops, "remove_directory", remove)
    installing.uninstall_local_game(installed_game)

    assert removed == [installed_game.get_local_cache_dir()]


def test_pretending_removes_nothing(installed_game):
    installing.uninstall_local_game(installed_game, pretend_run = True)

    assert os.path.exists(installed_game.get_local_cache_dir())


###########################################################
# Dispatch
###########################################################

def test_a_store_platform_checks_the_store(store):
    store["is_store"] = True
    store["store"] = FakeStore(installed = True)

    assert installing.is_game_installed(FakeGameInfo()) is True
    assert store["store"].checks == ["12345"]


def test_a_local_platform_checks_the_cache(store, tmp_path):
    # Without the dispatch a local game would be asked about a store it has no
    # entry in.
    store["is_store"] = False
    store["store"] = FakeStore(installed = True)
    cache = tmp_path / "cache"
    cache.mkdir()

    assert installing.is_game_installed(
        FakeGameInfo(local_cache_dir = str(cache))) is False
    assert store["store"].checks == []


def test_installing_a_store_platform_uses_the_store(store):
    store["is_store"] = True
    store["store"] = FakeStore()
    installing.install_game(FakeGameInfo())

    assert store["store"].installs == ["12345"]


def test_installing_a_local_platform_never_reaches_the_store(store, tmp_path, monkeypatch):
    store["is_store"] = False
    store["store"] = FakeStore()
    monkeypatch.setattr(installing, "install_local_game", lambda **kwargs: True)
    installing.install_game(FakeGameInfo())

    assert store["store"].installs == []


def test_uninstalling_a_store_platform_uses_the_store(store):
    store["is_store"] = True
    store["store"] = FakeStore()
    installing.uninstall_game(FakeGameInfo())

    assert store["store"].uninstalls == ["12345"]


def test_uninstalling_a_local_platform_removes_its_caches(store, installed_game):
    store["is_store"] = False

    assert installing.uninstall_game(installed_game) is True
    assert not os.path.exists(installed_game.get_local_cache_dir())


def test_addons_dispatch_on_the_platform(store, monkeypatch):
    reached = []
    monkeypatch.setattr(
        installing, "install_local_game_addons",
        lambda **kwargs: reached.append("local") or True)

    store["is_store"] = True
    installing.install_game_addons(FakeGameInfo())
    assert reached == []

    store["is_store"] = False
    installing.install_game_addons(FakeGameInfo())
    assert reached == ["local"]


@pytest.mark.parametrize("call", [
    installing.is_game_installed,
    installing.install_game,
    installing.uninstall_game,
])
def test_every_entry_point_consults_the_platform(store, monkeypatch, call, tmp_path):
    seen = []
    monkeypatch.setattr(
        installing.stores, "is_store_platform",
        lambda platform: seen.append(platform) or False)
    monkeypatch.setattr(installing, "install_local_game", lambda **kwargs: True)
    call(FakeGameInfo(platform = "Sony PlayStation",
                      local_cache_dir = str(tmp_path / "absent")))

    assert seen == ["Sony PlayStation"]


###########################################################
# Store edge cases
###########################################################

def test_a_platform_without_a_store_is_not_installed_or_uninstalled(store):
    store["store"] = None

    assert installing.install_store_game(FakeGameInfo()) is False
    assert installing.uninstall_store_game(FakeGameInfo()) is False


def test_an_invalid_game_is_not_uninstalled(store):
    assert installing.uninstall_store_game(FakeGameInfo(valid = False)) is False
    assert store["store"].uninstalls == []


###########################################################
# Installing locally
###########################################################

class LocalGameInfo(FakeGameInfo):

    def __init__(self, values = None, **kwargs):
        super().__init__(**kwargs)
        self.values = values or {}

    def get_name(self):
        return "Game"

    def get_boxfront_asset(self):
        return "/art/boxfront.png"

    def get_remote_rom_dir(self):
        return "/remote/roms/Game"

    def get_value(self, key):
        return self.values.get(key)


@pytest.fixture
def local(monkeypatch, tmp_path):
    state = {
        "cache": tmp_path / "cache",
        "source_available": True,
        "tmp_ok": True,
        "sync_ok": True,
        "transform": False,
        "transform_ok": True,
        "copy_ok": True,
        "populate": True,
        "popups": [],
        "removed": [],
        "synced": [],
        "transformed": [],
        "copied": [],
        "tmp_count": 0,
    }

    def create_temporary_directory(**kwargs):
        state["tmp_count"] += 1
        return state["tmp_ok"], str(tmp_path / ("tmp%d" % state["tmp_count"]))

    def sync_from_remote_decrypted(src, dest, **kwargs):
        state["synced"].append((src, dest))
        return state["sync_ok"]

    def transform_game_file(source_dir, output_dir, **kwargs):
        state["transformed"].append(source_dir)
        if not state["transform_ok"]:
            return False, "transform failed"
        return True, output_dir + "/out/game.iso"

    def copy_contents(src, dest, **kwargs):
        state["copied"].append((src, dest))
        if state["populate"]:
            os.makedirs(dest, exist_ok = True)
            with open(os.path.join(dest, "game.bin"), "w") as handle:
                handle.write("content")
        return state["copy_ok"]

    monkeypatch.setattr(
        installing.locker, "does_path_contain_files", lambda path: state["source_available"])
    monkeypatch.setattr(installing.fileops, "create_temporary_directory", create_temporary_directory)
    monkeypatch.setattr(installing.locker, "sync_from_remote_decrypted", sync_from_remote_decrypted)
    monkeypatch.setattr(installing.transform, "transform_game_file", transform_game_file)
    monkeypatch.setattr(installing.fileops, "copy_contents", copy_contents)
    monkeypatch.setattr(
        installing.fileops, "remove_directory",
        lambda src, **kwargs: state["removed"].append(src) or True)
    monkeypatch.setattr(
        installing.platforms, "is_transform_platform", lambda platform: state["transform"])
    monkeypatch.setattr(
        installing.gui, "display_error_popup",
        lambda title_text, message_text: state["popups"].append(title_text))
    monkeypatch.setattr(
        installing.gui, "display_loading_window",
        lambda run_func, **kwargs: run_func())
    return state


def a_local_game(local):
    return LocalGameInfo(local_cache_dir = str(local["cache"]))


def test_an_already_cached_game_is_not_installed_again(local):
    local["cache"].mkdir()
    (local["cache"] / "game.bin").write_text("content")

    assert installing.install_local_game(a_local_game(local)) is True
    assert local["synced"] == []


def test_a_game_without_source_files_is_not_installed(local):
    local["source_available"] = False

    assert installing.install_local_game(a_local_game(local)) is False
    assert local["popups"] == ["Source files unavailable"]


def test_a_failed_temporary_directory_stops_the_install(local):
    local["tmp_ok"] = False

    assert installing.install_local_game(a_local_game(local)) is False
    assert local["synced"] == []


def test_a_failed_download_stops_the_install_and_cleans_up(local, tmp_path):
    local["sync_ok"] = False

    assert installing.install_local_game(a_local_game(local)) is False
    assert local["removed"] == [str(tmp_path / "tmp1")]
    assert local["copied"] == []


def test_a_local_game_is_downloaded_and_cached(local, tmp_path):
    assert installing.install_local_game(a_local_game(local)) is True
    assert local["synced"] == [("/remote/roms/Game", str(tmp_path / "tmp1"))]
    assert local["copied"] == [(str(tmp_path / "tmp1"), str(local["cache"]))]
    assert local["removed"] == [str(tmp_path / "tmp1")]
    assert local["popups"] == []


def test_a_transform_platform_game_is_transformed_before_caching(local, tmp_path):
    local["transform"] = True

    assert installing.install_local_game(a_local_game(local)) is True
    assert local["transformed"] == [str(tmp_path / "tmp1")]
    assert local["copied"] == [(str(tmp_path / "tmp2" / "out"), str(local["cache"]))]
    assert local["removed"] == [str(tmp_path / "tmp2"), str(tmp_path / "tmp1")]


def test_a_game_that_did_not_reach_the_cache_fails_the_install(local):
    # Launching would otherwise start a game that is not there.
    local["populate"] = False

    assert installing.install_local_game(a_local_game(local)) is False
    assert local["popups"] == ["Failed to cache game"]


def test_a_pretend_install_is_not_reported_as_failed(local):
    local["populate"] = False

    assert installing.install_local_game(a_local_game(local), pretend_run = True) is True
    assert local["popups"] == []


def test_a_failed_copy_is_reported(local):
    local["copy_ok"] = False

    assert installing.install_local_untransformed_game(
        a_local_game(local), source_dir = "/src") is False


def test_a_failed_transform_temporary_directory_is_reported(local):
    local["tmp_ok"] = False

    assert installing.install_local_transformed_game(
        a_local_game(local), source_dir = "/src") is False
    assert local["transformed"] == []


def test_a_failed_transform_is_reported_and_cleaned_up(local, tmp_path):
    local["transform_ok"] = False

    assert installing.install_local_transformed_game(
        a_local_game(local), source_dir = "/src") is False
    assert local["copied"] == []
    assert local["removed"] == [str(tmp_path / "tmp1")]


def test_a_failed_transformed_copy_is_reported_and_cleaned_up(local, tmp_path):
    local["copy_ok"] = False

    assert installing.install_local_transformed_game(
        a_local_game(local), source_dir = "/src") is False
    assert local["removed"] == [str(tmp_path / "tmp1")]


###########################################################
# Local addons
###########################################################

class FakeEmulator:

    def __init__(self, platforms, result = True):
        self.platforms = platforms
        self.result = result
        self.calls = []

    def get_platforms(self):
        return self.platforms

    def install_addons(self, dlc_dirs, update_dirs, **kwargs):
        self.calls.append((dlc_dirs, update_dirs))
        return self.result


@pytest.fixture
def addons(monkeypatch):
    state = {"possible": True, "emulators": []}
    monkeypatch.setattr(
        installing.platforms, "are_addons_possible", lambda platform: state["possible"])
    monkeypatch.setattr(installing.programs, "get_emulators", lambda: state["emulators"])
    monkeypatch.setattr(
        installing.environment, "get_locker_gaming_dlc_root_dir", lambda: "/dlc")
    monkeypatch.setattr(
        installing.environment, "get_locker_gaming_update_root_dir", lambda: "/update")
    return state


def test_a_platform_without_addons_needs_no_work(addons):
    addons["possible"] = False
    emulator = FakeEmulator(["Nintendo Switch"])
    addons["emulators"] = [emulator]

    assert installing.install_local_game_addons(
        LocalGameInfo(platform = "Nintendo Switch")) is True
    assert emulator.calls == []


def test_addons_go_to_the_platforms_emulators(addons):
    switch = FakeEmulator(["Nintendo Switch"])
    other = FakeEmulator(["Nintendo Wii"])
    addons["emulators"] = [other, switch]
    game = LocalGameInfo(platform = "Nintendo Switch", values = {
        installing.config.json_key_dlc: ["Game/dlc1"],
        installing.config.json_key_update: ["Game/update1"],
    })

    assert installing.install_local_game_addons(game) is True
    assert switch.calls == [(["/dlc/Game/dlc1"], ["/update/Game/update1"])]
    assert other.calls == []


def test_a_game_without_addon_entries_installs_none(addons):
    emulator = FakeEmulator(["Nintendo Switch"])
    addons["emulators"] = [emulator]

    assert installing.install_local_game_addons(
        LocalGameInfo(platform = "Nintendo Switch")) is True
    assert emulator.calls == [([], [])]


def test_a_failed_addon_install_is_reported(addons):
    addons["emulators"] = [FakeEmulator(["Nintendo Switch"], result = False)]

    assert installing.install_local_game_addons(
        LocalGameInfo(platform = "Nintendo Switch")) is False


def test_installing_a_local_platform_reaches_the_local_install(store, local):
    store["is_store"] = False

    assert installing.install_game(a_local_game(local)) is True
    assert local["copied"] != []
