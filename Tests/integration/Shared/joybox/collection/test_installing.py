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
