# Imports
import pytest

# Local imports
from joybox.collection import backup


###########################################################
# Game file backup
#
# Store games are re-downloaded from the store when the store's build has moved
# past what the collection holds; local games are already the master copy and
# are never re-fetched.
###########################################################

class FakeGameInfo:

    def __init__(self, platform = "Microsoft Windows", identifier = "12345",
                 branchid = None, buildid = "1000"):
        self.platform = platform
        self.identifier = identifier
        self.branchid = branchid
        self.buildid = buildid

    def get_platform(self):
        return self.platform

    def get_store_info_identifier(self):
        return self.identifier

    def get_store_branchid(self):
        return self.branchid

    def get_store_buildid(self):
        return self.buildid


class FakeStore:

    def __init__(self, latest = "1000", downloadable = True):
        self.latest = latest
        self.downloadable = downloadable
        self.asked = []

    def can_download_purchases(self):
        return self.downloadable

    def get_latest_version(self, identifier, branch, **kwargs):
        self.asked.append((identifier, branch))
        return self.latest


@pytest.fixture
def store(monkeypatch):
    holder = {"store": FakeStore(), "is_store": True}
    monkeypatch.setattr(
        backup.stores, "get_store_by_platform",
        lambda platform, **kwargs: holder["store"])
    monkeypatch.setattr(
        backup.stores, "is_store_platform", lambda platform: holder["is_store"])
    return holder


###########################################################
# Store games
###########################################################

def test_a_newer_store_build_is_backed_up(store):
    store["store"] = FakeStore(latest = "1001")

    assert backup.should_backup_store_game_files(FakeGameInfo(buildid = "1000")) is True


def test_a_matching_store_build_is_not_backed_up(store):
    # Re-downloading an unchanged build costs bandwidth and gains nothing.
    store["store"] = FakeStore(latest = "1000")

    assert backup.should_backup_store_game_files(FakeGameInfo(buildid = "1000")) is False


def test_an_older_store_build_is_backed_up(store):
    # A rollback is still a change, and the collection should follow the store.
    store["store"] = FakeStore(latest = "999")

    assert backup.should_backup_store_game_files(FakeGameInfo(buildid = "1000")) is True


def test_a_game_with_no_recorded_build_is_backed_up(store):
    store["store"] = FakeStore(latest = "1000")

    assert backup.should_backup_store_game_files(FakeGameInfo(buildid = None)) is True


def test_an_unknown_latest_version_is_treated_as_a_change(store):
    store["store"] = FakeStore(latest = None)

    assert backup.should_backup_store_game_files(FakeGameInfo(buildid = "1000")) is True


def test_a_platform_without_a_store_is_not_backed_up(monkeypatch):
    monkeypatch.setattr(
        backup.stores, "get_store_by_platform", lambda platform, **kwargs: None)

    assert backup.should_backup_store_game_files(FakeGameInfo()) is False


def test_a_store_that_cannot_download_is_not_backed_up(store):
    # Nothing to fetch, so there is nothing to back up.
    store["store"] = FakeStore(downloadable = False)

    assert backup.should_backup_store_game_files(FakeGameInfo()) is False


def test_the_version_check_is_not_reached_without_download_support(store):
    store["store"] = FakeStore(downloadable = False)
    backup.should_backup_store_game_files(FakeGameInfo())

    assert store["store"].asked == []


def test_the_identifier_and_branch_reach_the_store(store):
    store["store"] = FakeStore()
    backup.should_backup_store_game_files(
        FakeGameInfo(identifier = "steam-9999", branchid = "beta"))

    assert store["store"].asked == [("steam-9999", "beta")]


###########################################################
# Local games
###########################################################

def test_a_local_game_is_never_backed_up():
    # The local copy is the master; there is no upstream to re-fetch from.
    assert backup.should_backup_local_game_files(FakeGameInfo()) is False


def test_backing_up_a_local_game_reports_success():
    assert backup.backup_local_game_files(FakeGameInfo(), locker_type = None) is True


###########################################################
# Dispatch
###########################################################

def test_a_store_platform_uses_the_store_check(store):
    store["is_store"] = True
    store["store"] = FakeStore(latest = "1001")

    assert backup.should_backup_game_files(FakeGameInfo(buildid = "1000")) is True


def test_a_local_platform_uses_the_local_check(store):
    # Without the dispatch a local game would be asked about a store it has no
    # entry in.
    store["is_store"] = False
    store["store"] = FakeStore(latest = "1001")

    assert backup.should_backup_game_files(FakeGameInfo(buildid = "1000")) is False


def test_a_local_platform_never_reaches_the_store(store):
    store["is_store"] = False
    store["store"] = FakeStore(latest = "1001")
    backup.should_backup_game_files(FakeGameInfo())

    assert store["store"].asked == []


def test_backing_up_a_local_platform_reports_success(store):
    store["is_store"] = False

    assert backup.backup_game_files(FakeGameInfo(), locker_type = None) is True


def test_an_unchanged_store_game_skips_the_backup(store, monkeypatch):
    # An early return before any temporary directory is created.
    store["is_store"] = True
    store["store"] = FakeStore(latest = "1000")

    def fail(*args, **kwargs):
        raise AssertionError("no backup work should start")

    monkeypatch.setattr(backup.fileops, "create_temporary_directory", fail)

    assert backup.backup_game_files(FakeGameInfo(buildid = "1000"), locker_type = None) is True


###########################################################
# Store backup pipeline
###########################################################

@pytest.fixture
def pipeline(store, monkeypatch, tmp_path):
    state = {"temp": tmp_path / "temp", "temp_ok": True, "downloaded": [], "uploaded": [],
             "download_ok": True, "upload_ok": True}
    store["store"] = FakeStore(latest = "2000")

    def create_temporary_directory(**kwargs):
        if not state["temp_ok"]:
            return (False, "")
        state["temp"].mkdir()
        return (True, str(state["temp"]))

    def download_game_store_purchase(game_info, output_dir, **kwargs):
        state["downloaded"].append(output_dir)
        return state["download_ok"]

    def upload_game_files(game_info, game_root, locker_type, **kwargs):
        state["uploaded"].append((game_root, locker_type))
        return state["upload_ok"]

    monkeypatch.setattr(backup.fileops, "create_temporary_directory", create_temporary_directory)
    monkeypatch.setattr(backup, "download_game_store_purchase", download_game_store_purchase)
    monkeypatch.setattr(backup, "upload_game_files", upload_game_files)
    return state


def test_a_changed_store_game_is_downloaded_then_uploaded(pipeline):
    assert backup.backup_game_files(FakeGameInfo(), locker_type = "Primary") is True
    assert pipeline["downloaded"] == [str(pipeline["temp"])]
    assert pipeline["uploaded"] == [(str(pipeline["temp"]), "Primary")]
    assert not pipeline["temp"].exists()


def test_a_backup_without_a_temporary_directory_fails(pipeline):
    pipeline["temp_ok"] = False

    assert backup.backup_game_files(FakeGameInfo(), locker_type = None) is False
    assert pipeline["downloaded"] == []


def test_a_failed_download_uploads_nothing_and_cleans_up(pipeline):
    pipeline["download_ok"] = False

    assert backup.backup_game_files(FakeGameInfo(), locker_type = None) is False
    assert pipeline["uploaded"] == []
    assert not pipeline["temp"].exists()


def test_a_failed_upload_fails_and_cleans_up(pipeline):
    pipeline["upload_ok"] = False

    assert backup.backup_game_files(FakeGameInfo(), locker_type = None) is False
    assert not pipeline["temp"].exists()


###########################################################
# Backing up every game
###########################################################

@pytest.fixture
def every_game(monkeypatch):
    state = {"backed_up": [], "result": True}

    class StubGameInfo:
        def __init__(self, game_supercategory, game_category, game_subcategory, game_name, **kwargs):
            self.name = game_name

    def find_json_game_names(game_supercategory, game_category, game_subcategory):
        return ["Alpha", "Beta"] if game_subcategory == backup.config.Subcategory.NINTENDO_NES else []

    def backup_game_files(game_info, locker_type, **kwargs):
        state["backed_up"].append((game_info.name, locker_type))
        return state["result"]

    monkeypatch.setattr(backup.gameinfo, "GameInfo", StubGameInfo)
    monkeypatch.setattr(backup.gameinfo, "find_json_game_names", find_json_game_names)
    monkeypatch.setattr(backup, "backup_game_files", backup_game_files)
    return state


def test_every_game_is_backed_up(every_game):
    assert backup.backup_all_game_files("Primary") is True
    assert every_game["backed_up"] == [("Alpha", "Primary"), ("Beta", "Primary")]


def test_backing_up_every_game_stops_at_a_failure(every_game):
    every_game["result"] = False

    assert backup.backup_all_game_files("Primary") is False
    assert every_game["backed_up"] == [("Alpha", "Primary")]
