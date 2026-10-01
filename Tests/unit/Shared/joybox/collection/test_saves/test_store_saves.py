# Imports
import os
import shutil

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox import storebase
from joybox.collection import saves


###########################################################
# Store game saves
#
# A store game records its save locations as tokenized paths. Exporting
# resolves them on this machine, gathers what exists and packs it; importing
# save paths reads the packed archives back into tokenized paths.
###########################################################

PROFILE = config.token_user_profile_dir
INSTALL = config.token_store_install_dir


class FakeStore:

    def __init__(self, profile_dirs, install_dirs):
        self.translation_map = {
            config.token_user_registry_dir: [],
            config.token_user_public_dir: ["C:\\Users\\Public"],
            PROFILE: profile_dirs,
            INSTALL: install_dirs}
        self.asked = []

    def get_type(self):
        return "Steam"

    def add_path_variants(self, paths = None):
        new_paths = list(paths) if paths else []
        for path in list(new_paths):
            if "/AppData/Roaming/" in path:
                new_paths.append(path.replace("/AppData/Roaming/", "/Application Data/"))
        return new_paths

    def build_path_translation_map(self, appid = None, appname = None):
        self.asked.append((appid, appname))
        return self.translation_map


@pytest.fixture
def store_game(tmp_path, game):
    game.platform = "Steam"
    game.category = config.Category.COMPUTER
    game.store_paths = [PROFILE + "/AppData/Roaming/Hades", INSTALL + "/userdata/save"]
    return game


@pytest.fixture
def store(tmp_path, monkeypatch):
    profile = tmp_path / "profile"
    install = tmp_path / "steam"
    fake = FakeStore([str(profile)], [str(install)])
    monkeypatch.setattr(
        saves.stores, "get_store_by_platform",
        lambda platform, **kwargs: fake if platform == "Steam" else None)
    return fake


def relative(path):
    return storebase.convert_from_tokenized_path(path, store_type = "Steam")


###########################################################
# Resolving save paths
###########################################################

def test_a_game_outside_any_store_has_no_store_paths(game, store):
    assert saves.get_store_path_entries(game) == []


def test_each_token_resolves_to_its_location_on_this_machine(tmp_path, store_game, store):
    entries = saves.get_store_path_entries(store_game)

    assert {"full": str(tmp_path / "profile") + "/AppData/Roaming/Hades",
            "relative": relative(PROFILE + "/AppData/Roaming/Hades")} in entries
    assert {"full": str(tmp_path / "steam") + "/userdata/save",
            "relative": relative(INSTALL + "/userdata/save")} in entries
    assert store.asked == [("1145360", "Hades")]


def test_path_variants_are_resolved_too(tmp_path, store_game, store):
    fulls = [entry["full"] for entry in saves.get_store_path_entries(store_game)]

    assert str(tmp_path / "profile") + "/Application Data/Hades" in fulls


def test_no_entry_keeps_an_unresolved_token(store_game, store):
    # A token the path does not contain must not yield a copy of the raw path.
    for entry in saves.get_store_path_entries(store_game):
        assert PROFILE not in entry["full"]
        assert INSTALL not in entry["full"]


def test_a_token_with_no_location_on_this_machine_yields_nothing(store_game, store):
    store.translation_map[PROFILE] = []

    entries = saves.get_store_path_entries(store_game)

    assert [entry["relative"] for entry in entries] == [relative(INSTALL + "/userdata/save")]


def test_each_location_appears_once(store_game, store):
    store_game.store_paths = store_game.store_paths * 2

    entries = saves.get_store_path_entries(store_game)

    assert len(entries) == len({entry["full"] for entry in entries})


def test_a_game_without_recorded_paths_has_no_entries(store_game, store):
    store_game.store_paths = None

    assert saves.get_store_path_entries(store_game) == []


###########################################################
# Importing save paths from archives
###########################################################

@pytest.fixture
def archived(tmp_path, store_game, fake_archive):
    packed = tmp_path / "packed"
    packed.mkdir()
    (packed / "Hades_1700000000.zip").write_bytes(b"zip")
    (packed / "Hades_1700000100.zip").write_bytes(b"zip")
    fake_archive.listings = {
        "Hades_1700000000.zip": ["General/AppData/Roaming/Hades/Profile1.sav"],
        "Hades_1700000100.zip": ["General/Documents/Hades/Profile2.sav"]}
    store_game.store_paths = [PROFILE + "/AppData/Roaming/Hades"]
    return store_game


def test_archived_files_become_tokenized_save_paths(archived, fake_archive):
    assert saves.import_store_game_save_paths(archived) is True

    assert archived.store_paths == [
        PROFILE + "/AppData/Roaming/Hades",
        PROFILE + "/Documents/Hades/Profile2.sav"]
    assert len(archived.updates) == 1


def test_save_paths_are_read_from_the_archives_not_the_live_saves(archived, fake_archive):
    saves.import_store_game_save_paths(archived)

    assert sorted(os.path.dirname(path) for path in fake_archive.listed) == \
        [archived.get_local_save_dir()] * 2


def test_a_game_without_recorded_paths_gains_the_archived_ones(archived):
    archived.store_paths = None

    assert saves.import_store_game_save_paths(archived) is True
    assert archived.store_paths == [
        PROFILE + "/AppData/Roaming/Hades/Profile1.sav",
        PROFILE + "/Documents/Hades/Profile2.sav"]


def test_a_failed_write_back_fails_the_import(archived):
    archived.update_result = False

    assert saves.import_store_game_save_paths(archived) is False


def test_flags_reach_the_lister_and_the_json_write(archived, fake_archive, monkeypatch):
    seen = []
    listings = fake_archive.listings

    def list_archive(archive_file, **kwargs):
        seen.append(kwargs)
        return listings[os.path.basename(archive_file)]
    fake_archive.list_archive = list_archive

    saves.import_store_game_save_paths(archived, verbose = True, pretend_run = True, exit_on_failure = True)

    expected = {"verbose": True, "pretend_run": True, "exit_on_failure": True}
    assert seen == [expected, expected]
    assert archived.updates == [expected]


def test_importing_a_store_save_is_a_no_op(store_game):
    # The store restores its own saves.
    assert saves.import_store_game_save(store_game) is True


###########################################################
# Exporting
###########################################################

@pytest.fixture
def copying(monkeypatch):
    copies = []

    def smart_copy(src, dest, **kwargs):
        copies.append((src, dest, kwargs))
        shutil.copytree(src, dest)
        return True
    monkeypatch.setattr(saves.fileops, "smart_copy", smart_copy)
    return copies


@pytest.fixture
def packing(monkeypatch):
    packs = []

    def pack_save_dir(game_info, input_save_dir, **kwargs):
        files = sorted(
            os.path.relpath(os.path.join(base, name), input_save_dir)
            for base, _, names in os.walk(input_save_dir) for name in names)
        packs.append({"save_dir": input_save_dir, "files": files, **kwargs})
        return packs_result[0]
    packs_result = [True]
    monkeypatch.setattr(saves, "_pack_save_dir", pack_save_dir)
    return packs, packs_result


@pytest.fixture
def installed(tmp_path):
    saves_dir = tmp_path / "profile" / "AppData" / "Roaming" / "Hades"
    saves_dir.mkdir(parents = True)
    (saves_dir / "Profile1.sav").write_bytes(b"progress")
    return saves_dir


def test_existing_store_saves_are_gathered_and_packed(store_game, store, installed, copying, packing, temp_dirs):
    packs, _ = packing

    assert saves.export_store_game_save(store_game, locker_type = config.LockerType.ALL) is True

    assert len(copying) == 1
    assert packs[0]["save_dir"] == temp_dirs[0]
    assert packs[0]["files"] == [os.path.join(relative(PROFILE + "/AppData/Roaming/Hades"), "Profile1.sav")]
    assert packs[0]["locker_type"] == config.LockerType.ALL
    assert packs[0]["output_save_dir"] == store_game.get_local_save_dir()
    assert not os.path.exists(temp_dirs[0])


@pytest.mark.parametrize("verbose", [False, True])
def test_nothing_installed_exports_nothing(store_game, store, copying, packing, temp_dirs, verbose):
    packs, _ = packing

    assert saves.export_store_game_save(store_game, verbose = verbose) is True
    assert packs == []
    assert not os.path.exists(temp_dirs[0])


def test_a_failed_copy_fails_the_export(store_game, store, installed, packing, temp_dirs, monkeypatch):
    # Packing a partial save would record it as the newest one.
    packs, _ = packing
    monkeypatch.setattr(saves.fileops, "smart_copy", lambda **kwargs: False)

    assert saves.export_store_game_save(store_game) is False
    assert packs == []
    assert not os.path.exists(temp_dirs[0])


def test_a_failed_pack_fails_the_export(store_game, store, installed, copying, packing, temp_dirs):
    _, packs_result = packing
    packs_result[0] = False

    assert saves.export_store_game_save(store_game) is False
    assert not os.path.exists(temp_dirs[0])


def test_no_temporary_directory_fails_the_export(store_game, store, monkeypatch):
    monkeypatch.setattr(
        saves.fileops, "create_temporary_directory", lambda **kwargs: (False, "no space"))

    assert saves.export_store_game_save(store_game) is False


def test_a_pretend_run_creates_no_temporary_directory(store_game, store, installed, packing, temp_dirs, monkeypatch):
    copies = []
    monkeypatch.setattr(
        saves.fileops, "smart_copy", lambda **kwargs: copies.append(kwargs) or True)

    saves.export_store_game_save(store_game, pretend_run = True)

    assert temp_dirs == [os.path.join(os.path.dirname(temp_dirs[0]), "pretend")]
    assert not os.path.exists(temp_dirs[0])
    assert copies[0]["pretend_run"] is True
    assert packing[0][0]["pretend_run"] is True


def test_an_exported_store_save_is_archived_and_backed_up(store_game, store, installed, copying, fake_archive, fake_locker, temp_dirs):
    assert saves.export_store_game_save(store_game) is True

    assert fake_archive.created[0]["source_dir"] == temp_dirs[0]
    assert len(fake_locker.backups) == 1
    assert all(not os.path.exists(path) for path in temp_dirs)


def test_a_pretend_export_with_saves_to_copy_reports_success(store_game, store, installed, fake_archive, fake_locker, temp_dirs):
    # The pretend copy never fills the temporary tree, yet every step would run.
    assert saves.export_store_game_save(store_game, pretend_run = True) is True

    assert fake_archive.created[0]["pretend_run"] is True
    assert fake_locker.backups[0]["pretend_run"] is True


def test_a_pretend_export_with_nothing_installed_packs_nothing(store_game, store, fake_archive, temp_dirs):
    assert saves.export_store_game_save(store_game, pretend_run = True) is True
    assert fake_archive.created == []
