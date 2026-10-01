# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.collection import saves
from saves_helpers import FakeGameInfo, make_catalog


###########################################################
# Packing a save
#
# The live save directory is zipped into a temporary directory, tested, and
# backed up into the lockers as a timestamped archive. The temporary directory
# must not outlive the call, whichever way it ends.
###########################################################

@pytest.fixture
def stamped(monkeypatch):
    monkeypatch.setattr(saves.runtime, "get_current_timestamp", lambda: 1700000000)


def test_a_save_is_archived_tested_and_backed_up(game, fake_archive, fake_locker, stamped):
    assert saves.pack_save(game, locker_type = config.LockerType.ALL) is True

    created = fake_archive.created[0]
    assert created["source_dir"] == game.get_save_dir()
    assert fake_archive.tested == [created["archive_file"]]
    assert [backup["locker_type"] for backup in fake_locker.backups] == [
        config.LockerType.LOCAL, config.LockerType.ALL]
    for backup in fake_locker.backups:
        assert backup["src"] == created["archive_file"]
        assert backup["existed"] is True
        assert backup["dest_rel_path"].endswith("Chrono Trigger (USA)_1700000000.zip")


def test_the_temporary_archive_is_named_after_the_game(game, fake_archive):
    saves.pack_save(game)

    assert os.path.basename(fake_archive.created[0]["archive_file"]) == \
        "Chrono Trigger (USA)" + config.ArchiveFileType.ZIP.cval()


def test_the_temporary_directory_is_removed_after_packing(game, temp_dirs):
    saves.pack_save(game)

    assert len(temp_dirs) == 1
    assert not os.path.exists(temp_dirs[0])


def test_the_archive_directory_is_created(game):
    saves.pack_save(game)

    assert os.path.isdir(game.get_local_save_dir())


@pytest.mark.parametrize("locker_type", [None, config.LockerType.LOCAL])
def test_without_another_locker_the_save_goes_to_the_local_locker_once(game, fake_locker, locker_type):
    # The archive directory is in the local locker; skipping the backup would
    # delete the only copy along with the temporary directory.
    saves.pack_save(game, locker_type = locker_type)

    assert [backup["locker_type"] for backup in fake_locker.backups] == [config.LockerType.LOCAL]


def test_a_remote_locker_also_gets_a_local_copy(game, fake_locker):
    # Duplicate checks and unpacking only read the local archive directory.
    assert saves.pack_save(game, locker_type = config.LockerType.HETZNER) is True
    assert [backup["locker_type"] for backup in fake_locker.backups] == [
        config.LockerType.LOCAL, config.LockerType.HETZNER]


def test_a_failed_local_backup_skips_the_remote_one(game, fake_locker):
    fake_locker.result = False

    assert saves.pack_save(game, locker_type = config.LockerType.HETZNER) is False
    assert [backup["locker_type"] for backup in fake_locker.backups] == [config.LockerType.LOCAL]


def test_an_explicit_save_directory_is_packed_instead(game, fake_archive, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    (other / "elsewhere.sav").write_bytes(b"elsewhere")

    assert saves.pack_save(game, save_dir = str(other)) is True
    assert fake_archive.created[0]["source_dir"] == str(other)


@pytest.mark.parametrize("verbose", [False, True])
def test_an_empty_save_directory_packs_nothing(game, fake_archive, temp_dirs, verbose):
    os.remove(os.path.join(game.get_save_dir(), "slot1.sav"))

    assert saves.pack_save(game, verbose = verbose) is False
    assert fake_archive.created == []
    assert temp_dirs == []


def test_a_computer_save_excludes_its_prefix_directories(game, fake_archive):
    game.category = config.Category.COMPUTER
    saves.pack_save(game)

    assert fake_archive.created[0]["excludes"] == [
        config.SaveType.WINE.val(), config.SaveType.SANDBOXIE.val()]


def test_other_saves_exclude_nothing(game, fake_archive):
    saves.pack_save(game)

    assert fake_archive.created[0]["excludes"] == []


def test_an_identical_archive_is_not_backed_up_again(game, fake_hashing, fake_locker, temp_dirs):
    fake_hashing.duplicates = ["/locker/Chrono Trigger (USA)_1600000000.zip"]

    assert saves.pack_save(game) is True
    assert fake_locker.backups == []
    assert fake_hashing.asked[0][1] == game.get_local_save_dir()
    assert not os.path.exists(temp_dirs[0])


###########################################################
# Failures
###########################################################

def test_an_unmakeable_archive_directory_fails_before_any_work(game, fake_archive, temp_dirs, monkeypatch):
    monkeypatch.setattr(saves.fileops, "make_directory", lambda **kwargs: False)

    assert saves.pack_save(game) is False
    assert temp_dirs == []
    assert fake_archive.created == []


def test_no_temporary_directory_fails(game, fake_archive, monkeypatch):
    monkeypatch.setattr(
        saves.fileops, "create_temporary_directory", lambda **kwargs: (False, "no space"))

    assert saves.pack_save(game) is False
    assert fake_archive.created == []


def test_a_failed_archive_is_not_backed_up(game, fake_archive, fake_locker, temp_dirs):
    fake_archive.create_result = False

    assert saves.pack_save(game) is False
    assert fake_archive.tested == []
    assert fake_locker.backups == []
    assert not os.path.exists(temp_dirs[0])


def test_an_archive_that_fails_its_test_is_not_backed_up(game, fake_archive, fake_locker, temp_dirs):
    # A zip that cannot be read back must never replace a good one.
    fake_archive.test_result = False

    assert saves.pack_save(game) is False
    assert fake_locker.backups == []
    assert not os.path.exists(temp_dirs[0])


def test_a_failed_backup_fails_the_pack(game, fake_locker, temp_dirs):
    fake_locker.result = False

    assert saves.pack_save(game) is False
    assert not os.path.exists(temp_dirs[0])


def test_the_temporary_directory_is_removed_when_archiving_raises(game, fake_archive, temp_dirs):
    def explode(**kwargs):
        raise RuntimeError("archiver crashed")
    fake_archive.create_archive_from_folder = explode

    with pytest.raises(RuntimeError):
        saves.pack_save(game)
    assert not os.path.exists(temp_dirs[0])


###########################################################
# Flags
###########################################################

def test_a_pretend_run_reports_success_without_writing(game, fake_archive, fake_locker):
    assert saves.pack_save(game, pretend_run = True) is True

    assert not os.path.exists(game.get_local_save_dir())
    assert fake_archive.created[0]["pretend_run"] is True
    assert fake_locker.backups[0]["pretend_run"] is True


def test_flags_reach_the_archiver_and_the_locker(game, fake_archive, fake_locker):
    saves.pack_save(game, verbose = True, exit_on_failure = True)

    for call in [fake_archive.created[0], fake_locker.backups[0]]:
        assert call["verbose"] is True
        assert call["exit_on_failure"] is True
        assert call["pretend_run"] is False


###########################################################
# Packing every game
###########################################################

def catalog_game(tmp_path, name, with_save = True):
    live = tmp_path / name / "live"
    live.mkdir(parents = True)
    if with_save:
        (live / "slot1.sav").write_bytes(b"data")
    return FakeGameInfo(str(live), str(tmp_path / name / "packed"), name = name)


def test_every_game_with_a_save_is_packed(tmp_path, game, monkeypatch):
    games = {
        "First": catalog_game(tmp_path, "First"),
        "Second": catalog_game(tmp_path, "Second", with_save = False),
        "Third": catalog_game(tmp_path, "Third")}
    built = make_catalog(monkeypatch, games)
    packed = []

    def pack_save(game_info, **kwargs):
        packed.append((game_info.get_name(), kwargs))
        return True
    monkeypatch.setattr(saves, "pack_save", pack_save)

    assert saves.pack_all_saves(locker_type = config.LockerType.LOCAL, verbose = True) is True
    assert [name for name, _ in packed] == ["First", "Third"]
    assert packed[0][1]["locker_type"] == config.LockerType.LOCAL
    assert packed[0][1]["verbose"] is True
    assert built[0][1]["game_supercategory"] == config.Supercategory.ROMS


def test_a_game_without_a_save_does_not_stop_packing(tmp_path, game, fake_locker, monkeypatch):
    games = {
        "Empty": catalog_game(tmp_path, "Empty", with_save = False),
        "Saved": catalog_game(tmp_path, "Saved")}
    make_catalog(monkeypatch, games)

    assert saves.pack_all_saves() is True
    assert len(fake_locker.backups) == 1


def test_the_first_failed_pack_stops_the_run(tmp_path, game, monkeypatch):
    games = {
        "First": catalog_game(tmp_path, "First"),
        "Second": catalog_game(tmp_path, "Second")}
    make_catalog(monkeypatch, games)
    packed = []

    def pack_save(game_info, **kwargs):
        packed.append(game_info.get_name())
        return False
    monkeypatch.setattr(saves, "pack_save", pack_save)

    assert saves.pack_all_saves() is False
    assert packed == ["First"]
