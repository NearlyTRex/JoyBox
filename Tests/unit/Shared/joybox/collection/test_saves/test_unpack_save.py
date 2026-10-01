# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox.collection import saves
from saves_helpers import FakeGameInfo, make_catalog


###########################################################
# Unpacking a save
#
# The newest archive in the local locker is extracted into the live save
# directory, and only when that directory holds no progress of its own.
###########################################################

@pytest.fixture
def packed_game(tmp_path, game):
    packed = tmp_path / "packed"
    packed.mkdir()
    for stamp in ["1700000000", "1700000300", "1700000100"]:
        (packed / ("Chrono Trigger (USA)_%s.zip" % stamp)).write_bytes(stamp.encode())
    os.remove(os.path.join(game.get_save_dir(), "slot1.sav"))
    os.rmdir(game.get_save_dir())
    return game


def newest(game):
    return os.path.join(game.get_local_save_dir(), "Chrono Trigger (USA)_1700000300.zip")


def test_the_newest_archive_is_restored(packed_game, fake_archive):
    assert saves.unpack_save(packed_game) is True

    assert fake_archive.extracted[0]["archive_file"] == newest(packed_game)
    assert fake_archive.extracted[0]["extract_dir"] == packed_game.get_save_dir()
    assert os.path.exists(os.path.join(packed_game.get_save_dir(), "slot1.sav"))


def test_the_newest_archive_wins_whatever_order_the_listing_has(packed_game, fake_archive, monkeypatch):
    # Directory walks have no defined order.
    listing = sorted(os.path.join(packed_game.get_local_save_dir(), name)
                     for name in os.listdir(packed_game.get_local_save_dir()))
    monkeypatch.setattr(saves.paths, "build_file_list", lambda root: list(reversed(listing)))

    saves.unpack_save(packed_game)

    assert fake_archive.extracted[0]["archive_file"] == newest(packed_game)


def test_an_existing_empty_save_directory_is_filled(packed_game, fake_archive):
    os.mkdir(packed_game.get_save_dir())

    assert saves.unpack_save(packed_game) is True
    assert fake_archive.extracted


def test_a_live_save_is_never_overwritten(packed_game, fake_archive):
    os.mkdir(packed_game.get_save_dir())
    with open(os.path.join(packed_game.get_save_dir(), "slot1.sav"), "wb") as handle:
        handle.write(b"newer progress")

    assert saves.unpack_save(packed_game) is False
    assert fake_archive.extracted == []


def test_an_explicit_archive_directory_is_used(packed_game, fake_archive, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    (other / "Chrono Trigger (USA)_1500000000.zip").write_bytes(b"old")

    assert saves.unpack_save(packed_game, save_dir = str(other)) is True
    assert fake_archive.extracted[0]["archive_file"] == \
        str(other / "Chrono Trigger (USA)_1500000000.zip")


@pytest.mark.parametrize("verbose", [False, True])
def test_nothing_packed_restores_nothing(game, fake_archive, verbose):
    assert saves.unpack_save(game, verbose = verbose) is False
    assert fake_archive.extracted == []


###########################################################
# Failures
###########################################################

def test_an_unmakeable_save_directory_fails(packed_game, fake_archive, monkeypatch):
    monkeypatch.setattr(saves.fileops, "make_directory", lambda **kwargs: False)

    assert saves.unpack_save(packed_game) is False
    assert fake_archive.extracted == []


def test_a_failed_extraction_fails(packed_game, fake_archive):
    fake_archive.extract_result = False

    assert saves.unpack_save(packed_game) is False


def test_an_extraction_that_restores_nothing_fails(packed_game, fake_archive):
    fake_archive.extract_contents = {}

    assert saves.unpack_save(packed_game) is False


###########################################################
# Flags
###########################################################

def test_a_pretend_run_reports_success_without_writing(packed_game, fake_archive):
    assert saves.unpack_save(packed_game, pretend_run = True) is True

    assert not os.path.exists(packed_game.get_save_dir())
    assert fake_archive.extracted[0]["pretend_run"] is True


def test_flags_reach_the_extractor(packed_game, fake_archive):
    saves.unpack_save(packed_game, verbose = True, exit_on_failure = True)

    assert fake_archive.extracted[0]["verbose"] is True
    assert fake_archive.extracted[0]["exit_on_failure"] is True


###########################################################
# Unpacking every game
###########################################################

def catalog_game(tmp_path, name, with_archive = True):
    packed = tmp_path / name / "packed"
    packed.mkdir(parents = True)
    if with_archive:
        (packed / (name + "_1700000000.zip")).write_bytes(b"zip")
    return FakeGameInfo(str(tmp_path / name / "live"), str(packed), name = name)


def test_every_game_with_an_archive_is_unpacked(tmp_path, game, monkeypatch):
    games = {
        "First": catalog_game(tmp_path, "First"),
        "Second": catalog_game(tmp_path, "Second", with_archive = False),
        "Third": catalog_game(tmp_path, "Third")}
    make_catalog(monkeypatch, games)
    unpacked = []

    def unpack_save(game_info, **kwargs):
        unpacked.append((game_info.get_name(), kwargs))
        return True
    monkeypatch.setattr(saves, "unpack_save", unpack_save)

    assert saves.unpack_all_saves(pretend_run = True) is True
    assert [name for name, _ in unpacked] == ["First", "Third"]
    assert unpacked[0][1]["pretend_run"] is True


def test_a_game_without_an_archive_does_not_stop_unpacking(tmp_path, game, fake_archive, monkeypatch):
    games = {
        "Empty": catalog_game(tmp_path, "Empty", with_archive = False),
        "Packed": catalog_game(tmp_path, "Packed")}
    make_catalog(monkeypatch, games)

    assert saves.unpack_all_saves() is True
    assert len(fake_archive.extracted) == 1


def test_the_first_failed_unpack_stops_the_run(tmp_path, game, monkeypatch):
    games = {
        "First": catalog_game(tmp_path, "First"),
        "Second": catalog_game(tmp_path, "Second")}
    make_catalog(monkeypatch, games)
    unpacked = []

    def unpack_save(game_info, **kwargs):
        unpacked.append(game_info.get_name())
        return False
    monkeypatch.setattr(saves, "unpack_save", unpack_save)

    assert saves.unpack_all_saves() is False
    assert unpacked == ["First"]
