# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox.collection import saves


###########################################################
# Save packing eligibility
#
# Packing archives a game's live save directory into the locker; unpacking
# restores it. Both predicates guard destructive work, so a wrong answer
# either overwrites a live save or silently skips a backup.
###########################################################

def populated(tmp_path, name = "live"):
    directory = tmp_path / name
    directory.mkdir()
    (directory / "save.dat").write_text("data")
    return str(directory)


def empty(tmp_path, name = "empty"):
    directory = tmp_path / name
    directory.mkdir()
    return str(directory)


def absent(tmp_path, name = "absent"):
    return str(tmp_path / name)


###########################################################
# Packing
###########################################################

def test_a_directory_with_saves_is_packable(tmp_path):
    assert saves.is_save_dir_packable(populated(tmp_path)) is True


def test_an_empty_directory_is_not_packable(tmp_path):
    # Packing nothing would replace a good archive with an empty one.
    assert saves.is_save_dir_packable(empty(tmp_path)) is False


def test_a_missing_directory_is_not_packable(tmp_path):
    assert saves.is_save_dir_packable(absent(tmp_path)) is False


def test_nested_saves_count(tmp_path):
    directory = tmp_path / "live"
    (directory / "profile").mkdir(parents = True)
    (directory / "profile" / "save.dat").write_text("data")

    assert saves.is_save_dir_packable(str(directory)) is True


def test_the_output_directory_is_optional(tmp_path):
    # can_save_be_packed asks with only an input directory.
    source = populated(tmp_path)

    assert saves.is_save_dir_packable(source) == \
        saves.is_save_dir_packable(source, absent(tmp_path, "out"))


###########################################################
# Unpacking
###########################################################

def test_an_archive_unpacks_into_a_missing_directory(tmp_path):
    assert saves.is_save_dir_unpackable(
        populated(tmp_path), absent(tmp_path, "out")) is True


def test_an_empty_archive_does_not_unpack(tmp_path):
    assert saves.is_save_dir_unpackable(
        empty(tmp_path), absent(tmp_path, "out")) is False


def test_a_missing_archive_does_not_unpack(tmp_path):
    assert saves.is_save_dir_unpackable(
        absent(tmp_path, "src"), absent(tmp_path, "out")) is False


def test_an_existing_destination_blocks_unpacking(tmp_path):
    # Unpacking over a live save directory would overwrite current progress.
    assert saves.is_save_dir_unpackable(
        populated(tmp_path), populated(tmp_path, "out")) is False


def test_an_existing_empty_destination_blocks_unpacking(tmp_path):
    assert saves.is_save_dir_unpackable(
        populated(tmp_path), empty(tmp_path, "out")) is False


###########################################################
# The two directions
###########################################################

def test_packing_and_unpacking_disagree_about_a_live_directory(tmp_path):
    # A populated directory is what packing wants and what unpacking refuses
    # to overwrite.
    source = populated(tmp_path)
    destination = populated(tmp_path, "out")

    assert saves.is_save_dir_packable(source, destination) is True
    assert saves.is_save_dir_unpackable(source, destination) is False


###########################################################
# Packing and unpacking
#
# A save is archived into the locker and restored from it. These run the real
# archiver, because the failure that matters is an archive that is written but
# cannot be read back.
###########################################################

import os

from joybox import config


class FakeGameInfo:

    def __init__(self, save_dir, local_save_dir, name = "Chrono Trigger (USA)",
                 category = None):
        self.save_dir = save_dir
        self.local_save_dir = local_save_dir
        self.name = name
        self.category = category or config.Category.NINTENDO

    def get_name(self):
        return self.name

    def get_save_dir(self):
        return self.save_dir

    def get_local_save_dir(self):
        return self.local_save_dir

    def get_supercategory(self):
        return config.Supercategory.SAVES

    def get_category(self):
        return self.category

    def get_subcategory(self):
        return config.Subcategory.NINTENDO_NES


@pytest.fixture
def game(tmp_path, monkeypatch):
    live = tmp_path / "live"
    packed = tmp_path / "packed"
    live.mkdir()
    packed.mkdir()
    (live / "slot1.sav").write_bytes(b"save slot one")
    (live / "slot2.sav").write_bytes(b"save slot two")

    # The locker backup is a copy into the packed directory
    def backup(src, dest_rel_path, **kwargs):
        target = packed / os.path.basename(dest_rel_path)
        target.write_bytes(open(src, "rb").read())
        return True

    monkeypatch.setattr(saves.locker, "backup", backup)
    monkeypatch.setattr(
        saves.locker, "convert_to_relative_path", lambda path: os.path.basename(path))
    return FakeGameInfo(str(live), str(packed))


def archives_in(directory):
    return sorted(
        name for name in os.listdir(str(directory)) if name.endswith(".zip"))


###########################################################
# Packing
###########################################################

@pytest.mark.slow
def test_a_save_is_packed(tmp_path, game):
    assert saves.pack_save(game) is True
    assert archives_in(game.get_local_save_dir())


@pytest.mark.slow
def test_a_packed_save_is_named_after_the_game(tmp_path, game):
    saves.pack_save(game)
    packed = archives_in(game.get_local_save_dir())[0]

    assert packed.startswith(game.get_name())
    assert packed.endswith(config.ArchiveFileType.ZIP.cval())


@pytest.mark.slow
def test_a_packed_save_is_timestamped(tmp_path, game):
    # Several packs of the same save must not overwrite one another.
    saves.pack_save(game)
    packed = archives_in(game.get_local_save_dir())[0]
    stamp = packed[len(game.get_name()) + 1:-len(config.ArchiveFileType.ZIP.cval())]

    assert stamp.isdigit()


@pytest.mark.slow
def test_an_empty_save_directory_packs_nothing(tmp_path, game):
    for name in os.listdir(game.get_save_dir()):
        os.remove(os.path.join(game.get_save_dir(), name))

    assert saves.pack_save(game) is False
    assert archives_in(game.get_local_save_dir()) == []


@pytest.mark.slow
def test_an_identical_save_is_not_packed_twice(tmp_path, game):
    # Otherwise every sync would add another copy of an unchanged save.
    saves.pack_save(game)
    first = archives_in(game.get_local_save_dir())

    assert saves.pack_save(game) is True
    assert archives_in(game.get_local_save_dir()) == first


@pytest.mark.slow
def test_a_changed_save_is_packed_again(tmp_path, game):
    # The archive name carries a whole-second timestamp, so a second pack has
    # to land in a later second to get its own file.
    import time

    saves.pack_save(game)
    first = archives_in(game.get_local_save_dir())
    with open(os.path.join(game.get_save_dir(), "slot1.sav"), "wb") as handle:
        handle.write(b"progress was made")
    time.sleep(1.1)

    saves.pack_save(game)
    assert len(archives_in(game.get_local_save_dir())) == len(first) + 1


@pytest.mark.slow
def test_an_explicit_save_directory_is_used(tmp_path, game):
    other = tmp_path / "other"
    other.mkdir()
    (other / "elsewhere.sav").write_bytes(b"elsewhere")

    assert saves.pack_save(game, save_dir = str(other)) is True
    assert archives_in(game.get_local_save_dir())


@pytest.mark.slow
def test_a_computer_save_excludes_its_prefix_directories(tmp_path, game):
    # The wine and sandboxie trees are the prefix, not the save.
    game.category = config.Category.COMPUTER
    for save_type in [config.SaveType.WINE, config.SaveType.SANDBOXIE]:
        nested = os.path.join(game.get_save_dir(), save_type.val())
        os.makedirs(nested, exist_ok = True)
        with open(os.path.join(nested, "prefix.dat"), "wb") as handle:
            handle.write(b"prefix data")

    assert saves.pack_save(game) is True

    restored = tmp_path / "restored"
    packed = archives_in(game.get_local_save_dir())[0]
    saves.archive.extract_archive(
        archive_file = os.path.join(game.get_local_save_dir(), packed),
        extract_dir = str(restored))
    names = {name for _, _, files in os.walk(str(restored)) for name in files}
    assert "prefix.dat" not in names
    assert "slot1.sav" in names


###########################################################
# Unpacking
###########################################################

@pytest.mark.slow
def test_a_packed_save_is_restored(tmp_path, game):
    saves.pack_save(game)
    for name in os.listdir(game.get_save_dir()):
        os.remove(os.path.join(game.get_save_dir(), name))
    os.rmdir(game.get_save_dir())

    assert saves.unpack_save(game) is True
    assert os.path.exists(os.path.join(game.get_save_dir(), "slot1.sav"))


@pytest.mark.slow
def test_restored_content_matches_what_was_packed(tmp_path, game):
    original = open(os.path.join(game.get_save_dir(), "slot1.sav"), "rb").read()
    saves.pack_save(game)
    for name in os.listdir(game.get_save_dir()):
        os.remove(os.path.join(game.get_save_dir(), name))
    os.rmdir(game.get_save_dir())
    saves.unpack_save(game)

    assert open(os.path.join(game.get_save_dir(), "slot1.sav"), "rb").read() == original


@pytest.mark.slow
def test_the_newest_archive_is_the_one_restored(tmp_path, game):
    # Archives are named with a timestamp and picked by sort order, so the
    # newest has to sort last.
    saves.pack_save(game)
    with open(os.path.join(game.get_save_dir(), "slot1.sav"), "wb") as handle:
        handle.write(b"the newer save")
    import time
    time.sleep(1.1)
    saves.pack_save(game)

    for name in os.listdir(game.get_save_dir()):
        os.remove(os.path.join(game.get_save_dir(), name))
    os.rmdir(game.get_save_dir())
    saves.unpack_save(game)

    assert open(os.path.join(game.get_save_dir(), "slot1.sav"), "rb").read() == \
        b"the newer save"


@pytest.mark.slow
def test_an_existing_save_is_not_overwritten(tmp_path, game):
    # Unpacking over a live save would lose progress made since the pack.
    saves.pack_save(game)
    with open(os.path.join(game.get_save_dir(), "slot1.sav"), "wb") as handle:
        handle.write(b"newer progress")

    saves.unpack_save(game)
    assert open(os.path.join(game.get_save_dir(), "slot1.sav"), "rb").read() == \
        b"newer progress"


@pytest.mark.slow
def test_nothing_packed_restores_nothing(tmp_path, game):
    for name in os.listdir(game.get_save_dir()):
        os.remove(os.path.join(game.get_save_dir(), name))
    os.rmdir(game.get_save_dir())

    assert saves.unpack_save(game) is False


@pytest.mark.slow
def test_a_round_trip_preserves_every_file(tmp_path, game):
    before = sorted(os.listdir(game.get_save_dir()))
    saves.pack_save(game)
    for name in os.listdir(game.get_save_dir()):
        os.remove(os.path.join(game.get_save_dir(), name))
    os.rmdir(game.get_save_dir())
    saves.unpack_save(game)

    assert sorted(os.listdir(game.get_save_dir())) == before
