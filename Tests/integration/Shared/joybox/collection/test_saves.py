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
