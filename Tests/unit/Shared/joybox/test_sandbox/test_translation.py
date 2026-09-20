# Imports
import getpass
import os
import pytest

# Local imports
from joybox import commandoptions, config, sandbox
from sandbox_helpers import options, WINE, SANDBOXIE, NEITHER, PREFIX


###########################################################
# Translating paths across the prefix boundary
###########################################################

def test_a_path_inside_the_prefix_keeps_its_drive_letter(wine_prefix):
    real = os.path.join(wine_prefix.get_prefix_dir(), "drive_c", "Games", "save.dat")

    info = sandbox.get_prefix_path_info(real, wine_prefix, is_real_path = True)

    assert info["letter"] == "c"
    assert info["offset"] == os.path.join("Games", "save.dat")


def test_a_secondary_drive_inside_the_prefix_is_recognised(wine_prefix):
    real = os.path.join(wine_prefix.get_prefix_dir(), "dosdevices", "d:", "Games", "save.dat")

    info = sandbox.get_prefix_path_info(real, wine_prefix, is_real_path = True)

    assert info["letter"] == "d"
    assert info["offset"] == os.path.join("Games", "save.dat")


def test_a_path_outside_the_prefix_is_reached_through_the_z_drive(wine_prefix):
    # Wine maps the host filesystem onto Z:, and building that mapping used to
    # raise instead of returning a path.
    info = sandbox.get_prefix_path_info("/home/user/saves/file.sav", wine_prefix, is_real_path = True)

    assert info["letter"] == "z"
    assert info["virtual"].startswith("Z:")


def test_a_virtual_path_translates_to_a_real_one(wine_prefix):
    real = sandbox.translate_virtual_path_to_real_path("C:/Games/save.dat", wine_prefix)

    assert real == os.path.join(wine_prefix.get_prefix_dir(), "drive_c", "Games", "save.dat")


def test_a_real_path_translates_back_to_a_virtual_one(wine_prefix):
    real = os.path.join(wine_prefix.get_prefix_dir(), "drive_c", "Games", "save.dat")

    assert sandbox.translate_real_path_to_virtual_path(real, wine_prefix) == "C:/Games/save.dat"


def test_a_translation_round_trips(wine_prefix):
    virtual = "C:/Games/Deep/save.dat"

    real = sandbox.translate_virtual_path_to_real_path(virtual, wine_prefix)

    assert sandbox.translate_real_path_to_virtual_path(real, wine_prefix) == virtual


def test_a_path_is_untouched_without_a_prefix():
    plain = options()

    assert sandbox.translate_virtual_path_to_real_path("/home/user/save.dat", plain) == \
        "/home/user/save.dat"


###########################################################
# Bringing results back out of the sandbox
###########################################################

def test_a_file_written_inside_the_prefix_is_moved_out(wine_prefix, monkeypatch):
    # The game wrote to its virtual C: drive; the caller asked for the file at
    # the path it used, not the one inside the prefix.
    moved = []
    monkeypatch.setattr(
        sandbox.fileops, "move_file_or_directory",
        lambda src, dest, **kwargs: moved.append((src, dest)))
    inside = os.path.join(wine_prefix.get_prefix_dir(), "drive_c", "Games")
    os.makedirs(inside)
    with open(os.path.join(inside, "save.dat"), "w") as handle:
        handle.write("payload")

    sandbox.transfer_from_sandbox("C:/Games/save.dat", wine_prefix)

    assert moved == [(os.path.join(inside, "save.dat"), "C:/Games/save.dat")]


def test_a_copy_can_be_left_behind_in_the_sandbox(wine_prefix, tmp_path, monkeypatch):
    # A game that keeps running expects its own save to still be there.
    copied = []
    monkeypatch.setattr(
        sandbox.fileops, "copy_file_or_directory",
        lambda src, dest, **kwargs: copied.append((src, dest)))
    inside = os.path.join(wine_prefix.get_prefix_dir(), "drive_c", "Games")
    os.makedirs(inside)
    with open(os.path.join(inside, "save.dat"), "w") as handle:
        handle.write("payload")

    sandbox.transfer_from_sandbox("C:/Games/save.dat", wine_prefix, keep_in_sandbox = True)

    assert copied == [(os.path.join(inside, "save.dat"), "C:/Games/save.dat")]


def test_a_directory_is_transferred_by_its_contents(wine_prefix, monkeypatch):
    moved = []
    monkeypatch.setattr(
        sandbox.fileops, "move_contents",
        lambda src, dest, **kwargs: moved.append((src, dest)))
    inside = os.path.join(wine_prefix.get_prefix_dir(), "drive_c", "Games")
    os.makedirs(inside)

    sandbox.transfer_from_sandbox("C:/Games", wine_prefix)

    assert moved == [(inside, "C:/Games")]


def test_nothing_is_transferred_when_the_prefix_holds_nothing(wine_prefix, monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("there is nothing in the prefix to transfer")

    monkeypatch.setattr(sandbox.fileops, "move_file_or_directory", fail)
    monkeypatch.setattr(sandbox.fileops, "move_contents", fail)

    sandbox.transfer_from_sandbox("C:/Games/save.dat", wine_prefix)


def test_nothing_is_transferred_without_a_prefix(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("a path outside a prefix is already where it belongs")

    monkeypatch.setattr(sandbox.fileops, "move_file_or_directory", fail)
    monkeypatch.setattr(sandbox.fileops, "move_contents", fail)

    sandbox.transfer_from_sandbox("/home/user/save.dat", options())
