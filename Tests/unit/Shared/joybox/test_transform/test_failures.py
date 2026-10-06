# Imports
import os
import types

# Third-party imports
import pytest

# Local imports
from joybox import config, transform


###########################################################
# Transform failures
#
# A step that fails part way must stop its chain and say which step it was;
# carrying on hands the next tool a half-made file.
###########################################################

def game_info(category = None, subcategory = None, transform_file = "game.iso"):
    return types.SimpleNamespace(
        get_name = lambda: "A Game",
        get_category = lambda: category,
        get_subcategory = lambda: subcategory,
        get_transform_file = lambda: transform_file,
        get_key_file = lambda: "game.dkey")


def write(path, contents = "data"):
    path = str(path)
    os.makedirs(os.path.dirname(path), exist_ok = True)
    with open(path, "w") as handle:
        handle.write(contents)
    return path


def fail(**kwargs):
    return False


def succeed(**kwargs):
    return True


###########################################################
# Computer programs
###########################################################

@pytest.fixture
def installer(monkeypatch, tmp_path):
    monkeypatch.setattr(
        transform.environment, "get_cache_gaming_install_dir",
        lambda category, subcategory, name: str(tmp_path / "cache" / name))
    monkeypatch.setattr(transform.computer, "setup_computer_game", succeed)
    monkeypatch.setattr(transform.fileops, "smart_transfer", succeed)
    monkeypatch.setattr(transform.install, "unpack_install_image", succeed)
    return write(tmp_path / "source" / "setup.exe")


@pytest.mark.parametrize("owner, name, reason", [
    ("fileops", "smart_transfer", "Unable to backup computer game install"),
    ("install", "unpack_install_image", "Unable to unpack install image"),
    ("fileops", "touch_file", "Unable to create raw index"),
])
def test_a_failed_computer_step_reports_its_reason(installer, monkeypatch, tmp_path, owner, name, reason):
    monkeypatch.setattr(getattr(transform, owner), name, fail)

    result = transform.transform_computer_programs(game_info(), installer, str(tmp_path / "out"))

    assert result == (False, reason)


###########################################################
# Playlists
###########################################################

def test_only_chd_entries_in_a_playlist_are_extracted(monkeypatch, tmp_path):
    extracted = []
    monkeypatch.setattr(
        transform.chd, "extract_disc_chd",
        lambda chd_file, **kwargs: extracted.append(os.path.basename(chd_file)) or True)
    source = write(tmp_path / "discs" / "Game.m3u", "Disc 1.chd\nnotes.txt\n")

    success, _ = transform.transform_disc_image(source, str(tmp_path / "out"))

    assert success is True
    assert extracted == ["Disc 1.chd"]


def test_a_playlist_that_cannot_be_written_fails(monkeypatch, tmp_path):
    monkeypatch.setattr(transform.chd, "extract_disc_chd", succeed)
    monkeypatch.setattr(transform.playlist, "write_playlist", fail)
    source = write(tmp_path / "discs" / "Game.m3u", "Disc 1.chd\n")

    assert transform.transform_disc_image(source, str(tmp_path / "out")) == (False, "Unable to write playlist")


def test_only_iso_entries_in_an_xbox_playlist_are_rewritten(monkeypatch, tmp_path):
    rewritten = []
    monkeypatch.setattr(
        transform.xbox, "rewrite_xbox_iso",
        lambda iso_file, **kwargs: rewritten.append(os.path.basename(iso_file)) or True)
    source = write(tmp_path / "discs" / "Game.m3u", "Disc 1.iso\ncover.png\n")

    success, _ = transform.transform_xbox_disc_image(source, str(tmp_path / "out"))

    assert success is True
    assert rewritten == ["Disc 1.iso"]


def test_only_iso_entries_in_a_ps3_playlist_are_extracted(monkeypatch, tmp_path):
    extracted = []
    monkeypatch.setattr(
        transform.playstation, "extract_ps3_iso",
        lambda iso_file, **kwargs: extracted.append(os.path.basename(iso_file)) or True)
    source = write(tmp_path / "discs" / "Game.m3u", "Disc 1.iso\nreadme.txt\n")

    success, _ = transform.transform_ps3_disc_image(source, "key.dkey", str(tmp_path / "out"))

    assert success is True
    assert extracted == ["Disc 1.iso"]


###########################################################
# Index files and licences
###########################################################

@pytest.fixture
def no_index(monkeypatch):
    monkeypatch.setattr(transform.fileops, "touch_file", fail)
    monkeypatch.setattr(transform.playstation, "extract_ps3_iso", succeed)
    monkeypatch.setattr(transform.playstation, "extract_psn_pkg", succeed)


@pytest.mark.parametrize("build", [
    lambda source, output: transform.transform_ps3_disc_image(source, "key.dkey", output),
    transform.transform_ps3_network_package,
    transform.transform_psv_network_package,
])
def test_a_missing_index_fails_the_transform(no_index, tmp_path, build):
    source = write(tmp_path / "discs" / "Game.iso")

    assert build(source, str(tmp_path / "out")) == (False, "Unable to create raw index")


def test_a_licence_that_cannot_be_copied_fails(monkeypatch, tmp_path):
    monkeypatch.setattr(transform.playstation, "get_psn_package_content_id", lambda pkg_file: "UP0001-GAME")
    monkeypatch.setattr(transform.fileops, "copy_file_or_directory", fail)
    source = write(tmp_path / "downloads" / "Game.pkg")
    write(tmp_path / "downloads" / "Game.rap")

    result = transform.transform_ps3_network_package(source, str(tmp_path / "out"))

    assert result == (False, "Unable to copy rap files")


def test_a_vita_licence_that_cannot_be_copied_fails(monkeypatch, tmp_path):
    monkeypatch.setattr(transform.fileops, "copy_file_or_directory", fail)
    source = write(tmp_path / "downloads" / "Game.pkg")
    write(tmp_path / "downloads" / "Game.work.bin")

    result = transform.transform_psv_network_package(source, str(tmp_path / "out"))

    assert result == (False, "Unable to copy work.bin files")


def test_a_vita_package_that_cannot_be_extracted_fails(monkeypatch, tmp_path):
    monkeypatch.setattr(transform.playstation, "extract_psn_pkg", fail)
    source = write(tmp_path / "downloads" / "Game.pkg")

    result = transform.transform_psv_network_package(source, str(tmp_path / "out"))

    assert result == (False, "Unable to extract psv pkg files")


###########################################################
# Game file routing
###########################################################

@pytest.fixture
def output_dir(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    return str(output)


def test_no_temporary_directory_means_no_transform(monkeypatch, output_dir):
    monkeypatch.setattr(transform.fileops, "create_temporary_directory", lambda **kwargs: (False, "disk full"))

    result = transform.transform_game_file(game_info(config.Category.COMPUTER), "/src", output_dir)

    assert result == (False, "disk full")


def produce():
    def run(output_dir, **kwargs):
        path = write(os.path.join(output_dir, "made.iso"))
        return (True, path)
    return run


@pytest.mark.parametrize("subcategory, first, failing", [
    (config.Subcategory.MICROSOFT_XBOX, "transform_disc_image", "transform_xbox_disc_image"),
    (config.Subcategory.SONY_PLAYSTATION_3, None, "transform_disc_image"),
    (config.Subcategory.SONY_PLAYSTATION_3, "transform_disc_image", "transform_ps3_disc_image"),
    (config.Subcategory.SONY_PLAYSTATION_NETWORK_PS3, None, "transform_ps3_network_package"),
    (config.Subcategory.SONY_PLAYSTATION_NETWORK_PSV, None, "transform_psv_network_package"),
])
def test_a_failing_platform_step_reports_its_reason(monkeypatch, tmp_path, output_dir, subcategory, first, failing):
    if first:
        monkeypatch.setattr(transform, first, produce())
    monkeypatch.setattr(transform, failing, lambda **kwargs: (False, failing + " failed"))

    result = transform.transform_game_file(game_info(subcategory = subcategory), "/src", output_dir)

    assert result == (False, failing + " failed")


def test_output_that_cannot_be_moved_fails(monkeypatch, tmp_path, output_dir):
    monkeypatch.setattr(transform, "transform_computer_programs", produce())
    monkeypatch.setattr(transform.fileops, "move_contents", fail)

    result = transform.transform_game_file(game_info(config.Category.COMPUTER), "/src", output_dir)

    assert result == (False, "Unable to move transformed output")


def test_a_failed_transform_removes_its_temporary_directory(monkeypatch, tmp_path, output_dir):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(transform.fileops, "create_temporary_directory", lambda **kwargs: (True, str(scratch)))
    monkeypatch.setattr(transform, "transform_computer_programs", produce())
    monkeypatch.setattr(transform.fileops, "move_contents", fail)

    transform.transform_game_file(game_info(config.Category.COMPUTER), "/src", output_dir)

    assert not scratch.exists()
