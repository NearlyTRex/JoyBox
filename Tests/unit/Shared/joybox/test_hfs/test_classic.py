# Imports
import os
import sys

# Third-party imports
import machfs
import pytest

# Local imports
from joybox import hfs
from hfs_helpers import CLASSIC_VOLUME_SIZE, NEW_YEAR_2005, make_classic_volume, make_apm_image, make_signed_image, make_file, read_appledouble_entries


###########################################################
# Classic HFS
#
# machfs reads the volume; each file's data fork becomes the file and its
# Finder info and resource fork an AppleDouble file beside it.
###########################################################

@pytest.fixture
def image(tmp_path):
    target = tmp_path / "Game.iso"
    target.write_bytes(make_apm_image(make_classic_volume()))
    return str(target)


def test_extracting_writes_the_data_forks_and_folders(image, tmp_path):
    output = tmp_path / "Game"

    assert hfs.extract_hfs(image, str(output)) is True

    assert (output / "Read Me").read_bytes() == b"plain text"
    assert (output / "Start").read_bytes() == b"code"
    assert (output / "Extras" / "Either:Or").read_bytes() == b"slashed"


def test_extracting_writes_appledouble_only_beside_mac_files(image, tmp_path):
    output = tmp_path / "Game"
    hfs.extract_hfs(image, str(output))

    _, _, entries = read_appledouble_entries((output / "._Start").read_bytes())
    assert entries[hfs.appledouble_entry_finder_info][:8] == b"APPLPJ03"
    assert entries[hfs.appledouble_entry_resource_fork] == b"resources"
    assert not (output / "._Read Me").exists()


def test_extracting_keeps_the_modified_date(image, tmp_path):
    output = tmp_path / "Game"
    hfs.extract_hfs(image, str(output))

    assert os.path.getmtime(str(output / "Read Me")) == NEW_YEAR_2005 - hfs.hfs_to_unix_seconds


def test_an_unusable_name_is_skipped(tmp_path, caplog):
    folder = machfs.Folder()
    folder[".."] = make_file(data = b"escape")
    folder["Kept"] = make_file(data = b"kept")

    assert hfs.extract_hfs_folder(folder, str(tmp_path / "out")) is True
    assert sorted(os.listdir(str(tmp_path / "out"))) == ["Kept"]
    assert "unusable name '..'" in caplog.text


def test_an_unreadable_volume_reports_failure(tmp_path, caplog):
    target = tmp_path / "Game.iso"
    target.write_bytes(make_signed_image(b"BD"))

    assert hfs.extract_hfs(str(target), str(tmp_path / "Game")) is False
    assert "Unable to read the HFS volume" in caplog.text


def test_a_volume_past_the_end_of_the_image_reports_failure(image, tmp_path):
    assert hfs.extract_hfs_volume(image, CLASSIC_VOLUME_SIZE * 2, CLASSIC_VOLUME_SIZE, str(tmp_path / "Game")) is False


def test_extracting_without_machfs_reports_failure(monkeypatch, image, tmp_path, caplog):
    monkeypatch.setitem(sys.modules, "machfs", None)

    assert hfs.extract_hfs(image, str(tmp_path / "Game")) is False
    assert "machfs was not found" in caplog.text


@pytest.mark.parametrize("failing_path", ["Game", "Game/Read Me", "Game/._Start", "Game/Extras"])
def test_a_write_that_fails_stops_the_extraction(monkeypatch, image, tmp_path, failing_path):
    failing = str(tmp_path / failing_path)
    make_directory, touch_file = hfs.fileops.make_directory, hfs.fileops.touch_file
    monkeypatch.setattr(hfs.fileops, "make_directory", lambda src, **kwargs: src != failing and make_directory(src, **kwargs))
    monkeypatch.setattr(hfs.fileops, "touch_file", lambda src, **kwargs: src != failing and touch_file(src, **kwargs))

    assert hfs.extract_hfs(image, str(tmp_path / "Game")) is False
