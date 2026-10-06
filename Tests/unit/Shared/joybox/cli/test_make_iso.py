# Imports
import pytest

# Local imports
from cli_helpers import CommandHarness, Recorder, assert_entry_points
from joybox.cli import make_iso


###########################################################
# make_iso
#
# Folders, or zips extracted beside themselves, become images named after
# them; one whose image already exists is skipped.
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings):
    command = CommandHarness(monkeypatch, make_iso)
    command.create = Recorder(result = True)
    command.extract = Recorder(result = True)
    monkeypatch.setattr(make_iso.iso, "create_iso", command.create)
    monkeypatch.setattr(make_iso.archive, "extract_archive", command.extract)
    return command


@pytest.fixture
def sources(tmp_path):
    for name in ["Disc A", "Disc B"]:
        (tmp_path / name).mkdir()
    for name in ["Disc B.iso", "Zip A.zip", "Zip B.zip", "Zip B.iso", "loose.txt"]:
        (tmp_path / name).write_bytes(b"")
    return tmp_path


def test_folders_without_an_image_become_images(tool, sources):
    tool.main("-i", str(sources), "-n", "VOLUME", "-d")

    assert tool.create.calls == [{
        "iso_file": str(sources / "Disc A.iso"),
        "source_dir": str(sources / "Disc A"),
        "volume_name": "VOLUME",
        "delete_original": True,
        "verbose": False,
        "pretend_run": False,
        "exit_on_failure": False}]
    assert tool.extract.calls == []


def test_auto_volume_name_uses_the_folder_name(tool, sources):
    tool.main("-i", str(sources), "-n", "VOLUME", "-a")

    assert tool.create.values("volume_name") == ["Disc A"]


def test_zips_without_an_image_are_extracted_then_imaged(tool, sources):
    tool.main("-i", str(sources), "-t", "Zip")

    assert tool.extract.values("archive_file") == [str(sources / "Zip A.zip")]
    assert tool.extract.values("extract_dir") == [str(sources / "Zip A_extracted")]
    assert tool.extract.values("work_dir") == [str(sources)]
    assert tool.create.values("iso_file") == [str(sources / "Zip A.iso")]
    assert tool.create.values("source_dir") == [str(sources / "Zip A_extracted")]
    assert tool.create.values("volume_name") == [""]


def test_auto_volume_name_uses_the_zip_name(tool, sources):
    tool.main("-i", str(sources), "-t", "Zip", "-a")

    assert tool.create.values("volume_name") == ["Zip A"]


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, make_iso)
