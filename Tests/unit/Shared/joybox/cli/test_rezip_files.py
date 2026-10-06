# Imports
import pytest

# Local imports
from cli_helpers import CommandHarness, Recorder, assert_entry_points
from joybox.cli import rezip_files


###########################################################
# rezip_files
#
# Each zip is unpacked beside itself and repacked in place; a failure at
# either step stops the run before the next zip is touched.
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings):
    command = CommandHarness(monkeypatch, rezip_files)
    command.extract = Recorder(result = True)
    command.create = Recorder(result = True)
    monkeypatch.setattr(rezip_files.archive, "extract_archive", command.extract)
    monkeypatch.setattr(rezip_files.archive, "create_archive_from_folder", command.create)
    return command


@pytest.fixture
def zips(tmp_path):
    for name in ["a.zip", "b.zip", "c.7z"]:
        (tmp_path / name).write_bytes(b"")
    return tmp_path


def test_each_zip_is_unpacked_and_repacked_in_place(tool, zips):
    tool.main("-i", str(zips), "--no-preview")

    assert tool.extract.values("archive_file") == [str(zips / "a.zip"), str(zips / "b.zip")]
    assert tool.extract.values("extract_dir") == [str(zips / "a_extracted"), str(zips / "b_extracted")]
    assert tool.create.values("archive_file") == tool.extract.values("archive_file")
    assert tool.create.values("source_dir") == tool.extract.values("extract_dir")


def test_a_failed_unzip_stops_the_run(tool, zips):
    tool.extract.result = False

    with pytest.raises(SystemExit):
        tool.main("-i", str(zips), "--no-preview")
    assert tool.errors == ["Unable to unzip file %s" % (zips / "a.zip")]
    assert tool.create.calls == []


def test_a_failed_rezip_stops_the_run(tool, zips):
    tool.create.result = False

    with pytest.raises(SystemExit):
        tool.main("-i", str(zips), "--no-preview")
    assert tool.errors == ["Unable to rezip file %s" % (zips / "a.zip")]
    assert len(tool.extract.calls) == 1


def test_a_confirmed_preview_rezips(tool, zips):
    tool.main("-i", str(zips))

    assert len(tool.create.calls) == 2


def test_a_declined_preview_touches_nothing(tool, zips):
    tool.confirm = False

    tool.main("-i", str(zips))

    assert tool.previews == [("Rezip files deterministically", ["Path: %s" % zips])]
    assert tool.extract.calls == []


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, rezip_files)
