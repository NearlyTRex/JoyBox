# Imports
from typing import ClassVar

# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox.cli import dat_renamer


###########################################################
# dat_renamer
#
# Records come from the DAT directory when it exists, otherwise from the
# cache file; the input is renamed from whatever was loaded.
###########################################################

class FakeDat:

    log: ClassVar[list] = []

    def import_clrmamepro_dat_files(self, dat_dir, **kwargs):
        FakeDat.log.append(("import_dats", dat_dir))

    def export_cache_dat_file(self, dat_file, **kwargs):
        FakeDat.log.append(("export_cache", dat_file))

    def import_cache_dat_file(self, dat_file, **kwargs):
        FakeDat.log.append(("import_cache", dat_file))

    def rename_files(self, input_dir, **kwargs):
        FakeDat.log.append(("rename", input_dir))


@pytest.fixture
def tool(monkeypatch, isolated_settings, tmp_path):
    command = CommandHarness(monkeypatch, dat_renamer)
    command.roms = tmp_path / "roms"
    command.dats = tmp_path / "dats"
    command.cache = tmp_path / "cache.dat"
    command.roms.mkdir()
    command.dats.mkdir()
    command.cache.write_text("")
    FakeDat.log = []
    monkeypatch.setattr(dat_renamer.dat, "Dat", FakeDat)
    return command


def test_dat_directory_records_rename_the_input(tool):
    tool.main("-i", str(tool.roms), "-d", str(tool.dats), "-c", str(tool.cache), "--no-preview")

    assert FakeDat.log == [("import_dats", str(tool.dats)), ("rename", str(tool.roms))]


def test_generate_cachefile_writes_the_dat_records_to_the_cache(tool):
    tool.main("-i", str(tool.roms), "-d", str(tool.dats), "-c", str(tool.cache), "-g", "--no-preview")

    assert FakeDat.log == [("import_dats", str(tool.dats)), ("export_cache", str(tool.cache)), ("rename", str(tool.roms))]


def test_the_cache_file_is_read_without_a_dat_directory(tool):
    tool.main("-i", str(tool.roms), "-c", str(tool.cache), "--no-preview")

    assert FakeDat.log == [("import_cache", str(tool.cache)), ("rename", str(tool.roms))]


def test_without_records_the_rename_still_runs(tool):
    tool.main("-i", str(tool.roms), "--no-preview")

    assert FakeDat.log == [("rename", str(tool.roms))]


def test_the_preview_lists_the_record_sources_given(tool):
    tool.main("-i", str(tool.roms), "-d", str(tool.dats), "-c", str(tool.cache))
    tool.main("-i", str(tool.roms))

    assert [details for _, details in tool.previews] == [
        ["Input path: %s" % tool.roms, "DAT directory: %s" % tool.dats, "DAT cachefile: %s" % tool.cache],
        ["Input path: %s" % tool.roms]]


def test_a_declined_preview_renames_nothing(tool):
    tool.confirm = False

    tool.main("-i", str(tool.roms))

    assert FakeDat.log == []


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, dat_renamer)
