# Imports
import pytest

# Local imports
from cli_helpers import CommandHarness, Recorder, assert_entry_points
from joybox.cli import chdzip


###########################################################
# chdzip
#
# Each .chd is archived beside itself, unless its zip already exists.
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings):
    command = CommandHarness(monkeypatch, chdzip)
    command.archive = Recorder(result = True)
    monkeypatch.setattr(chdzip.chd, "archive_disc_chd", command.archive)
    return command


@pytest.fixture
def discs(tmp_path):
    for name in ["new.chd", "done.chd", "done.zip"]:
        (tmp_path / name).write_bytes(b"")
    return tmp_path


def test_each_chd_without_a_zip_is_archived(tool, discs):
    tool.main("-i", str(discs), "--no-preview", "-d", "-p")

    assert tool.archive.calls == [{
        "chd_file": str(discs / "new.chd"),
        "zip_file": str(discs / "new.zip"),
        "delete_original": True,
        "verbose": False,
        "pretend_run": True,
        "exit_on_failure": False}]


def test_the_preview_shows_whether_originals_are_deleted(tool, discs):
    tool.main("-i", str(discs))

    assert tool.previews == [("CHD to ZIP", ["Path: %s" % discs, "Delete originals: False"])]


def test_a_declined_preview_archives_nothing(tool, discs):
    tool.confirm = False

    tool.main("-i", str(discs))

    assert tool.archive.calls == []
    assert tool.warnings == ["Operation cancelled by user"]


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, chdzip)
