# Imports
import pytest

# Local imports
from cli_helpers import CommandHarness, Recorder, assert_entry_points
from joybox.cli import compress_folders

ARCHIVE_PHRASE = "folder-archive-phrase"


###########################################################
# compress_folders
#
# Only top-level folders are compressed, and a folder whose archive already
# exists is skipped.
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings):
    command = CommandHarness(monkeypatch, compress_folders)
    command.create = Recorder(result = True)
    monkeypatch.setattr(compress_folders.archive, "create_archive_from_folder", command.create)
    return command


@pytest.fixture
def folders(tmp_path):
    for name in ["new", "done", "new/nested"]:
        (tmp_path / name).mkdir()
    (tmp_path / "done.zip").write_bytes(b"")
    (tmp_path / "loose.txt").write_bytes(b"")
    return tmp_path


def test_each_top_level_folder_without_an_archive_is_compressed(tool, folders):
    tool.main("-i", str(folders), "--no-preview")

    assert tool.create.calls == [{
        "archive_file": str(folders / "new.zip"),
        "source_dir": str(folders / "new"),
        "password": None,
        "volume_size": None,
        "delete_original": False,
        "verbose": False,
        "pretend_run": False,
        "exit_on_failure": False}]


def test_archive_options_reach_the_archiver(tool, folders):
    tool.main("-i", str(folders), "--no-preview", "-a", "7Z", "-w", ARCHIVE_PHRASE, "-s", "100m", "-d")

    assert tool.create.values("archive_file") == [str(folders / "done.7z"), str(folders / "new.7z")]
    call = tool.create.calls[0]
    assert (call["password"], call["volume_size"], call["delete_original"]) == (ARCHIVE_PHRASE, "100m", True)


def test_the_preview_shows_the_archive_type(tool, folders):
    tool.main("-i", str(folders))

    assert tool.previews == [("Compress folders", ["Path: %s" % folders, "Archive type: ZIP", "Delete originals: False"])]


def test_a_declined_preview_compresses_nothing(tool, folders):
    tool.confirm = False

    tool.main("-i", str(folders))

    assert tool.create.calls == []


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, compress_folders)
