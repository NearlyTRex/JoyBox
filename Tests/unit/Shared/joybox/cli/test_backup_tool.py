# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, Recorder, assert_entry_points
from joybox import config
from joybox.cli import backup_tool


###########################################################
# Path resolution and dispatch
###########################################################

@pytest.fixture
def tool(monkeypatch, tmp_path):
    harness = CommandHarness(monkeypatch, backup_tool)
    harness.source = tmp_path / "source"
    harness.dest = tmp_path / "dest"
    harness.source.mkdir()
    harness.dest.mkdir()
    harness.copies = Recorder(result = True)
    harness.archives = Recorder(result = True)

    def resolve(path, base_path, game_offset, **kwargs):
        if base_path:
            return str(tmp_path / base_path / (game_offset or ""))
        return path

    monkeypatch.setattr(backup_tool.backup, "resolve_path", resolve)
    monkeypatch.setattr(backup_tool.backup, "copy_files", harness.copies)
    monkeypatch.setattr(backup_tool.backup, "archive_sub_folders", harness.archives)
    harness.paths = ["-i", str(harness.source), "-o", str(harness.dest)]
    return harness


def test_a_plain_copy_skips_errors_into_a_log_by_default(tool):
    tool.run(*tool.paths, "-w", "Saves,,Cache", "-e")

    [copy] = tool.copies.calls
    assert copy["input_base_path"] == str(tool.source)
    assert copy["output_base_path"] == str(tool.dest)
    assert copy["cryption_type"] == config.CryptionType.NONE
    assert copy["locker_type"] is None
    assert copy["exclude_paths"] == ["Saves", "Cache"]
    assert copy["skip_existing"] is True
    assert copy["skip_on_error"] is True
    assert copy["error_log_path"] == str(tool.dest / "copy_errors.txt")
    assert tool.previews == [("Backup files", ["Source: %s" % tool.source, "Destination: %s" % tool.dest, "Type: Copy"])]


def test_exit_on_failure_copies_without_an_error_log(tool):
    tool.run(*tool.paths, "-x", "--no-preview")

    assert tool.copies.calls[0]["skip_on_error"] is False
    assert tool.copies.calls[0]["error_log_path"] is None


@pytest.mark.parametrize("cryption, locker", [
    ("Encrypt", config.LockerType.HETZNER),
    ("Decrypt", config.LockerType.GDRIVE),
])
def test_the_passphrase_comes_from_the_encrypted_side(tool, cryption, locker):
    tool.run(*tool.paths, "-r", cryption, "-l", "Gdrive", "-d", "Hetzner", "--delete_original")

    assert tool.copies.calls[0]["locker_type"] == locker
    assert tool.copies.calls[0]["delete_original"] is True
    assert tool.previews[0][1][-1] == "Cryption: %s" % cryption


def test_archive_mode_archives_each_sub_folder(tool):
    tool.run(*tool.paths, "-b", "Archive", "-a", "--no-preview")

    assert tool.copies.calls == []
    [archive] = tool.archives.calls
    assert archive["archive_type"] == config.ArchiveFileType.SEVENZIP
    assert archive["skip_identical"] is True


def test_a_missing_source_is_refused(tool, tmp_path):
    assert tool.exit_code("-i", str(tmp_path / "gone"), "-o", str(tool.dest)) != 0
    assert tool.errors == ["Could not resolve source path"]


def test_a_missing_destination_is_refused(tool, tmp_path):
    assert tool.exit_code("-i", str(tool.source), "-o", str(tmp_path / "gone")) != 0
    assert tool.errors == ["Could not resolve destination path"]


def test_a_destination_under_an_output_locker_base_is_created(tool, tmp_path):
    (tmp_path / "base").mkdir()

    tool.run("-i", str(tool.source), "--output_locker_base", str(tmp_path / "base"), "-g", "Game", "--no-preview")

    assert (tmp_path / "base" / "Game").is_dir()
    assert tool.copies.calls[0]["output_base_path"] == str(tmp_path / "base" / "Game")


def test_a_missing_output_locker_base_is_refused(tool, tmp_path):
    assert tool.exit_code("-i", str(tool.source), "--output_locker_base", str(tmp_path / "nowhere")) != 0
    assert tool.errors == ["Could not resolve destination path"]


def test_source_and_destination_must_differ(tool):
    assert tool.exit_code("-i", str(tool.source), "-o", str(tool.source)) != 0
    assert tool.errors == ["Source and destination paths cannot be the same"]


def test_a_declined_preview_copies_nothing(tool):
    tool.confirm = False

    tool.run(*tool.paths)

    assert tool.copies.calls == []
    assert tool.warnings == ["Operation cancelled by user"]


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, backup_tool)
