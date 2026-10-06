# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, Recorder, assert_entry_points
from joybox.cli import compress_files


###########################################################
# File selection
###########################################################

@pytest.fixture
def tool(monkeypatch, tmp_path):
    harness = CommandHarness(monkeypatch, compress_files)
    harness.created = Recorder(result = True)
    monkeypatch.setattr(compress_files.archive, "create_archive_from_file", harness.created)
    for name in ("Game.iso", "Game.bin", "Done.iso", "Done.zip", "Done.7z"):
        (tmp_path / name).write_bytes(b"x")
    (tmp_path / "Folder.iso").mkdir()
    return harness


def compressed(tool):
    return sorted(call["source_file"].rsplit("/", 1)[-1] for call in tool.created.calls)


def test_every_file_without_an_archive_is_compressed_by_default(tool, tmp_path):
    tool.run("-i", str(tmp_path), "--no-preview")

    assert compressed(tool) == ["Game.bin", "Game.iso"]


def test_only_the_selected_suffixes_are_compressed(tool, tmp_path):
    tool.run("-i", str(tmp_path), "--no-preview", "-t", ".iso", "-a", "7Z", "-w", "pw", "-s", "4g", "-d")

    assert tool.created.calls == [{"archive_file": str(tmp_path / "Game.7z"), "source_file": str(tmp_path / "Game.iso"),
        "password": "pw", "volume_size": "4g", "delete_original": True,
        "verbose": False, "pretend_run": False, "exit_on_failure": False}]


def test_a_confirmed_preview_compresses(tool, tmp_path):
    tool.run("-i", str(tmp_path), "-t", ".bin")

    assert len(tool.previews) == 1
    assert compressed(tool) == ["Game.bin"]


def test_the_preview_lists_the_settings_and_a_decline_compresses_nothing(tool, tmp_path):
    tool.confirm = False

    tool.run("-i", str(tmp_path), "-t", ".iso")

    assert tool.previews == [("Compress files", ["Path: %s" % tmp_path, "Archive type: ZIP",
        "File types: .iso", "Delete originals: False"])]
    assert tool.created.calls == []
    assert tool.warnings == ["Operation cancelled by user"]


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, compress_files)
