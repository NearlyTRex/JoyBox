# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, Recorder, assert_entry_points
from joybox.cli import isoextract


###########################################################
# Extraction method
###########################################################

@pytest.fixture
def tool(monkeypatch, tmp_path):
    harness = CommandHarness(monkeypatch, isoextract)
    harness.iso_calls = Recorder(result = True)
    harness.archive_calls = Recorder(result = True)
    harness.hfs_calls = Recorder(result = True)
    monkeypatch.setattr(isoextract.iso, "extract_iso", harness.iso_calls)
    monkeypatch.setattr(isoextract.hfs, "extract_hfs", harness.hfs_calls)
    monkeypatch.setattr(isoextract.archive, "extract_archive", harness.archive_calls)
    (tmp_path / "Game.iso").write_bytes(b"x")
    (tmp_path / "Done.iso").write_bytes(b"x")
    (tmp_path / "Done").mkdir()
    return harness


def test_iso_method_extracts_each_image_not_yet_extracted(tool, tmp_path):
    tool.run("-i", str(tmp_path), "-d")

    assert tool.iso_calls.calls == [{"iso_file": str(tmp_path / "Game.iso"), "extract_dir": str(tmp_path / "Game"),
        "delete_original": True, "verbose": False, "pretend_run": False, "exit_on_failure": False}]
    assert tool.archive_calls.calls == []


def test_archive_method_extracts_through_7zip(tool, tmp_path):
    tool.run("-i", str(tmp_path), "-e", "Archive", "-s")

    assert tool.iso_calls.calls == []
    assert [(call["archive_file"], call["extract_dir"], call["skip_existing"]) for call in tool.archive_calls.calls] == [
        (str(tmp_path / "Game.iso"), str(tmp_path / "Game"), True)]


@pytest.mark.parametrize("method", ["Iso", "Archive"])
def test_hfs_filesystem_extracts_the_mac_side_with_either_method(tool, tmp_path, method):
    tool.run("-i", str(tmp_path), "-f", "HFS", "-e", method, "-d")

    assert tool.iso_calls.calls == []
    assert tool.archive_calls.calls == []
    assert tool.hfs_calls.calls == [{"image_file": str(tmp_path / "Game.iso"), "extract_dir": str(tmp_path / "Game"),
        "delete_original": True, "verbose": False, "pretend_run": False, "exit_on_failure": False}]


def test_iso_filesystem_is_the_default(tool, tmp_path):
    tool.run("-i", str(tmp_path), "-f", "ISO")

    assert len(tool.iso_calls.calls) == 1
    assert tool.hfs_calls.calls == []


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, isoextract)
