# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox.cli import decompress_archives


###########################################################
# Extraction targets
#
# Each archive goes into a folder named after it, or beside it with -s.
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings, tmp_path):
    harness = CommandHarness(monkeypatch, decompress_archives)
    harness.extracted = []
    monkeypatch.setattr(decompress_archives.archive, "extract_archive", lambda **kwargs: harness.extracted.append(kwargs))
    for name in ("one.zip", "two.7z", "three.txt"):
        (tmp_path / name).write_bytes(b"")
    return harness


def test_each_archive_is_extracted_into_its_own_folder(tool, tmp_path):
    tool.run("--no-preview", "-i", str(tmp_path), "-d")

    [call] = tool.extracted
    assert call["archive_file"] == str(tmp_path / "one.zip")
    assert call["extract_dir"] == str(tmp_path / "one")
    assert call["delete_original"] is True


def test_same_dir_extracts_beside_the_archive(tool, tmp_path):
    tool.run("--no-preview", "-i", str(tmp_path), "-a", "7Z", "-s")

    [call] = tool.extracted
    assert call["archive_file"] == str(tmp_path / "two.7z")
    assert call["extract_dir"] == str(tmp_path)


def test_the_preview_describes_the_run(tool, tmp_path):
    tool.run("-i", str(tmp_path))

    [(title, details)] = tool.previews
    assert title == "Decompress archives"
    assert details[0] == "Path: %s" % tmp_path
    assert len(tool.extracted) == 1


def test_a_cancelled_preview_extracts_nothing(tool, tmp_path):
    tool.confirm = False

    tool.run("-i", str(tmp_path))

    assert tool.extracted == []


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, decompress_archives)
