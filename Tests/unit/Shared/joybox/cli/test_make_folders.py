# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox.cli import make_folders


###########################################################
# Folder per file
###########################################################

@pytest.fixture
def tool(monkeypatch, tmp_path):
    for name in ("Game.iso", "Other.chd", "notes.txt"):
        (tmp_path / name).write_text(name)
    (tmp_path / "Existing").mkdir()
    return CommandHarness(monkeypatch, make_folders)


def test_matching_files_move_into_a_folder_of_their_name(tool, tmp_path):
    tool.run("-i", str(tmp_path))

    assert (tmp_path / "Game" / "Game.iso").read_text() == "Game.iso"
    assert (tmp_path / "Other" / "Other.chd").read_text() == "Other.chd"
    assert (tmp_path / "notes.txt").is_file()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["Existing", "Game", "Other", "notes.txt"]


def test_only_the_selected_file_types_move(tool, tmp_path):
    tool.run("-i", str(tmp_path), "-f", ".txt")

    assert (tmp_path / "notes" / "notes.txt").is_file()
    assert (tmp_path / "Game.iso").is_file()


def test_a_pretend_run_moves_nothing(tool, tmp_path):
    tool.run("-i", str(tmp_path), "-p")

    assert (tmp_path / "Game.iso").is_file()
    assert not (tmp_path / "Game").exists()


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, make_folders)
