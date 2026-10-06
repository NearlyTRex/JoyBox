# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox.cli import clean_game_hash_files


###########################################################
# Sorting
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings):
    harness = CommandHarness(monkeypatch, clean_game_hash_files)
    harness.sorted = []
    harness.result = True

    def sort(**kwargs):
        harness.sorted.append(kwargs)
        return harness.result

    monkeypatch.setattr(clean_game_hash_files.collection, "sort_all_hash_files", sort)
    return harness


def test_every_hash_file_is_sorted(tool):
    tool.run("--no-preview", "-p")

    assert tool.sorted == [{"verbose": False, "pretend_run": True, "exit_on_failure": False}]


def test_the_preview_names_the_hash_directory(tool):
    tool.run()

    [(_, details)] = tool.previews
    assert details[0].endswith("Hashes")
    assert len(tool.sorted) == 1


def test_a_cancelled_preview_sorts_nothing(tool):
    tool.confirm = False

    tool.run()

    assert tool.sorted == []


def test_a_failed_sort_exits_with_an_error(tool):
    tool.result = False

    assert tool.exit_code("--no-preview") != 0

    assert tool.errors == ["Sort of hash file failed!"]


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, clean_game_hash_files)
