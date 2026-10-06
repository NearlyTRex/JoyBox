# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox import config
from joybox.cli import build_game_json_files


###########################################################
# Game roots
#
# Each game is built from the input path, the given locker root, or (with
# neither) wherever collection looks it up; a failed build stops the run.
###########################################################

CATEGORIES = (config.Supercategory.ROMS, config.Category.NINTENDO, config.Subcategory.NINTENDO_SWITCH)


@pytest.fixture
def tool(monkeypatch, isolated_settings):
    harness = CommandHarness(monkeypatch, build_game_json_files)
    harness.built = []
    harness.listed = []
    harness.result = True
    module = build_game_json_files
    monkeypatch.setattr(module.gameinfo, "iterate_selected_game_categories", lambda **kwargs: iter([CATEGORIES]))

    def find_names(*args):
        harness.listed.append(args)
        return ["Alpha", "Beta"]

    def build(**kwargs):
        harness.built.append((kwargs["game_name"], kwargs["game_root"], kwargs["locker_type"]))
        return harness.result

    monkeypatch.setattr(module.gameinfo, "find_locker_game_names", find_names)
    monkeypatch.setattr(module.collection, "build_game_json_file", build)
    return harness


def test_without_a_root_every_game_is_built_from_its_locker(tool):
    tool.run("--no-preview", "-l", "Hetzner")

    assert tool.built == [("Alpha", None, config.LockerType.HETZNER), ("Beta", None, config.LockerType.HETZNER)]
    assert tool.listed == [(*CATEGORIES, config.LockerType.HETZNER, None)]


def test_a_game_name_selects_only_that_game(tool):
    tool.run("--no-preview", "-n", "Beta")

    assert [name for name, _, _ in tool.built] == ["Beta"]


def test_an_input_path_is_the_root_of_every_game(tool, tmp_path):
    tool.run("--no-preview", "-i", str(tmp_path))

    assert [root for _, root, _ in tool.built] == [str(tmp_path), str(tmp_path)]


def test_a_locker_base_dir_roots_each_game_in_its_gaming_folder(tool, tmp_path):
    tool.run("--no-preview", "-b", str(tmp_path), "-n", "Alpha")

    [(_, root, _)] = tool.built
    assert root.startswith(str(tmp_path / "Gaming"))
    assert "Alpha" in root
    assert tool.listed[0][-1] == str(tmp_path)


def test_the_preview_lists_each_json_file(tool):
    tool.run()

    [(_, details)] = tool.previews
    assert len(details) == 2
    assert all(detail.endswith(".json") for detail in details)
    assert len(tool.built) == 2


def test_a_cancelled_preview_builds_nothing(tool):
    tool.confirm = False

    tool.run()

    assert tool.built == []
    assert tool.warnings == ["Operation cancelled by user"]


def test_a_failed_build_stops_the_run(tool):
    tool.result = False

    assert tool.exit_code("--no-preview") != 0

    assert tool.errors == ["Build of json file failed!"]
    assert len(tool.built) == 1


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, build_game_json_files)
