# Imports
import sys
import types

# Third-party imports
import pytest

# Local imports
from cli_helpers import assert_entry_points
from joybox import config
from joybox import collection
from joybox.cli import save_game_tool


###########################################################
# save_game_tool
#
# With no game named, every selected game is visited. Pack and Unpack skip
# the games with nothing to do instead of treating them as failures, so one
# game without a save cannot stop the run.
###########################################################

class FakeGameInfo:

    def __init__(self, name, save_dir, local_save_dir):
        self.name = name
        self.save_dir = save_dir
        self.local_save_dir = local_save_dir

    def get_name(self):
        return self.name

    def get_save_dir(self):
        return self.save_dir

    def get_local_save_dir(self):
        return self.local_save_dir

    def get_supercategory(self):
        return config.Supercategory.ROMS

    def get_category(self):
        return config.Category.NINTENDO

    def get_subcategory(self):
        return config.Subcategory.NINTENDO_SNES


def make_game(tmp_path, name, live = False, packed = False):
    root = tmp_path / name
    (root / "live").mkdir(parents = True)
    (root / "packed").mkdir()
    if live:
        (root / "live" / "slot1.sav").write_bytes(b"save")
    if packed:
        (root / "packed" / (name + "_1700000000.zip")).write_bytes(b"zip")
    return FakeGameInfo(name, str(root / "live"), str(root / "packed"))


class Run:

    def __init__(self):
        self.handled = []
        self.errors = []
        self.infos = []
        self.previews = []
        self.result = True


@pytest.fixture
def run(monkeypatch, isolated_settings):
    state = Run()
    state.games = []

    def handler(game_info, **kwargs):
        state.handled.append((game_info.get_name(), kwargs))
        return state.result

    def log_error(message, quit_program = False, **kwargs):
        state.errors.append((message, kwargs))
        if quit_program:
            raise SystemExit(1)

    def prompt_for_preview(title, details):
        state.previews.append((title, details))
        return True

    for name in ["pack_save", "unpack_save", "import_game_save", "export_game_save", "import_game_save_paths"]:
        monkeypatch.setattr(collection, name, handler)
    monkeypatch.setattr(save_game_tool.setup, "check_requirements", lambda: None)
    monkeypatch.setattr(save_game_tool, "logger", types.SimpleNamespace(
        setup_logging = lambda: None,
        log_error = log_error,
        log_info = state.infos.append,
        log_warning = state.infos.append))
    monkeypatch.setattr(save_game_tool, "gameinfo", types.SimpleNamespace(
        iterate_selected_game_infos = lambda **kwargs: iter(state.games)))
    monkeypatch.setattr(save_game_tool, "prompts", types.SimpleNamespace(
        prompt_for_preview = prompt_for_preview))

    def invoke(*args):
        monkeypatch.setattr(sys, "argv", ["save_game_tool", *args])
        return save_game_tool.main()
    state.invoke = invoke
    return state


def handled_names(run):
    return [name for name, _ in run.handled]


###########################################################
# Skipping games with nothing to do
###########################################################

def test_pack_skips_games_without_a_save(run, tmp_path):
    run.games = [
        make_game(tmp_path, "Empty"),
        make_game(tmp_path, "Saved", live = True)]

    run.invoke("-a", "Pack", "--no-preview")

    assert handled_names(run) == ["Saved"]
    assert run.errors == []


def test_unpack_skips_games_without_an_archive(run, tmp_path):
    run.games = [
        make_game(tmp_path, "Unpacked"),
        make_game(tmp_path, "Packed", packed = True)]

    run.invoke("-a", "Unpack", "--no-preview")

    assert handled_names(run) == ["Packed"]


def test_unpack_skips_games_whose_live_save_would_be_overwritten(run, tmp_path):
    run.games = [make_game(tmp_path, "Playing", live = True, packed = True)]

    run.invoke("-a", "Unpack", "--no-preview")

    assert run.handled == []


def test_skipped_games_are_reported_in_verbose_mode(run, tmp_path):
    run.games = [make_game(tmp_path, "Empty")]

    run.invoke("-a", "Pack", "--no-preview", "-v")

    assert run.infos == ["Nothing to pack for Empty"]


def test_skipped_games_are_left_out_of_the_preview(run, tmp_path):
    run.games = [
        make_game(tmp_path, "Empty"),
        make_game(tmp_path, "Saved", live = True)]

    run.invoke("-a", "Pack")

    assert run.previews == [("Save game Pack", ["Nintendo/Nintendo SNES/Saved"])]


@pytest.mark.parametrize("action", ["Export", "Import", "ImportSavePaths"])
def test_other_actions_visit_every_game(run, tmp_path, action):
    # Their handlers already treat nothing to do as success.
    run.games = [make_game(tmp_path, "Empty"), make_game(tmp_path, "Saved", live = True)]

    run.invoke("-a", action, "--no-preview")

    assert handled_names(run) == ["Empty", "Saved"]


###########################################################
# Dispatch
###########################################################

def test_pack_and_export_receive_the_locker(run, tmp_path):
    run.games = [make_game(tmp_path, "Saved", live = True)]

    run.invoke("-a", "Pack", "-l", "Hetzner", "--no-preview", "-p", "-x")

    kwargs = run.handled[0][1]
    assert kwargs["locker_type"] == config.LockerType.HETZNER
    assert (kwargs["verbose"], kwargs["pretend_run"], kwargs["exit_on_failure"]) == (False, True, True)


def test_unpack_receives_no_locker(run, tmp_path):
    run.games = [make_game(tmp_path, "Packed", packed = True)]

    run.invoke("-a", "Unpack", "--no-preview")

    assert "locker_type" not in run.handled[0][1]


def test_a_failed_game_stops_the_run(run, tmp_path):
    run.games = [
        make_game(tmp_path, "First", live = True),
        make_game(tmp_path, "Second", live = True)]
    run.result = False

    with pytest.raises(SystemExit):
        run.invoke("-a", "Pack", "--no-preview")
    assert handled_names(run) == ["First"]
    assert run.errors[0][0] == "Packing of save failed!"
    assert run.errors[0][1]["game_name"] == "First"


def test_a_declined_preview_processes_nothing(run, tmp_path, monkeypatch):
    run.games = [make_game(tmp_path, "Saved", live = True)]
    monkeypatch.setattr(save_game_tool, "prompts", types.SimpleNamespace(
        prompt_for_preview = lambda title, details: False))

    run.invoke("-a", "Pack")

    assert run.handled == []
    assert run.infos == ["Operation cancelled by user"]


###########################################################
# Entry point
###########################################################

def test_every_action_has_a_handler(run, tmp_path):
    run.games = [make_game(tmp_path, "Saved", live = True)]
    for action in config.SaveActionType.members():
        run.invoke("-a", action.val(), "--no-preview")

    assert run.errors == []


def test_run_reports_a_clean_finish(run, tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["save_game_tool", "-a", "Export", "--no-preview"])
    run.games = [make_game(tmp_path, "Saved", live = True)]

    save_game_tool.run()

    assert handled_names(run) == ["Saved"]


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, save_game_tool)
