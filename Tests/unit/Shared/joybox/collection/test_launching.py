# Imports
import types

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.collection import launching


###########################################################
# Launching games
#
# A launch installs the game, restores its save, runs it and packs the save
# again. The save is exported to the same locker the launch was given, and a
# failed step stops everything after it.
###########################################################

class FakeGameInfo:

    def __init__(self, platform = "Nintendo SNES", valid = True, playable = True,
                 save_dir = "/cache/saves/game"):
        self.platform = platform
        self.valid = valid
        self.playable = playable
        self.save_dir = save_dir

    def is_valid(self):
        return self.valid

    def is_playable(self):
        return self.playable

    def get_platform(self):
        return self.platform

    def get_name(self):
        return "Chrono Trigger (USA)"

    def get_save_dir(self):
        return self.save_dir

    def get_main_store_key(self):
        return "steam"

    def get_subvalue(self, store_key, identifier_key):
        return {"steam": {"appid": "1145360"}}[store_key][identifier_key]


class FakeStore:

    def __init__(self, handles_launching = True, result = True):
        self.handles_launching = handles_launching
        self.result = result
        self.launches = []

    def can_handle_launching(self):
        return self.handles_launching

    def get_install_identifier_key(self):
        return "appid"

    def launch(self, identifier, **kwargs):
        self.launches.append((identifier, kwargs))
        return self.result


class FakeLauncher:

    def __init__(self, config_file = "", save_dir = "", setup_dir = "/setup", result = True):
        self.config_file = config_file
        self.save_dir = save_dir
        self.setup_dir = setup_dir
        self.result = result
        self.launches = []

    def get_config_file(self):
        return self.config_file

    def get_save_dir(self, platform):
        return self.save_dir

    def get_setup_dir(self):
        return self.setup_dir

    def launch(self, game_info, **kwargs):
        self.launches.append(kwargs)
        return self.result


class Recorder:

    # Records every step of a launch in order; results can be overridden per step
    def __init__(self):
        self.calls = []
        self.results = {}

    def step(self, name):
        def record(*args, **kwargs):
            self.calls.append((name, kwargs))
            return self.results.get(name, True)
        return record

    def names(self):
        return [name for name, _ in self.calls]

    def kwargs(self, name):
        return [kwargs for called, kwargs in self.calls if called == name][0]


@pytest.fixture
def steps(monkeypatch):
    recorder = Recorder()
    for name in [
        "install_store_game", "install_local_game",
        "import_store_game_save", "export_store_game_save",
        "import_local_game_save", "export_local_game_save"]:
        monkeypatch.setattr(launching, name, recorder.step(name))
    monkeypatch.setattr(launching, "fileops", types.SimpleNamespace(**{
        name: recorder.step(name) for name in [
            "create_symlink", "replace_strings_in_file", "remove_object", "make_directory"]}))
    monkeypatch.setattr(launching, "gui", types.SimpleNamespace(
        display_error_popup = recorder.step("display_error_popup")))
    return recorder


@pytest.fixture
def store(monkeypatch):
    fake = FakeStore()
    monkeypatch.setattr(launching, "stores", types.SimpleNamespace(
        is_store_platform = lambda platform: platform == "Steam",
        get_store_by_platform = lambda platform: fake if platform == "Steam" else None))
    return fake


@pytest.fixture
def launcher(monkeypatch):
    fake = FakeLauncher()
    monkeypatch.setattr(launching, "programs", types.SimpleNamespace(
        get_emulator_by_platform = lambda platform: fake))
    return fake


###########################################################
# Store games
###########################################################

def test_a_store_game_is_installed_restored_launched_and_saved(steps, store):
    game = FakeGameInfo(platform = "Steam")

    assert launching.launch_store_game(game, locker_type = config.LockerType.HETZNER) is True
    assert steps.names() == ["install_store_game", "import_store_game_save", "export_store_game_save"]
    assert store.launches[0][0] == "1145360"


def test_a_store_save_is_exported_to_the_launch_locker(steps, store):
    launching.launch_store_game(FakeGameInfo(platform = "Steam"), locker_type = config.LockerType.HETZNER)

    assert steps.kwargs("install_store_game")["locker_type"] == config.LockerType.HETZNER
    assert steps.kwargs("export_store_game_save")["locker_type"] == config.LockerType.HETZNER


def test_a_store_launch_reports_the_export_result(steps, store):
    steps.results["export_store_game_save"] = False

    assert launching.launch_store_game(FakeGameInfo(platform = "Steam")) is False


@pytest.mark.parametrize("game", [
    None,
    FakeGameInfo(platform = "Steam", valid = False),
    FakeGameInfo(platform = "Steam", playable = False)])
def test_an_unlaunchable_store_game_does_nothing(steps, store, game):
    assert launching.launch_store_game(game) is False
    assert steps.calls == []


def test_a_failed_store_install_stops_the_launch(steps, store):
    steps.results["install_store_game"] = False

    assert launching.launch_store_game(FakeGameInfo(platform = "Steam")) is False
    assert store.launches == []


def test_a_store_game_without_a_store_is_not_launched(steps, store):
    assert launching.launch_store_game(FakeGameInfo(platform = "Unknown Store")) is False
    assert steps.names() == ["install_store_game"]


def test_a_store_that_cannot_launch_is_not_asked_to(steps, store):
    store.handles_launching = False

    assert launching.launch_store_game(FakeGameInfo(platform = "Steam")) is False
    assert store.launches == []


def test_a_failed_store_save_import_stops_the_launch(steps, store):
    steps.results["import_store_game_save"] = False

    assert launching.launch_store_game(FakeGameInfo(platform = "Steam")) is False
    assert store.launches == []


def test_a_failed_store_launch_exports_nothing(steps, store):
    store.result = False

    assert launching.launch_store_game(FakeGameInfo(platform = "Steam")) is False
    assert "export_store_game_save" not in steps.names()


###########################################################
# Local games
###########################################################

def test_a_local_game_is_installed_restored_launched_and_saved(steps, store, launcher):
    game = FakeGameInfo()

    assert launching.launch_local_game(
        game, locker_type = config.LockerType.GDRIVE,
        capture_type = config.CaptureType.VIDEO, fullscreen = True) is True
    assert steps.names() == ["install_local_game", "import_local_game_save", "export_local_game_save"]
    assert launcher.launches[0]["capture_type"] == config.CaptureType.VIDEO
    assert launcher.launches[0]["fullscreen"] is True


def test_a_local_save_is_exported_to_the_launch_locker(steps, store, launcher):
    launching.launch_local_game(FakeGameInfo(), locker_type = config.LockerType.GDRIVE)

    assert steps.kwargs("install_local_game")["locker_type"] == config.LockerType.GDRIVE
    assert steps.kwargs("export_local_game_save")["locker_type"] == config.LockerType.GDRIVE


def test_a_launch_without_a_locker_exports_without_one(steps, store, launcher):
    launching.launch_local_game(FakeGameInfo())

    assert steps.kwargs("export_local_game_save")["locker_type"] is None


def test_flags_reach_every_step(steps, store, launcher):
    launching.launch_local_game(FakeGameInfo(), verbose = True, pretend_run = True, exit_on_failure = True)

    for name in ["install_local_game", "import_local_game_save", "export_local_game_save"]:
        kwargs = steps.kwargs(name)
        assert (kwargs["verbose"], kwargs["pretend_run"], kwargs["exit_on_failure"]) == (True, True, True)
    assert launcher.launches[0]["pretend_run"] is True


def test_the_launcher_save_dir_points_at_the_game_save_while_running(steps, store, launcher, tmp_path):
    launcher.save_dir = str(tmp_path / "emulator" / "saves")
    game = FakeGameInfo(save_dir = str(tmp_path / "game"))

    assert launching.launch_local_game(game) is True
    assert steps.kwargs("create_symlink") == {
        "src": game.get_save_dir(), "dest": launcher.save_dir,
        "verbose": False, "pretend_run": False, "exit_on_failure": False}
    assert steps.kwargs("remove_object")["obj"] == launcher.save_dir
    assert steps.kwargs("make_directory")["src"] == launcher.save_dir
    assert steps.names().index("export_local_game_save") > steps.names().index("make_directory")


def test_the_launcher_config_is_filled_in_and_reverted(steps, store, launcher, tmp_path):
    config_file = tmp_path / "emulator.cfg"
    config_file.write_text("setting")
    launcher.config_file = str(config_file)
    game = FakeGameInfo(save_dir = "/cache/saves/game")

    launching.launch_local_game(game)

    filled, reverted = [kwargs["replacements"] for name, kwargs in steps.calls
                        if name == "replace_strings_in_file"]
    assert filled == [
        {"from": config.token_emulator_setup_root, "to": "/setup"},
        {"from": config.token_game_save_dir, "to": "/cache/saves/game"}]
    assert reverted == [
        {"from": "/setup", "to": config.token_emulator_setup_root},
        {"from": "/cache/saves/game", "to": config.token_game_save_dir}]


def test_a_launcher_without_a_config_or_save_dir_is_left_alone(steps, store, launcher):
    launching.launch_local_game(FakeGameInfo())

    assert not {"create_symlink", "replace_strings_in_file", "remove_object"} & set(steps.names())


@pytest.mark.parametrize("game", [
    None,
    FakeGameInfo(valid = False),
    FakeGameInfo(playable = False)])
def test_an_unlaunchable_local_game_does_nothing(steps, store, launcher, game):
    assert launching.launch_local_game(game) is False
    assert steps.calls == []


def test_a_failed_local_install_stops_the_launch(steps, store, launcher):
    steps.results["install_local_game"] = False

    assert launching.launch_local_game(FakeGameInfo()) is False
    assert launcher.launches == []


def test_a_platform_without_a_launcher_is_reported(steps, store, monkeypatch):
    monkeypatch.setattr(launching, "programs", types.SimpleNamespace(
        get_emulator_by_platform = lambda platform: None))

    assert launching.launch_local_game(FakeGameInfo()) is False
    assert steps.names() == ["install_local_game", "display_error_popup"]


def test_a_failed_local_save_import_stops_the_launch(steps, store, launcher):
    steps.results["import_local_game_save"] = False

    assert launching.launch_local_game(FakeGameInfo()) is False
    assert launcher.launches == []


def test_a_failed_save_dir_link_stops_the_launch(steps, store, launcher, tmp_path):
    launcher.save_dir = str(tmp_path / "saves")
    steps.results["create_symlink"] = False

    assert launching.launch_local_game(FakeGameInfo()) is False
    assert launcher.launches == []


def test_a_failed_local_launch_exports_nothing(steps, store, launcher):
    launcher.result = False

    assert launching.launch_local_game(FakeGameInfo()) is False
    assert "export_local_game_save" not in steps.names()


@pytest.mark.parametrize("failing", ["remove_object", "make_directory"])
def test_a_failed_save_dir_revert_exports_nothing(steps, store, launcher, tmp_path, failing):
    launcher.save_dir = str(tmp_path / "saves")
    steps.results[failing] = False

    assert launching.launch_local_game(FakeGameInfo()) is False
    assert "export_local_game_save" not in steps.names()


def test_a_local_launch_reports_the_export_result(steps, store, launcher):
    steps.results["export_local_game_save"] = False

    assert launching.launch_local_game(FakeGameInfo()) is False


###########################################################
# Choosing the launch path
###########################################################

def test_a_store_platform_launches_through_the_store(steps, store, launcher):
    assert launching.launch_game(FakeGameInfo(platform = "Steam"), locker_type = config.LockerType.LOCAL) is True
    assert "install_store_game" in steps.names()
    assert steps.kwargs("export_store_game_save")["locker_type"] == config.LockerType.LOCAL
    assert launcher.launches == []


def test_other_platforms_launch_through_their_emulator(steps, store, launcher):
    assert launching.launch_game(
        FakeGameInfo(), locker_type = config.LockerType.LOCAL,
        capture_type = config.CaptureType.SCREENSHOT, fullscreen = True) is True
    assert steps.kwargs("export_local_game_save")["locker_type"] == config.LockerType.LOCAL
    assert launcher.launches[0]["capture_type"] == config.CaptureType.SCREENSHOT
    assert store.launches == []
