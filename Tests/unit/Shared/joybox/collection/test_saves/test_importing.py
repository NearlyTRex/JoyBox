# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.collection import saves
from saves_helpers import make_catalog


###########################################################
# Importing a local save
#
# Launching stops when the import reports failure, so a save that unpacks
# cleanly has to say so.
###########################################################

@pytest.mark.parametrize("unpacked", [True, False])
def test_importing_a_save_reports_the_unpack_result(monkeypatch, unpacked):
    monkeypatch.setattr(saves, "can_save_be_unpacked", lambda game_info: True)
    monkeypatch.setattr(saves, "unpack_save", lambda **kwargs: unpacked)

    assert saves.import_local_game_save(game_info = object()) is unpacked


def test_a_game_without_a_packed_save_imports_nothing(monkeypatch):
    monkeypatch.setattr(saves, "can_save_be_unpacked", lambda game_info: False)
    monkeypatch.setattr(saves, "unpack_save", lambda **kwargs: pytest.fail("nothing to unpack"))

    assert saves.import_local_game_save(game_info = object()) is True


def test_a_local_game_has_no_save_paths_to_import():
    # Only store games record save paths; the rest succeed with nothing to do.
    assert saves.import_local_game_save_paths(game_info = object()) is True


###########################################################
# Exporting a local save
###########################################################

@pytest.mark.parametrize("packed", [True, False])
def test_exporting_a_save_reports_the_pack_result(monkeypatch, packed):
    calls = []
    monkeypatch.setattr(saves, "can_save_be_packed", lambda game_info: True)

    def pack_save(**kwargs):
        calls.append(kwargs)
        return packed
    monkeypatch.setattr(saves, "pack_save", pack_save)

    assert saves.export_local_game_save(
        game_info = "game", locker_type = config.LockerType.LOCAL, verbose = True) is packed
    assert calls[0]["locker_type"] == config.LockerType.LOCAL
    assert calls[0]["verbose"] is True


def test_a_game_that_saved_nothing_exports_nothing(monkeypatch):
    # A session that wrote no save is not a failed launch.
    monkeypatch.setattr(saves, "can_save_be_packed", lambda game_info: False)
    monkeypatch.setattr(saves, "pack_save", lambda **kwargs: pytest.fail("nothing to pack"))

    assert saves.export_local_game_save(game_info = object()) is True


###########################################################
# Store or local
###########################################################

class PlatformOnly:

    def __init__(self, platform):
        self.platform = platform

    def get_platform(self):
        return self.platform


@pytest.fixture
def routed(monkeypatch):
    calls = []
    monkeypatch.setattr(saves.stores, "is_store_platform", lambda platform: platform == "Steam")
    for name in [
        "import_store_game_save_paths", "import_local_game_save_paths",
        "import_store_game_save", "import_local_game_save",
        "export_store_game_save", "export_local_game_save"]:
        def handler(name = name, **kwargs):
            calls.append((name, kwargs))
            return name
        monkeypatch.setattr(saves, name, handler)
    return calls


@pytest.mark.parametrize("function, platform, expected", [
    ("import_game_save_paths", "Steam", "import_store_game_save_paths"),
    ("import_game_save_paths", "Nintendo SNES", "import_local_game_save_paths"),
    ("import_game_save", "Steam", "import_store_game_save"),
    ("import_game_save", "Nintendo SNES", "import_local_game_save"),
    ("export_game_save", "Steam", "export_store_game_save"),
    ("export_game_save", "Nintendo SNES", "export_local_game_save"),
])
def test_store_games_take_the_store_route(routed, function, platform, expected):
    game_info = PlatformOnly(platform)

    assert getattr(saves, function)(game_info = game_info, pretend_run = True) == expected
    assert routed[0][1]["game_info"] is game_info
    assert routed[0][1]["pretend_run"] is True


def test_an_export_carries_the_locker(routed):
    saves.export_game_save(game_info = PlatformOnly("Steam"), locker_type = config.LockerType.HETZNER)

    assert routed[0][1]["locker_type"] == config.LockerType.HETZNER


###########################################################
# Every game
###########################################################

@pytest.mark.parametrize("function, per_game, extra", [
    ("import_all_game_save_paths", "import_game_save_paths", {}),
    ("import_all_game_saves", "import_game_save", {}),
    ("export_all_game_save", "export_game_save", {"locker_type": config.LockerType.LOCAL}),
])
def test_every_game_is_visited_until_one_fails(monkeypatch, function, per_game, extra):
    games = {"First": "first", "Second": "second", "Third": "third"}
    make_catalog(monkeypatch, games)
    visited = []

    def handler(game_info, **kwargs):
        visited.append((game_info, kwargs))
        return game_info != "second"
    monkeypatch.setattr(saves, per_game, handler)

    assert getattr(saves, function)(verbose = True, **extra) is False
    assert [game_info for game_info, _ in visited] == ["first", "second"]
    assert visited[0][1]["verbose"] is True
    for key, value in extra.items():
        assert visited[0][1][key] == value


@pytest.mark.parametrize("function, per_game", [
    ("import_all_game_save_paths", "import_game_save_paths"),
    ("import_all_game_saves", "import_game_save"),
    ("export_all_game_save", "export_game_save"),
])
def test_every_game_succeeding_succeeds(monkeypatch, function, per_game):
    built = make_catalog(monkeypatch, {"First": "first", "Second": "second"})
    visited = []
    monkeypatch.setattr(saves, per_game, lambda game_info, **kwargs: visited.append(game_info) or True)

    assert getattr(saves, function)(pretend_run = True) is True
    assert visited == ["first", "second"]
    assert built[0][1]["pretend_run"] is True
