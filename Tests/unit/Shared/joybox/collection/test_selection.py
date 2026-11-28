# Local imports
from joybox import config
from joybox.collection import selection


def test_every_rom_subcategory_is_selected_without_filters():
    selected = list(selection.iterate_selected_subcategories())

    assert len(selected) == sum(len(config.subcategory_map[category]) for category in config.Category.members())
    assert {supercategory for supercategory, _, _ in selected} == {config.Supercategory.ROMS}


def test_a_category_filter_keeps_only_its_subcategories():
    selected = list(selection.iterate_selected_subcategories(categories = [config.Category.COMPUTER]))

    assert [subcategory for _, _, subcategory in selected] == list(config.subcategory_map[config.Category.COMPUTER])


def test_a_subcategory_filter_keeps_only_that_subcategory():
    subcategory = config.subcategory_map[config.Category.COMPUTER][0]

    selected = list(selection.iterate_selected_subcategories(subcategories = [subcategory]))

    assert selected == [(config.Supercategory.ROMS, config.Category.COMPUTER, subcategory)]


def test_json_games_are_listed_per_selected_subcategory(monkeypatch):
    subcategory = config.subcategory_map[config.Category.COMPUTER][0]
    calls = []
    monkeypatch.setattr(selection.gamecollection, "find_json_game_names",
        lambda supercategory, category, sub, locker_type: calls.append(locker_type) or ["A", "B"])

    games = list(selection.iterate_selected_json_games(subcategories = [subcategory], locker_type = config.LockerType.LOCAL))

    assert [name for _, _, _, name in games] == ["A", "B"]
    assert games[0][:3] == (config.Supercategory.ROMS, config.Category.COMPUTER, subcategory)
    assert calls == [config.LockerType.LOCAL]


def test_locker_games_are_listed_per_selected_subcategory(monkeypatch):
    subcategory = config.subcategory_map[config.Category.COMPUTER][0]
    monkeypatch.setattr(selection.gamecollection, "find_locker_game_names",
        lambda supercategory, category, sub, locker_type: ["Locker Game"])

    games = list(selection.iterate_selected_locker_games(subcategories = [subcategory]))

    assert games == [(config.Supercategory.ROMS, config.Category.COMPUTER, subcategory, "Locker Game")]
