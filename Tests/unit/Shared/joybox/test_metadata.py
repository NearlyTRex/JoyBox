# Imports
import pytest

# Local imports
from joybox import config, metadata, metadataentry


###########################################################
# Metadata database
#
# The in-memory index of every scraped game, keyed by platform and name.
# set_game merges into an existing entry rather than replacing it, so a
# collector that revisits a game must not lose what was already known.
###########################################################

PLATFORM = config.Platform.NINTENDO_64
OTHER_PLATFORM = config.Platform.NINTENDO_GAMECUBE


def entry(game = "Chrono Trigger", platform = PLATFORM, **extra):
    built = metadataentry.MetadataEntry()
    built.set_game(game)
    built.set_platform(platform)
    built.set_file("game.z64")
    for key, value in extra.items():
        built.set_value(key, value)
    return built


def build(*entries):
    database = metadata.Metadata()
    for item in entries:
        database.add_game(item)
    return database


###########################################################
# Adding
###########################################################

def test_a_complete_entry_is_added():
    database = build(entry())

    assert database.has_game(PLATFORM, "Chrono Trigger") is True


def test_an_incomplete_entry_is_ignored():
    # Without the minimum keys there is nothing to index it under.
    incomplete = metadataentry.MetadataEntry()
    incomplete.set_game("Nameless")

    database = build(incomplete)

    assert database.get_sorted_platforms() == []


def test_adding_injects_the_categories():
    database = build(entry())
    stored = database.get_game(PLATFORM, "Chrono Trigger")

    assert stored.get_supercategory() == config.Supercategory.ROMS
    assert stored.get_category() is not None
    assert stored.get_subcategory() is not None


def test_a_missing_game_is_not_reported_present():
    database = build(entry())

    assert database.has_game(PLATFORM, "Absent") is False
    assert database.has_game(OTHER_PLATFORM, "Chrono Trigger") is False
    assert database.get_game(PLATFORM, "Absent") is None


###########################################################
# Merging on re-add
###########################################################

def test_re_adding_a_game_fills_gaps():
    database = build(entry(genre = "RPG"))
    database.add_game(entry(developer = "Square"))

    stored = database.get_game(PLATFORM, "Chrono Trigger")
    assert stored.get_value("genre") == "RPG"
    assert stored.get_value("developer") == "Square"


def test_re_adding_does_not_overwrite_what_is_known():
    database = build(entry(genre = "RPG"))
    database.add_game(entry(genre = "Adventure"))

    assert database.get_game(PLATFORM, "Chrono Trigger").get_value("genre") == "RPG"


def test_re_adding_does_not_alias_the_incoming_entry():
    # merge returns its first argument, so without a copy the stored entry and
    # the caller's would become one object.
    database = build(entry(genre = "RPG"))
    incoming = entry(developer = "Square")
    database.add_game(incoming)

    stored = database.get_game(PLATFORM, "Chrono Trigger")
    stored.set_value("later", "value")

    assert incoming.is_key_set("later") is False


def test_a_reused_entry_does_not_leak_between_games():
    # A collector looping over games with one entry object would otherwise
    # alias every stored game together.
    database = metadata.Metadata()
    database.add_game(entry("First"))
    database.add_game(entry("Second"))
    database.add_game(entry("First", genre = "RPG"))

    assert database.get_game(PLATFORM, "Second").is_key_set("genre") is False


###########################################################
# Ordering
###########################################################

def test_platforms_are_sorted():
    database = build(entry("A", OTHER_PLATFORM), entry("B", PLATFORM))

    assert database.get_sorted_platforms() == sorted(database.get_sorted_platforms())


def test_names_are_sorted_within_a_platform():
    database = build(entry("Zelda"), entry("Actraiser"), entry("Mario"))

    assert database.get_sorted_names(PLATFORM) == ["Actraiser", "Mario", "Zelda"]


def test_names_for_an_unknown_platform_are_empty():
    assert build(entry()).get_sorted_names(OTHER_PLATFORM) == []


def test_all_names_span_every_platform():
    database = build(entry("A", PLATFORM), entry("B", OTHER_PLATFORM))

    assert sorted(database.get_all_sorted_names()) == ["A", "B"]


def test_entries_follow_the_name_order():
    database = build(entry("Zelda"), entry("Actraiser"))
    entries = database.get_sorted_entries(PLATFORM)

    assert [item.get_game() for item in entries] == ["Actraiser", "Zelda"]


def test_all_entries_span_every_platform():
    database = build(entry("A", PLATFORM), entry("B", OTHER_PLATFORM))

    assert len(database.get_all_sorted_entries()) == 2


###########################################################
# Missing data
###########################################################

def test_an_entry_with_every_key_is_not_missing_data():
    database = build(entry(genre = "RPG"))

    assert database.is_entry_missing_data(PLATFORM, "Chrono Trigger", ["genre"]) is False


def test_an_absent_key_counts_as_missing():
    database = build(entry())

    assert database.is_entry_missing_data(PLATFORM, "Chrono Trigger", ["genre"]) is True


def test_an_empty_value_counts_as_missing():
    # An empty string is a placeholder, not data.
    database = build(entry(genre = ""))

    assert database.is_entry_missing_data(PLATFORM, "Chrono Trigger", ["genre"]) is True


def test_the_database_reports_missing_data_anywhere():
    database = build(entry("A", genre = "RPG"), entry("B"))

    assert database.is_missing_data(["genre"]) is True


def test_a_complete_database_reports_nothing_missing():
    database = build(entry("A", genre = "RPG"), entry("B", genre = "Action"))

    assert database.is_missing_data(["genre"]) is False


def test_an_empty_database_reports_nothing_missing():
    assert metadata.Metadata().is_missing_data(["genre"]) is False


###########################################################
# Merging databases
###########################################################

def test_merging_takes_games_from_the_other_database():
    first = build(entry("A"))
    second = build(entry("B"))
    first.merge_contents(second)

    assert sorted(first.get_all_sorted_names()) == ["A", "B"]


def test_merging_does_not_change_the_other_database():
    first = build(entry("A"))
    second = build(entry("B"))
    first.merge_contents(second)

    assert second.get_all_sorted_names() == ["B"]


def test_merging_an_empty_database_changes_nothing():
    first = build(entry("A"))
    first.merge_contents(metadata.Metadata())

    assert first.get_all_sorted_names() == ["A"]


###########################################################
# Random selection
###########################################################

def test_a_random_entry_comes_from_the_database():
    database = build(entry("A"), entry("B"))
    picked = database.get_random_entry()

    assert picked.get_game() in ["A", "B"]


def test_a_random_entry_from_an_empty_database_raises():
    # Callers check the database is populated first.
    with pytest.raises(IndexError):
        metadata.Metadata().get_random_entry()
