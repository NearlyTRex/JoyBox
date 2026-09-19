# Imports
import pytest

# Local imports
from joybox import config, metadataentry


###########################################################
# MetadataEntry
#
# Holds one game's scraped metadata on its way into the collection json, so
# every accessor pair has to round-trip and merging must not lose a field.
###########################################################

ACCESSORS = [
    "background", "boxback", "boxfront", "category", "coop", "description",
    "developer", "file", "game", "genre", "label", "platform", "playable",
    "players", "publisher", "release", "screenshot", "subcategory",
    "supercategory", "url", "video",
]


def build(**values):
    entry = metadataentry.MetadataEntry()
    for key, value in values.items():
        entry.set_value(key, value)
    return entry


###########################################################
# Accessors
###########################################################

# set_description cleans and wraps web text into lines, so it does not round
# trip a bare string.
PLAIN_ACCESSORS = [field for field in ACCESSORS if field != "description"]


@pytest.mark.parametrize("field", PLAIN_ACCESSORS)
def test_every_field_round_trips(field):
    entry = metadataentry.MetadataEntry()
    getattr(entry, f"set_{field}")("value")

    assert getattr(entry, f"get_{field}")() == "value"


def test_a_description_is_stored_as_wrapped_lines():
    entry = metadataentry.MetadataEntry()
    entry.set_description("A short description.")

    stored = entry.get_description()
    assert isinstance(stored, list)
    assert "A short description." in " ".join(stored)


def test_a_description_given_as_lines_is_kept():
    entry = metadataentry.MetadataEntry()
    entry.set_description(["first", "second"])

    assert entry.get_description() == ["first", "second"]


@pytest.mark.parametrize("field", ACCESSORS)
def test_an_unset_field_returns_the_default(field):
    entry = metadataentry.MetadataEntry()

    assert getattr(entry, f"get_{field}")() is None
    assert getattr(entry, f"get_{field}")("fallback") == "fallback"


@pytest.mark.parametrize("field", ACCESSORS)
def test_every_field_uses_a_distinct_key(field):
    # Two accessors sharing a key would overwrite each other silently.
    entry = metadataentry.MetadataEntry()
    getattr(entry, f"set_{field}")("value")

    assert len(entry.game_entry) == 1


def test_fields_do_not_collide():
    entry = metadataentry.MetadataEntry()
    for field in ACCESSORS:
        getattr(entry, f"set_{field}")(f"value-{field}")

    assert len(entry.game_entry) == len(ACCESSORS)
    for field in PLAIN_ACCESSORS:
        assert getattr(entry, f"get_{field}")() == f"value-{field}"


###########################################################
# Raw access
###########################################################

def test_a_value_round_trips_by_key():
    entry = build(custom = "value")
    assert entry.get_value("custom") == "value"


def test_key_presence_is_reported():
    entry = build(present = "value")

    assert entry.is_key_set("present") is True
    assert entry.is_key_set("absent") is False


def test_a_value_is_deleted():
    entry = build(temporary = "value")
    entry.delete_value("temporary")

    assert entry.is_key_set("temporary") is False


def test_deleting_a_missing_key_raises():
    # Callers guard with is_key_set first; this is plain dict semantics.
    entry = metadataentry.MetadataEntry()

    with pytest.raises(KeyError):
        entry.delete_value("absent")


###########################################################
# Minimum keys
###########################################################

def test_a_new_entry_lacks_the_minimum_keys():
    assert metadataentry.MetadataEntry().has_minimum_keys() is False


def test_the_minimum_keys_are_satisfied_together():
    entry = metadataentry.MetadataEntry()
    for key in config.metadata_keys_minimum:
        entry.set_value(key, "value")

    assert entry.has_minimum_keys() is True


@pytest.mark.parametrize("omitted", config.metadata_keys_minimum)
def test_every_minimum_key_is_required(omitted):
    entry = metadataentry.MetadataEntry()
    for key in config.metadata_keys_minimum:
        if key != omitted:
            entry.set_value(key, "value")

    assert entry.has_minimum_keys() is False


def test_extra_keys_do_not_satisfy_the_minimum():
    entry = build(genre = "RPG", developer = "Acme")

    assert entry.has_minimum_keys() is False


###########################################################
# Merging
###########################################################

def test_merging_fills_gaps_from_the_other_entry():
    mine = build(game = "Mine")
    theirs = build(developer = "Acme")
    mine.merge(theirs)

    assert mine.get_value("game") == "Mine"
    assert mine.get_value("developer") == "Acme"


def test_merging_keeps_this_entry_on_a_conflict():
    # Scraped data fills gaps; it does not overwrite what is already known.
    mine = build(game = "Mine")
    theirs = build(game = "Theirs")
    mine.merge(theirs)

    assert mine.get_value("game") == "Mine"


def test_merging_does_not_change_the_other_entry():
    mine = build(game = "Mine")
    theirs = build(game = "Theirs", developer = "Acme")
    mine.merge(theirs)

    assert theirs.get_value("game") == "Theirs"


def test_merged_entries_do_not_share_state():
    # mergedeep returns its first argument, so without a copy both entries end
    # up holding the same dict.
    mine = build(game = "Mine")
    theirs = build(developer = "Acme")
    mine.merge(theirs)

    mine.set_value("later", "value")

    assert theirs.is_key_set("later") is False
    assert mine.game_entry is not theirs.game_entry


def test_merging_an_empty_entry_changes_nothing():
    mine = build(game = "Mine", genre = "RPG")
    mine.merge(metadataentry.MetadataEntry())

    assert mine.get_value("game") == "Mine"
    assert mine.get_value("genre") == "RPG"


def test_merging_into_an_empty_entry_takes_everything():
    mine = metadataentry.MetadataEntry()
    mine.merge(build(game = "Theirs", developer = "Acme"))

    assert mine.get_value("game") == "Theirs"
    assert mine.get_value("developer") == "Acme"
